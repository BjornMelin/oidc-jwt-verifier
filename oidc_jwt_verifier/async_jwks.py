"""Async JWKS client with caching and error mapping.

This module provides ``AsyncJWKSClient``, an asynchronous counterpart to the
sync ``JWKSClient`` wrapper. It fetches JWKS documents with ``httpx``,
implements TTL and key caches, and maps failures to ``AuthError``.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass, field

import httpx
import jwt
from jwt import PyJWK, PyJWKSet

from oidc_jwt_verifier.config import AuthConfig
from oidc_jwt_verifier.errors import AuthError


@dataclass(slots=True)
class AsyncJWKSClient:
    """Asynchronous JWKS client with TTL and key caching.

    The client supports:

    - Async JWKS fetches via ``httpx.AsyncClient``.
    - JWKS document caching with ``jwks_cache_ttl_s``.
    - Key-object caching with ``jwks_max_cached_keys``.
    - Error mapping to stable ``AuthError`` codes.

    Args:
        _config: Auth configuration.
        _client: Async HTTP client used for JWKS fetches.
        _owns_client: Whether this instance must close ``_client`` on
            ``aclose``.
        _max_fetch_attempts: Number of total fetch attempts for transient
            request failures. Minimum value is ``1``.
        _jwk_set_cache: Cached parsed JWKS set.
        _jwk_set_expiry_monotonic: Monotonic timestamp when JWKS cache expires.
        _key_cache: LRU-like cache of ``kid`` to ``PyJWK``.
        _lock: Async lock protecting cache state.

    Examples:
        >>> from oidc_jwt_verifier import AuthConfig
        >>> from oidc_jwt_verifier.async_jwks import AsyncJWKSClient
        >>> config = AuthConfig(
        ...     issuer="https://issuer.example/",
        ...     audience="https://api.example",
        ...     jwks_url="https://issuer.example/.well-known/jwks.json",
        ... )
        >>> client = AsyncJWKSClient.from_config(config)
        >>> # await client.get_signing_key_from_jwt(token)
        >>> # await client.aclose()
    """

    _config: AuthConfig
    _client: httpx.AsyncClient
    _owns_client: bool
    _max_fetch_attempts: int = 2
    _jwk_set_cache: PyJWKSet | None = None
    _jwk_set_expiry_monotonic: float = 0.0
    _key_cache: OrderedDict[str, PyJWK] = field(default_factory=OrderedDict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @classmethod
    def from_config(
        cls,
        config: AuthConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
        max_fetch_attempts: int = 2,
    ) -> AsyncJWKSClient:
        """Create an async JWKS client from configuration.

        Args:
            config: Auth configuration with JWKS URL/cache/timeout settings.
            http_client: Optional externally managed client. If omitted,
                an internal client is created and owned by this instance.
            max_fetch_attempts: Total fetch attempts for request failures.
                Must be ``>= 1``.

        Returns:
            Configured ``AsyncJWKSClient``.

        Raises:
            ValueError: If ``max_fetch_attempts < 1``.

        Examples:
            >>> from oidc_jwt_verifier import AuthConfig
            >>> config = AuthConfig(
            ...     issuer="https://issuer.example/",
            ...     audience="https://api.example",
            ...     jwks_url="https://issuer.example/.well-known/jwks.json",
            ... )
            >>> client = AsyncJWKSClient.from_config(config)
        """
        if max_fetch_attempts < 1:
            raise ValueError("max_fetch_attempts must be >= 1")

        owns_client = http_client is None
        client = http_client or httpx.AsyncClient(timeout=config.jwks_timeout_s)
        return cls(
            _config=config,
            _client=client,
            _owns_client=owns_client,
            _max_fetch_attempts=max_fetch_attempts,
        )

    async def aclose(self) -> None:
        """Close internal resources.

        Closes the underlying HTTP client only when this instance owns it.

        Examples:
            >>> # await client.aclose()
        """
        if self._owns_client:
            await self._client.aclose()

    async def get_signing_key_from_jwt(self, token: str | bytes) -> PyJWK:
        """Resolve signing key for a JWT from configured JWKS.

        Args:
            token: Encoded JWT as ``str`` or ASCII-compatible ``bytes``.

        Returns:
            Matching signing key.

        Raises:
            AuthError: On key lookup/fetch/parsing failures.

        Examples:
            >>> # signing_key = await client.get_signing_key_from_jwt(token)
        """
        if isinstance(token, bytes):
            try:
                token_str = token.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise AuthError(
                    code="jwks_error",
                    message="JWKS lookup failed",
                    status_code=401,
                ) from exc
        else:
            token_str = token

        kid = self._extract_kid(token_str)
        return await self.get_signing_key(kid)

    async def get_signing_key(self, kid: str) -> PyJWK:
        """Resolve a signing key by ``kid``.

        Performs lookup against cache first, then fetches/retries JWKS when
        needed, including one forced refresh attempt when ``kid`` is missing.

        Args:
            kid: JWT key identifier.

        Returns:
            Matching ``PyJWK``.

        Raises:
            AuthError: With ``key_not_found`` when no matching key exists.

        Examples:
            >>> # signing_key = await client.get_signing_key("kid-123")
        """
        cached = await self._try_get_key_from_caches(kid)
        if cached is not None:
            return cached

        key = await self._find_key_via_jwks(kid, refresh=False)
        if key is not None:
            return key

        key = await self._find_key_via_jwks(kid, refresh=True)
        if key is not None:
            return key

        raise AuthError(
            code="key_not_found",
            message="No matching signing key",
            status_code=401,
        )

    async def _try_get_key_from_caches(self, kid: str) -> PyJWK | None:
        """Try key and JWKS caches before network fetch.

        Args:
            kid: Key id to resolve.

        Returns:
            Cached key if available; otherwise ``None``.
        """
        async with self._lock:
            jwk_set = self._get_cached_jwk_set_unlocked()
            if jwk_set is None:
                return None

            direct = self._key_cache.get(kid)
            if direct is not None:
                self._key_cache.move_to_end(kid)
                return direct

            key = self._match_kid(self._extract_signing_keys(jwk_set), kid)
            if key is None:
                return None

            self._put_key_cache_unlocked(kid, key)
            return key

    async def _find_key_via_jwks(
        self, kid: str, *, refresh: bool
    ) -> PyJWK | None:
        """Resolve key by fetching JWKS if necessary.

        Args:
            kid: Key id to resolve.
            refresh: Whether to force JWKS refresh.

        Returns:
            Matching key if found; otherwise ``None``.
        """
        keys = await self._get_signing_keys(refresh=refresh)
        key = self._match_kid(keys, kid)
        if key is None:
            return None

        async with self._lock:
            self._put_key_cache_unlocked(kid, key)
        return key

    async def _get_signing_keys(self, *, refresh: bool) -> list[PyJWK]:
        """Get signing keys from cache or network.

        Args:
            refresh: Force JWKS refetch.

        Returns:
            Parsed signing keys from JWKS.

        Raises:
            AuthError: On network/parsing errors or missing signing keys.
        """
        if not refresh:
            async with self._lock:
                jwk_set = self._get_cached_jwk_set_unlocked()
                if jwk_set is not None:
                    return self._extract_signing_keys(jwk_set)

        jwk_set = await self._fetch_and_parse_jwk_set()
        signing_keys = self._extract_signing_keys(jwk_set)

        async with self._lock:
            self._jwk_set_cache = jwk_set
            ttl_s = self._config.jwks_cache_ttl_s
            self._jwk_set_expiry_monotonic = time.monotonic() + ttl_s
            self._key_cache.clear()

        return signing_keys

    async def _fetch_and_parse_jwk_set(self) -> PyJWKSet:
        """Fetch JWKS document and parse it into ``PyJWKSet``.

        Returns:
            Parsed JWKS set.

        Raises:
            AuthError: For fetch failures or malformed JWKS payloads.
        """
        last_request_exc: Exception | None = None
        for _ in range(self._max_fetch_attempts):
            try:
                response = await self._client.get(
                    self._config.jwks_url,
                    timeout=self._config.jwks_timeout_s,
                )
                response.raise_for_status()
                data = response.json()
            except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                last_request_exc = exc
                continue
            except ValueError as exc:
                raise AuthError(
                    code="jwks_error",
                    message="JWKS lookup failed",
                    status_code=401,
                ) from exc
            else:
                if not isinstance(data, dict):
                    raise AuthError(
                        code="jwks_error",
                        message="JWKS lookup failed",
                        status_code=401,
                    )
                try:
                    return PyJWKSet.from_dict(data)
                except jwt.PyJWTError as exc:
                    raise AuthError(
                        code="jwks_error",
                        message="JWKS lookup failed",
                        status_code=401,
                    ) from exc

        raise AuthError(
            code="jwks_fetch_failed",
            message="JWKS fetch failed",
            status_code=401,
        ) from last_request_exc

    def _get_cached_jwk_set_unlocked(self) -> PyJWKSet | None:
        """Get non-expired cached JWKS set.

        Returns:
            Cached JWKS set when valid, otherwise ``None``.
        """
        if self._jwk_set_cache is None:
            return None
        if time.monotonic() >= self._jwk_set_expiry_monotonic:
            self._jwk_set_cache = None
            self._key_cache.clear()
            return None
        return self._jwk_set_cache

    def _put_key_cache_unlocked(self, kid: str, key: PyJWK) -> None:
        """Insert/update key cache entry with configured max size.

        Args:
            kid: Key id.
            key: Key object.
        """
        self._key_cache[kid] = key
        self._key_cache.move_to_end(kid)
        while len(self._key_cache) > self._config.jwks_max_cached_keys:
            self._key_cache.popitem(last=False)

    @staticmethod
    def _extract_kid(token: str) -> str:
        """Extract ``kid`` from unverified token header.

        Args:
            token: Encoded JWT.

        Returns:
            Header key id.

        Raises:
            AuthError: If token/header is malformed or ``kid`` is missing.
        """
        try:
            header = jwt.get_unverified_header(token)
        except jwt.DecodeError as exc:
            raise AuthError(
                code="jwks_error",
                message="JWKS lookup failed",
                status_code=401,
            ) from exc

        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise AuthError(
                code="key_not_found",
                message="No matching signing key",
                status_code=401,
            )
        return kid

    @staticmethod
    def _extract_signing_keys(jwk_set: PyJWKSet) -> list[PyJWK]:
        """Filter valid signing keys from a JWK set.

        Args:
            jwk_set: Parsed JWKS set.

        Returns:
            List of signing-capable keys with non-empty ``kid``.

        Raises:
            AuthError: If no valid signing keys exist.
        """
        signing_keys = [
            jwk_key
            for jwk_key in jwk_set.keys
            if jwk_key.public_key_use in ["sig", None] and jwk_key.key_id
        ]
        if not signing_keys:
            raise AuthError(
                code="jwks_error",
                message="JWKS lookup failed",
                status_code=401,
            )
        return signing_keys

    @staticmethod
    def _match_kid(signing_keys: list[PyJWK], kid: str) -> PyJWK | None:
        """Find matching key by ``kid``.

        Args:
            signing_keys: Candidate keys.
            kid: Key id to match.

        Returns:
            Matching key or ``None``.
        """
        for key in signing_keys:
            if key.key_id == kid:
                return key
        return None
