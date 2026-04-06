"""JWKS client wrapper with caching and error mapping.

This module provides ``JWKSClient``, a thin wrapper around PyJWT's
``PyJWKClient`` that adds configurable caching and maps JWKS-related
errors to ``AuthError`` exceptions with appropriate error codes and
HTTP status codes.

The client never fetches JWKS from URLs specified in token headers;
all fetches use the URL configured in ``AuthConfig``.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import NoReturn, cast

from jwt import PyJWK, PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

from .config import AuthConfig
from .errors import AuthError


@dataclass(slots=True)
class JWKSClient:
    """JWKS client with caching and error mapping.

    This class wraps PyJWT's ``PyJWKClient`` to provide:

    - Configurable cache TTL and maximum cached keys from ``AuthConfig``.
    - Consistent error mapping: all JWKS-related failures are converted
      to ``AuthError`` exceptions with status code 401.

    The client is typically instantiated via the ``from_config`` class
    method, which configures caching parameters from an ``AuthConfig``
    instance.

    Attributes:
        _client: The underlying PyJWT ``PyJWKClient`` instance.

    Examples:
        Creating a client from configuration:

        >>> from oidc_jwt_verifier import AuthConfig
        >>> config = AuthConfig(
        ...     issuer="https://example.auth0.com/",
        ...     audience="https://api.example.com",
        ...     jwks_url="https://example.auth0.com/.well-known/jwks.json",
        ...     jwks_cache_ttl_s=600,
        ...     jwks_max_cached_keys=32,
        ... )
        >>> client = JWKSClient.from_config(config)  # doctest: +SKIP
    """

    _client: PyJWKClient

    @classmethod
    def from_config(cls, config: AuthConfig) -> "JWKSClient":
        """Create a JWKS client from an AuthConfig instance.

        Configures the underlying ``PyJWKClient`` with caching enabled
        using the TTL, maximum cached keys, and timeout settings from
        the provided configuration.

        Args:
            config: The authentication configuration containing the JWKS
                URL and caching parameters.

        Returns:
            A configured ``JWKSClient`` instance ready for key lookups.

        Examples:
            >>> from oidc_jwt_verifier import AuthConfig
            >>> config = AuthConfig(
            ...     issuer="https://example.auth0.com/",
            ...     audience="https://api.example.com",
            ...     jwks_url="https://example.auth0.com/.well-known/jwks.json",
            ... )
            >>> client = JWKSClient.from_config(config)  # doctest: +SKIP
        """
        jwks_client = PyJWKClient(
            uri=config.jwks_url,
            cache_jwk_set=True,
            lifespan=config.jwks_cache_ttl_s,
            cache_keys=True,
            max_cached_keys=config.jwks_max_cached_keys,
            timeout=config.jwks_timeout_s,
        )
        return cls(_client=jwks_client)

    def get_signing_key_from_jwt(self, token: str | bytes) -> PyJWK:
        """Retrieve the signing key for a JWT from the JWKS.

        Extracts the ``kid`` (Key ID) from the token header and looks up
        the corresponding key in the cached JWKS. If the key is not in
        the cache or the cache has expired, the JWKS is re-fetched from
        the configured URL.

        All errors during this process are mapped to ``AuthError``
        exceptions with HTTP status code 401.

        Args:
            token: The encoded JWT string (or bytes). The token must
                contain a ``kid`` header for key lookup.

        Returns:
            The ``PyJWK`` signing key object from PyJWT.

        Raises:
            AuthError: On any failure during key retrieval. Specific codes:
                - ``"jwks_fetch_failed"``: Network or HTTP errors when
                  fetching the JWKS.
                - ``"key_not_found"``: The ``kid`` in the token does not
                  match any key in the JWKS.
                - ``"jwks_error"``: Other JWKS-related errors (malformed
                  JWKS, invalid key data, etc.).

        Examples:
            Successful key retrieval (requires running JWKS server):

            >>> client = JWKSClient.from_config(config)  # doctest: +SKIP
            >>> key = client.get_signing_key_from_jwt(token)  # doctest: +SKIP
            >>> key.key  # doctest: +SKIP
            <RSAPublicKey ...>

            Key not found in JWKS:

            >>> client.get_signing_key_from_jwt(
            ...     token_with_unknown_kid
            ... )  # doctest: +SKIP
            Traceback (most recent call last):
                ...
            AuthError: No matching signing key
        """
        try:
            return self._client.get_signing_key_from_jwt(token)
        except Exception as exc:
            self._raise_auth_error(exc)

    def get_signing_key(self, kid: str, *, refresh: bool = False) -> PyJWK:
        """Retrieve a signing key directly by ``kid``.

        This method exposes direct key lookup parity with PyJWT's public
        JWKS client surface. When ``refresh=True``, it bypasses any cached
        JWKS document and resolves the key from a freshly fetched set.

        Args:
            kid: JWT key identifier to resolve.
            refresh: Whether to force a JWKS refresh before lookup.

        Returns:
            The matching ``PyJWK`` signing key.

        Raises:
            AuthError: On fetch, parsing, or key lookup failures.

        Examples:
            >>> client = JWKSClient.from_config(config)  # doctest: +SKIP
            >>> key = client.get_signing_key("kid-123")  # doctest: +SKIP
            >>> key.key_id  # doctest: +SKIP
            'kid-123'
        """
        try:
            if not refresh:
                get_signing_key = cast(
                    "Callable[[str], PyJWK]",
                    self._client.get_signing_key,
                )
                return get_signing_key(kid)

            self._clear_signing_key_cache()
            signing_keys = self._client.get_signing_keys(refresh=True)
            signing_key = self._client.match_kid(signing_keys, kid)
            if signing_key is None:
                raise PyJWKClientError(
                    f'Unable to find a signing key that matches: "{kid}"'
                )
            return signing_key
        except Exception as exc:
            self._raise_auth_error(exc)

    def get_signing_keys(self, *, refresh: bool = False) -> list[PyJWK]:
        """Retrieve signing-capable keys from the configured JWKS.

        Args:
            refresh: Whether to force a JWKS refresh before lookup.

        Returns:
            A list of signing-capable ``PyJWK`` objects.

        Raises:
            AuthError: On fetch, parsing, or key extraction failures.

        Examples:
            >>> client = JWKSClient.from_config(config)  # doctest: +SKIP
            >>> keys = client.get_signing_keys(refresh=True)  # doctest: +SKIP
            >>> len(keys) >= 1  # doctest: +SKIP
            True
        """
        try:
            if refresh:
                self._clear_signing_key_cache()
            return self._client.get_signing_keys(refresh=refresh)
        except Exception as exc:
            self._raise_auth_error(exc)

    def healthcheck(self, *, refresh: bool = False) -> bool:
        """Return whether the configured JWKS is currently usable.

        This is a fail-closed convenience API for startup checks and
        readiness probes. It does not log or expose failure detail.

        Args:
            refresh: Whether to force a JWKS refresh before the check.

        Returns:
            ``True`` when at least one signing key can be resolved from the
            configured JWKS endpoint; otherwise ``False``.

        Examples:
            >>> client = JWKSClient.from_config(config)  # doctest: +SKIP
            >>> client.healthcheck(refresh=True)  # doctest: +SKIP
            True
        """
        try:
            self.get_signing_keys(refresh=refresh)
        except AuthError:
            return False
        except Exception:
            return False
        return True

    @staticmethod
    def _raise_auth_error(exc: Exception) -> NoReturn:
        """Raise the canonical ``AuthError`` for a JWKS lookup failure.

        Args:
            exc: The caught exception from the underlying PyJWT client.

        Raises:
            AuthError: Stable public exception for JWKS failures.
        """
        if isinstance(exc, PyJWKClientConnectionError):
            raise AuthError(
                code="jwks_fetch_failed",
                message="JWKS fetch failed",
                status_code=401,
            ) from exc

        if isinstance(exc, PyJWKClientError):
            message = str(exc).lower()
            if (
                "unable to find a signing key" in message
                and "matches" in message
            ):
                raise AuthError(
                    code="key_not_found",
                    message="No matching signing key",
                    status_code=401,
                ) from exc
            raise AuthError(
                code="jwks_error",
                message="JWKS lookup failed",
                status_code=401,
            ) from exc

        raise AuthError(
            code="jwks_error",
            message="JWKS lookup failed",
            status_code=401,
        ) from exc

    def _clear_signing_key_cache(self) -> None:
        """Clear the underlying PyJWT per-kid cache when available."""
        cache_clear = getattr(self._client.get_signing_key, "cache_clear", None)
        if callable(cache_clear):
            cache_clear()
