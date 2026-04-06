"""Asynchronous JWT verification entry point.

This module provides ``AsyncJWTVerifier`` for native async token validation.
It shares the same verification policy as ``JWTVerifier`` but resolves keys
through ``AsyncJWKSClient``.
"""

from __future__ import annotations

from typing import Any

import httpx
import jwt
from jwt import PyJWK

from ._policy import (
    decode_and_validate_payload,
    enforce_authorization_claims,
    parse_and_validate_header,
)
from .async_jwks import AsyncJWKSClient
from .config import AuthConfig
from .errors import AuthError


class AsyncJWTVerifier:
    """Stateful asynchronous JWT verifier for OIDC access tokens.

    This verifier preserves sync-path semantics while using asynchronous JWKS
    fetches and key lookups.

    Args:
        config: Authentication configuration.
        jwks_client: Optional externally managed async JWKS client.
        http_client: Optional externally managed ``httpx.AsyncClient`` used
            when creating an internal ``AsyncJWKSClient``.

    Examples:
        >>> from oidc_jwt_verifier import AuthConfig
        >>> from oidc_jwt_verifier.async_verifier import AsyncJWTVerifier
        >>> config = AuthConfig(
        ...     issuer="https://example.auth0.com/",
        ...     audience="https://api.example.com",
        ...     jwks_url="https://example.auth0.com/.well-known/jwks.json",
        ... )
        >>> verifier = AsyncJWTVerifier(config)  # doctest: +SKIP
    """

    def __init__(
        self,
        config: AuthConfig,
        *,
        jwks_client: AsyncJWKSClient | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        """Initialize an async verifier.

        Args:
            config: Authentication configuration.
            jwks_client: Optional injected async JWKS client.
            http_client: Optional injected HTTP client for internally created
                async JWKS client.
        """
        self._config = config
        self._decoder = jwt.PyJWT(
            options={
                "enforce_minimum_key_length": config.enforce_minimum_key_length
            }
        )
        self._jwks = jwks_client or AsyncJWKSClient.from_config(
            config, http_client=http_client
        )
        self._owns_jwks = jwks_client is None

    async def verify_access_token(self, token: str | bytes) -> dict[str, Any]:
        """Verify a JWT access token and return its claims.

        Args:
            token: Encoded JWT as ``str`` or UTF-8 ``bytes``.

        Returns:
            Decoded JWT payload.

        Raises:
            AuthError: On authentication or authorization failure.
        """
        if isinstance(token, bytes):
            try:
                token = token.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise AuthError(
                    code="malformed_token",
                    message="Malformed token",
                    status_code=401,
                ) from exc

        normalized = token.strip()
        if not normalized:
            raise AuthError(
                code="missing_token",
                message="Missing access token",
                status_code=401,
            )

        _, algorithm = parse_and_validate_header(
            normalized,
            allowed_algorithms=self._config.allowed_algorithms,
        )
        signing_key = await self._jwks.get_signing_key_from_jwt(normalized)

        payload = decode_and_validate_payload(
            decoder=self._decoder,
            token=normalized,
            signing_key=signing_key,
            algorithm=algorithm,
            config=self._config,
        )
        enforce_authorization_claims(payload, config=self._config)
        return payload

    async def get_signing_keys(self, *, refresh: bool = False) -> list[PyJWK]:
        """Return signing-capable JWKS keys through the owned client.

        Args:
            refresh: Whether to force a JWKS refresh before lookup.

        Returns:
            A list of signing-capable ``PyJWK`` objects.

        Raises:
            AuthError: On fetch, parsing, or key extraction failures.
        """
        return await self._jwks.get_signing_keys(refresh=refresh)

    async def healthcheck(self, *, refresh: bool = False) -> bool:
        """Return whether the verifier's configured JWKS is usable.

        This is a convenience layer over the underlying ``AsyncJWKSClient``
        for startup checks and readiness probes.

        Args:
            refresh: Whether to force a JWKS refresh before the check.

        Returns:
            ``True`` when the verifier can currently resolve at least one
            signing key from the configured JWKS endpoint; otherwise
            ``False``.
        """
        return await self._jwks.healthcheck(refresh=refresh)

    async def aclose(self) -> None:
        """Close verifier-owned async resources.

        If the verifier created its own async JWKS client, this method closes
        that client and its owned HTTP resources.
        """
        if self._owns_jwks:
            await self._jwks.aclose()

    async def __aenter__(self) -> AsyncJWTVerifier:
        """Enter async context manager for the verifier.

        Returns:
            This verifier instance.
        """
        return self

    async def __aexit__(
        self, _exc_type: object, _exc: object, _tb: object
    ) -> None:
        """Exit async context manager and close owned resources."""
        await self.aclose()
