"""JWKS client wrapper with caching and error mapping.

This module provides ``JWKSClient``, a thin wrapper around PyJWT's
``PyJWKClient`` that adds configurable caching and maps JWKS-related
errors to ``AuthError`` exceptions with appropriate error codes and
HTTP status codes.

The client never fetches JWKS from URLs specified in token headers;
all fetches use the URL configured in ``AuthConfig``.
"""

from dataclasses import dataclass
from typing import Any

from jwt import PyJWKClient

from .config import AuthConfig
from .errors import AuthError


# Import PyJWT exception types with fallback for version compatibility.
# Some versions of PyJWT may not expose these exceptions.
try:
    from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError
except Exception:  # pragma: no cover
    PyJWKClientConnectionError = None  # type: ignore[assignment,misc]
    PyJWKClientError = None  # type: ignore[assignment,misc]


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

    def get_signing_key_from_jwt(self, token: str) -> Any:
        """Retrieve the signing key for a JWT from the JWKS.

        Extracts the ``kid`` (Key ID) from the token header and looks up
        the corresponding key in the cached JWKS. If the key is not in
        the cache or the cache has expired, the JWKS is re-fetched from
        the configured URL.

        All errors during this process are mapped to ``AuthError``
        exceptions with HTTP status code 401.

        Args:
            token: The encoded JWT string. The token must contain a ``kid``
                header for key lookup.

        Returns:
            The signing key object from PyJWT. The key's ``key`` attribute
            contains the cryptographic key material suitable for
            verification.

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

            >>> client.get_signing_key_from_jwt(token_with_unknown_kid)  # doctest: +SKIP
            Traceback (most recent call last):
                ...
            AuthError: No matching signing key
        """
        try:
            return self._client.get_signing_key_from_jwt(token)
        except Exception as exc:
            # Handle connection errors (network failures, timeouts).
            if PyJWKClientConnectionError is not None and isinstance(
                exc, PyJWKClientConnectionError
            ):
                raise AuthError(
                    code="jwks_fetch_failed",
                    message="JWKS fetch failed",
                    status_code=401,
                ) from exc

            # Handle other PyJWKClient errors (key not found, malformed JWKS).
            # NOTE: PyJWT does not provide a dedicated exception class for "key not
            # found" errors. PyJWKClientError is raised for both kid lookup failures
            # and other client issues. We differentiate by matching error message
            # substrings ("unable to find", "kid"). This creates coupling to PyJWT's
            # internal message format - verify these patterns when upgrading PyJWT.
            # See tests/test_jwks.py for regression tests that validate these patterns.
            if PyJWKClientError is not None and isinstance(exc, PyJWKClientError):
                message = str(exc).lower()
                if "unable to find" in message or "kid" in message:
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

            # Catch-all for unexpected exceptions.
            raise AuthError(
                code="jwks_error",
                message="JWKS lookup failed",
                status_code=401,
            ) from exc
