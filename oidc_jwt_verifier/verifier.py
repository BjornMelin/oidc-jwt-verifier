"""Core JWT verification logic.

This module provides ``JWTVerifier``, the main entry point for validating
JSON Web Tokens against an OIDC provider. The verifier performs a complete
verification chain including header validation, signature verification,
standard claim checks, and authorization enforcement.

The verification process implements fail-closed semantics: any error at
any stage results in rejection via ``AuthError``.
"""

from typing import Any

import jwt

from ._policy import (
    decode_and_validate_payload,
    enforce_authorization_claims,
    map_decode_error,
    parse_and_validate_header,
    parse_permissions_claim,
    parse_scope_claim,
)
from .config import AuthConfig
from .errors import AuthError
from .jwks import JWKSClient


def _parse_scope_claim(value: Any) -> set[str]:
    """Parse a scope claim value into a set of scope strings.

    OAuth 2.0 scopes can be represented in tokens either as a
    space-delimited string (per RFC 6749) or as a JSON array of strings
    (commonly used by some providers).

    Args:
        value: The raw claim value from the JWT payload. Expected to be
            either a space-delimited string, a list of strings, or None.

    Returns:
        A set of non-empty scope strings. Empty strings are filtered out.
        Returns an empty set if the value is None or an unsupported type.

    Examples:
        >>> _parse_scope_claim("read:users write:users")
        {'read:users', 'write:users'}
        >>> _parse_scope_claim(["read:users", "write:users"])
        {'read:users', 'write:users'}
        >>> _parse_scope_claim(None)
        set()
        >>> _parse_scope_claim(12345)
        set()
    """
    return parse_scope_claim(value)


def _parse_permissions_claim(value: Any) -> set[str]:
    """Parse a permissions claim value into a set of permission strings.

    Auth0 and similar providers typically store permissions as a JSON
    array in the token payload. This function also handles the less
    common case of space-delimited permission strings.

    Args:
        value: The raw claim value from the JWT payload. Expected to be
            either a list of strings, a space-delimited string, or None.

    Returns:
        A set of non-empty permission strings. Empty strings are filtered
        out. Returns an empty set if the value is None or an unsupported
        type.

    Examples:
        >>> _parse_permissions_claim(["admin", "read:users"])
        {'admin', 'read:users'}
        >>> _parse_permissions_claim("admin read:users")
        {'admin', 'read:users'}
        >>> _parse_permissions_claim(None)
        set()
        >>> _parse_permissions_claim({"nested": "object"})
        set()
    """
    return parse_permissions_claim(value)


def _map_decode_error(exc: Exception) -> AuthError:
    """Map PyJWT decode exceptions to AuthError instances.

    Converts PyJWT's exception hierarchy into ``AuthError`` instances with
    appropriate error codes and HTTP status codes. All decode errors
    result in a 401 status code.

    Args:
        exc: The exception raised by PyJWT during token decoding or
            verification.

    Returns:
        An ``AuthError`` instance with a specific error code based on the
        exception type:
        - ``"token_expired"``: The token's ``exp`` claim is in the past.
        - ``"token_not_yet_valid"``: The token's ``nbf`` claim is in the
          future.
        - ``"invalid_issuer"``: The ``iss`` claim does not match.
        - ``"invalid_audience"``: The ``aud`` claim does not match.
        - ``"missing_claim"``: A required claim is absent.
        - ``"disallowed_alg"``: The signing algorithm is not permitted.
        - ``"malformed_token"``: The token structure is invalid.
        - ``"invalid_token"``: Invalid key material or other token validation
          failures.

    Examples:
        >>> import jwt
        >>> error = _map_decode_error(jwt.ExpiredSignatureError())
        >>> error.code
        'token_expired'
        >>> error.status_code
        401
    """
    return map_decode_error(exc)


class JWTVerifier:
    """Stateful JWT verifier for OIDC access tokens.

    This class performs complete JWT verification including:

    1. **Header validation**: Rejects tokens with dangerous headers
       (``jku``, ``x5u``, ``crit``) and ensures the algorithm is in the
       allowlist.
    2. **Key retrieval**: Fetches the signing key from the JWKS using the
       token's ``kid`` header.
    3. **Signature verification**: Validates the cryptographic signature.
    4. **Claim validation**: Checks ``iss``, ``aud``, ``exp``, and ``nbf``
       claims against configuration.
    5. **Authorization enforcement**: Verifies required scopes and
       permissions are present (returns 403 on failure).

    The verifier maintains a cached JWKS client for efficient key lookups
    across multiple token verifications.

    Attributes:
        _config: The authentication configuration.
        _jwks: The JWKS client for signing key retrieval.
        _decoder: A configured ``jwt.PyJWT`` instance used for token decoding.

    Examples:
        Basic token verification:

        >>> from oidc_jwt_verifier import AuthConfig, AuthError, JWTVerifier
        >>> config = AuthConfig(
        ...     issuer="https://example.auth0.com/",
        ...     audience="https://api.example.com",
        ...     jwks_url="https://example.auth0.com/.well-known/jwks.json",
        ... )
        >>> verifier = JWTVerifier(config)  # doctest: +SKIP
        >>> claims = verifier.verify_access_token(token)  # doctest: +SKIP
        >>> claims["sub"]  # doctest: +SKIP
        'auth0|123456789'

        Handling verification errors:

        >>> try:
        ...     claims = verifier.verify_access_token(expired_token)
        ... except AuthError as e:
        ...     print(f"Error: {e.code}, Status: {e.status_code}")
        ...     print(e.www_authenticate_header())  # doctest: +SKIP
        Error: token_expired, Status: 401
        Bearer error="invalid_token", error_description="Token is expired"

        Verifying tokens with scope requirements:

        >>> config = AuthConfig(
        ...     issuer="https://example.auth0.com/",
        ...     audience="https://api.example.com",
        ...     jwks_url="https://example.auth0.com/.well-known/jwks.json",
        ...     required_scopes=["read:users"],
        ... )
        >>> verifier = JWTVerifier(config)  # doctest: +SKIP
        >>> # Token without required scopes raises AuthError with 403
        >>> claims = verifier.verify_access_token(token_without_scopes)  # doctest: +SKIP
        Traceback (most recent call last):
            ...
        AuthError: Insufficient scope
    """

    def __init__(self, config: AuthConfig) -> None:
        """Initialize a JWT verifier with the given configuration.

        Creates a JWKS client configured with the caching parameters
        from the provided configuration.

        Args:
            config: The authentication configuration specifying the
                issuer, audience, JWKS URL, allowed algorithms, and
                authorization requirements.

        Examples:
            >>> from oidc_jwt_verifier import AuthConfig
            >>> config = AuthConfig(
            ...     issuer="https://example.auth0.com/",
            ...     audience="https://api.example.com",
            ...     jwks_url="https://example.auth0.com/.well-known/jwks.json",
            ... )
            >>> verifier = JWTVerifier(config)  # doctest: +SKIP
        """
        self._config = config
        self._jwks = JWKSClient.from_config(config)
        self._decoder = jwt.PyJWT(
            options={"enforce_minimum_key_length": config.enforce_minimum_key_length}
        )

    def verify_access_token(self, token: str) -> dict[str, Any]:
        """Verify an access token and return its claims.

        Performs the complete verification chain:

        1. Validates the token is non-empty.
        2. Parses and validates the token header (rejects ``jku``, ``x5u``,
           ``crit``; validates ``alg`` and ``kid``).
        3. Fetches the signing key from the JWKS.
        4. Decodes and verifies the token signature.
        5. Validates standard claims (``iss``, ``aud``, ``exp``, ``nbf``).
        6. Enforces required scopes and permissions.

        The method supports Auth0-style multi-audience tokens where the
        ``aud`` claim is an array. Verification succeeds if any configured
        audience matches any audience in the token.

        Args:
            token: The encoded JWT access token string. Leading and
                trailing whitespace is stripped.

        Returns:
            The decoded token payload as a dictionary. Contains all
            claims from the token including registered claims (``iss``,
            ``sub``, ``aud``, ``exp``, etc.) and any custom claims.

        Raises:
            AuthError: On any verification failure. The error's
                ``status_code`` indicates the appropriate HTTP response:
                - 401 for authentication failures (missing token,
                  malformed token, invalid signature, expired token,
                  wrong issuer/audience).
                - 403 for authorization failures (insufficient scopes
                  or permissions).

                Specific error codes include:
                - ``"missing_token"``: Empty or whitespace-only token.
                - ``"malformed_token"``: Unparseable token or missing
                  ``alg`` header.
                - ``"forbidden_header"``: Token contains ``jku``,
                  ``x5u``, or ``crit`` headers.
                - ``"disallowed_alg"``: Algorithm not in allowlist or
                  is ``none``.
                - ``"missing_kid"``: Token lacks ``kid`` header.
                - ``"token_expired"``: Token ``exp`` is in the past.
                - ``"token_not_yet_valid"``: Token ``nbf`` is in the
                  future.
                - ``"invalid_issuer"``: ``iss`` claim mismatch.
                - ``"invalid_audience"``: ``aud`` claim mismatch.
                - ``"insufficient_scope"``: Missing required scopes.
                - ``"insufficient_permissions"``: Missing required
                  permissions.

        Examples:
            Successful verification:

            >>> claims = verifier.verify_access_token(valid_token)  # doctest: +SKIP
            >>> claims["sub"]  # doctest: +SKIP
            'auth0|123456789'
            >>> claims["aud"]  # doctest: +SKIP
            'https://api.example.com'

            Missing token:

            >>> verifier.verify_access_token("")  # doctest: +SKIP
            Traceback (most recent call last):
                ...
            AuthError: Missing access token

            Expired token:

            >>> verifier.verify_access_token(expired_token)  # doctest: +SKIP
            Traceback (most recent call last):
                ...
            AuthError: Token is expired
        """
        token = token.strip()
        if not token:
            raise AuthError(code="missing_token", message="Missing access token", status_code=401)

        _, alg = parse_and_validate_header(
            token, allowed_algorithms=self._config.allowed_algorithms
        )
        signing_key = self._jwks.get_signing_key_from_jwt(token)

        payload = decode_and_validate_payload(
            decoder=self._decoder,
            token=token,
            signing_key=signing_key,
            algorithm=alg,
            config=self._config,
        )
        enforce_authorization_claims(payload, config=self._config)
        return payload
