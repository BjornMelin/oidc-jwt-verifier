"""Framework-agnostic JWT verification for OIDC/JWKS issuers.

This package provides a minimal, security-focused JWT verification library
designed for integration with web frameworks such as Flask, FastAPI, Bottle,
Dash, and AWS Lambda handlers.

The verification chain implements fail-closed semantics: any error during
token parsing, JWKS fetching, signature verification, or claim validation
results in rejection. The JWKS URL is never derived from token headers.

Modules:
    config: Configuration dataclass for verifier settings.
    errors: Exception type with RFC 6750 Bearer challenge support.
    jwks: JWKS client wrapper with caching.
    verifier: Core JWT verification logic.

Public API:
    AuthConfig: Immutable configuration for issuer, audience, algorithms,
        and authorization requirements.
    AuthError: Exception raised on authentication or authorization failure,
        with stable error codes and HTTP status codes.
    JWTVerifier: Stateful verifier instance that validates JWTs against
        the configured OIDC provider.

Examples:
    Basic usage with Auth0:

    >>> from oidc_jwt_verifier import AuthConfig, AuthError, JWTVerifier
    >>> config = AuthConfig(
    ...     issuer="https://example.auth0.com/",
    ...     audience="https://api.example.com",
    ...     jwks_url="https://example.auth0.com/.well-known/jwks.json",
    ... )
    >>> verifier = JWTVerifier(config)
    >>> try:
    ...     claims = verifier.verify_access_token(token)
    ... except AuthError as e:
    ...     print(e.www_authenticate_header())

Security Notes:
    - The ``alg=none`` algorithm is always rejected.
    - Tokens with ``jku``, ``x5u``, or ``crit`` headers are rejected.
    - JWKS is fetched only from the pre-configured URL, not from token headers.
    - The ``kid`` header is required for key lookup.
"""

from .config import AuthConfig
from .errors import AuthError
from .verifier import JWTVerifier


__all__ = ["AuthConfig", "AuthError", "JWTVerifier"]
