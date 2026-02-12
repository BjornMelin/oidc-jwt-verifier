"""Shared JWT verification policy helpers.

This internal module centralizes the policy logic used by both the sync and
async verifier implementations:

- Header parsing and hardening checks.
- Decode error mapping to ``AuthError``.
- Claim decoding/validation loops for multi-audience support.
- Scope and permission enforcement.

The helpers in this module are intentionally side-effect free except for
raising ``AuthError`` on policy violations.
"""

from collections.abc import Sequence
from typing import Any

import jwt
from jwt.types import Options

from .config import AuthConfig
from .errors import AuthError


def parse_scope_claim(value: Any) -> set[str]:
    """Parse an OAuth scope claim into a normalized set.

    Args:
        value: Raw JWT claim value. Supported formats are ``str``, ``list``,
            or ``None``.

    Returns:
        A set of non-empty scope strings. Unsupported claim shapes return
        an empty set.

    Examples:
        >>> parse_scope_claim("read:users write:users")
        {'read:users', 'write:users'}
        >>> parse_scope_claim(["read:users", "write:users"])
        {'read:users', 'write:users'}
        >>> parse_scope_claim(None)
        set()
    """
    if value is None:
        return set()
    if isinstance(value, str):
        return {scope for scope in value.split() if scope}
    if isinstance(value, list):
        return {
            scope
            for scope in (str(item) for item in value if item is not None)
            if scope
        }
    return set()


def parse_permissions_claim(value: Any) -> set[str]:
    """Parse a permissions claim into a normalized set.

    Args:
        value: Raw JWT claim value. Supported formats are ``list``, ``str``,
            or ``None``.

    Returns:
        A set of non-empty permission strings. Unsupported claim shapes
        return an empty set.

    Examples:
        >>> parse_permissions_claim(["admin", "read:users"])
        {'admin', 'read:users'}
        >>> parse_permissions_claim("admin read:users")
        {'admin', 'read:users'}
        >>> parse_permissions_claim(None)
        set()
    """
    if value is None:
        return set()
    if isinstance(value, list):
        return {
            permission
            for permission in (str(item) for item in value if item is not None)
            if permission
        }
    if isinstance(value, str):
        return {permission for permission in value.split() if permission}
    return set()


def map_decode_error(exc: Exception) -> AuthError:
    """Map PyJWT decode errors to ``AuthError``.

    Args:
        exc: Exception raised by ``jwt.decode``.

    Returns:
        A mapped ``AuthError`` with an RFC-aligned status code and stable
        internal error code.
    """
    if isinstance(exc, jwt.ExpiredSignatureError):
        return AuthError(
            code="token_expired", message="Token is expired", status_code=401
        )
    if isinstance(exc, jwt.ImmatureSignatureError):
        return AuthError(
            code="token_not_yet_valid",
            message="Token is not valid yet",
            status_code=401,
        )
    if isinstance(exc, jwt.InvalidIssuerError):
        return AuthError(
            code="invalid_issuer", message="Invalid issuer", status_code=401
        )
    if isinstance(exc, jwt.InvalidAudienceError):
        return AuthError(
            code="invalid_audience", message="Invalid audience", status_code=401
        )
    if isinstance(exc, jwt.MissingRequiredClaimError):
        return AuthError(
            code="missing_claim", message=str(exc), status_code=401
        )
    if isinstance(exc, jwt.InvalidKeyError):
        return AuthError(
            code="invalid_token", message="Invalid token", status_code=401
        )
    if isinstance(exc, jwt.InvalidAlgorithmError):
        return AuthError(
            code="disallowed_alg",
            message="Disallowed signing algorithm",
            status_code=401,
        )
    if isinstance(exc, jwt.DecodeError):
        return AuthError(
            code="malformed_token", message="Malformed token", status_code=401
        )
    if isinstance(exc, jwt.InvalidTokenError):
        return AuthError(
            code="invalid_token", message="Invalid token", status_code=401
        )
    return AuthError(
        code="invalid_token", message="Invalid token", status_code=401
    )


def parse_and_validate_header(
    token: str,
    *,
    allowed_algorithms: Sequence[str],
) -> tuple[dict[str, Any], str]:
    """Parse and validate unverified JWT headers.

    This function performs header-only checks before any JWKS lookup to
    enforce fail-closed semantics and prevent unsafe key source behavior.

    Args:
        token: Encoded JWT.
        allowed_algorithms: Allowed signing algorithms configured by the user.

    Returns:
        A tuple of ``(header, alg)``.

    Raises:
        AuthError: If the token header is malformed or violates security
            policy.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.DecodeError as exc:
        raise AuthError(
            code="malformed_token",
            message="Malformed token",
            status_code=401,
        ) from exc

    # Header hardening: never allow token-provided key URL hints.
    if "jku" in header or "x5u" in header or "crit" in header:
        raise AuthError(
            code="forbidden_header",
            message="Forbidden token header parameter",
            status_code=401,
        )

    alg = header.get("alg")
    if not isinstance(alg, str) or not alg:
        raise AuthError(
            code="malformed_token",
            message="Missing alg header",
            status_code=401,
        )
    if alg.lower() == "none":
        raise AuthError(
            code="disallowed_alg",
            message="Disallowed signing algorithm",
            status_code=401,
        )
    if alg not in allowed_algorithms:
        raise AuthError(
            code="disallowed_alg",
            message="Disallowed signing algorithm",
            status_code=401,
        )

    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise AuthError(
            code="missing_kid", message="Missing kid header", status_code=401
        )

    return header, alg


def build_decode_options() -> Options:
    """Build canonical decode options shared by sync and async verifiers.

    Returns:
        A ``jwt.types.Options`` dictionary with strict verification settings.
    """
    return {
        "require": ["exp", "iss", "aud"],
        "verify_signature": True,
        "verify_exp": True,
        "verify_nbf": True,
        "verify_aud": True,
        "verify_iss": True,
        "strict_aud": False,  # Allow array audience claims.
    }


def decode_and_validate_payload(
    *,
    decoder: jwt.PyJWT,
    token: str,
    signing_key: Any,
    algorithm: str,
    config: AuthConfig,
) -> dict[str, Any]:
    """Decode payload and validate issuer/audience/time claims.

    Args:
        decoder: Configured ``jwt.PyJWT`` decoder instance.
        token: Encoded JWT.
        signing_key: Resolved signing key from JWKS.
        algorithm: Header algorithm validated against allowlist.
        config: Auth configuration.

    Returns:
        Decoded JWT payload.

    Raises:
        AuthError: If validation fails for every configured audience or for
            any other decode error.
    """
    payload: dict[str, Any] | None = None
    last_exc: Exception | None = None
    options = build_decode_options()

    for audience in config.audiences:
        try:
            payload = decoder.decode(
                token,
                signing_key,
                algorithms=[algorithm],
                audience=audience,
                issuer=config.issuer,
                leeway=config.leeway_s,
                options=options,
            )
            break
        except jwt.InvalidAudienceError as exc:
            last_exc = exc
            continue
        except jwt.PyJWTError as exc:
            raise map_decode_error(exc) from exc

    if payload is None:
        raise map_decode_error(
            last_exc or jwt.InvalidAudienceError("invalid audience")
        )

    return payload


def enforce_authorization_claims(
    payload: dict[str, Any], *, config: AuthConfig
) -> None:
    """Enforce required scopes and permissions.

    Args:
        payload: Decoded JWT payload.
        config: Auth configuration.

    Raises:
        AuthError: With status code 403 when required scopes or permissions
            are missing.
    """
    required_scopes = config.required_scope_set
    required_permissions = config.required_permission_set

    token_scopes = parse_scope_claim(payload.get(config.scope_claim))
    token_permissions = parse_permissions_claim(
        payload.get(config.permissions_claim)
    )

    missing_scopes = required_scopes - token_scopes
    if missing_scopes:
        raise AuthError(
            code="insufficient_scope",
            message="Insufficient scope",
            status_code=403,
            required_scopes=tuple(sorted(missing_scopes)),
        )

    missing_permissions = required_permissions - token_permissions
    if missing_permissions:
        raise AuthError(
            code="insufficient_permissions",
            message="Insufficient permissions",
            status_code=403,
            required_permissions=tuple(sorted(missing_permissions)),
        )
