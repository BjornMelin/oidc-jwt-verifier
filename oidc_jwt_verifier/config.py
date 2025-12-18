"""Configuration dataclass for JWT verification settings.

This module defines ``AuthConfig``, an immutable dataclass that holds all
parameters required for JWT verification. The configuration validates inputs
at construction time and normalizes sequences to tuples for consistency.

The configuration explicitly blocks the ``alg=none`` algorithm to prevent
algorithm confusion attacks.
"""

from collections.abc import Sequence
from dataclasses import dataclass


def _normalize_str_sequence(value: str | Sequence[str]) -> tuple[str, ...]:
    """Convert a string or sequence of strings to a tuple.

    This utility handles the common pattern where configuration values can be
    specified as either a single string or a sequence of strings.

    Args:
        value: A single string or a sequence of strings. If a single string,
            it is wrapped in a one-element tuple. If a sequence, it is
            converted to a tuple.

    Returns:
        A tuple containing the string(s).

    Examples:
        >>> _normalize_str_sequence("RS256")
        ('RS256',)
        >>> _normalize_str_sequence(["RS256", "RS384"])
        ('RS256', 'RS384')
        >>> _normalize_str_sequence(("ES256",))
        ('ES256',)
    """
    if isinstance(value, str):
        return (value,)
    return tuple(value)


@dataclass(frozen=True, slots=True)
class AuthConfig:
    """Immutable configuration for JWT verification.

    This dataclass holds all settings required by ``JWTVerifier`` to validate
    JWTs against an OIDC provider. The configuration is frozen (immutable)
    and uses slots for memory efficiency.

    All string inputs are stripped of leading/trailing whitespace during
    validation. Sequences are normalized to tuples.

    Attributes:
        issuer: The expected ``iss`` claim value. Must match the token issuer
            exactly. Typically the OIDC provider URL (e.g.,
            ``https://example.auth0.com/``).
        audience: One or more expected ``aud`` claim values. The token must
            contain at least one matching audience. Accepts a single string
            or a sequence of strings.
        jwks_url: The URL to fetch the JSON Web Key Set from. This URL is
            used for all key lookups; the verifier never derives JWKS URLs
            from token headers.
        allowed_algs: Permitted signing algorithms. Defaults to ``("RS256",)``.
            The ``none`` algorithm is always rejected regardless of this
            setting.
        leeway_s: Clock skew tolerance in seconds for ``exp`` and ``nbf``
            claim validation. Defaults to 0.
        jwks_timeout_s: HTTP timeout in seconds for JWKS fetches.
            Defaults to 3.
        jwks_cache_ttl_s: Time-to-live in seconds for cached JWKS data.
            Must be in the range (0, 86400]. Defaults to 300.
        jwks_max_cached_keys: Maximum number of signing keys to cache.
            Must be in the range (0, 1024]. Defaults to 16.
        required_scopes: Scopes that must be present in the token for
            authorization to succeed. Checked against the ``scope_claim``.
            Defaults to an empty tuple (no scope requirements).
        required_permissions: Permissions that must be present in the token.
            Checked against the ``permissions_claim``. Defaults to an empty
            tuple.
        scope_claim: The claim name containing OAuth 2.0 scopes. Defaults
            to ``"scope"``.
        permissions_claim: The claim name containing permissions (commonly
            used by Auth0). Defaults to ``"permissions"``.

    Raises:
        ValueError: If any validation constraint is violated during
            construction. Specific conditions include:
            - Empty or whitespace-only ``issuer``, ``jwks_url``, or
              ``audience``.
            - Empty or whitespace-only ``allowed_algs``, or inclusion of
              the ``none`` algorithm.
            - Negative ``leeway_s``.
            - Non-positive ``jwks_timeout_s``.
            - ``jwks_cache_ttl_s`` outside (0, 86400].
            - ``jwks_max_cached_keys`` outside (0, 1024].
            - Empty or whitespace-only ``scope_claim`` or
              ``permissions_claim``.

    Examples:
        Minimal configuration for Auth0:

        >>> config = AuthConfig(
        ...     issuer="https://example.auth0.com/",
        ...     audience="https://api.example.com",
        ...     jwks_url="https://example.auth0.com/.well-known/jwks.json",
        ... )
        >>> config.audiences
        ('https://api.example.com',)
        >>> config.allowed_algorithms
        ('RS256',)

        Configuration with multiple audiences and scope requirements:

        >>> config = AuthConfig(
        ...     issuer="https://example.auth0.com/",
        ...     audience=["https://api.example.com", "https://api2.example.com"],
        ...     jwks_url="https://example.auth0.com/.well-known/jwks.json",
        ...     allowed_algs=["RS256", "RS384"],
        ...     required_scopes=["read:users", "write:users"],
        ... )
        >>> config.audiences
        ('https://api.example.com', 'https://api2.example.com')
        >>> config.required_scope_set
        {'read:users', 'write:users'}

        Invalid configuration raises ValueError:

        >>> AuthConfig(
        ...     issuer="",
        ...     audience="api",
        ...     jwks_url="https://example.com/.well-known/jwks.json",
        ... )
        Traceback (most recent call last):
            ...
        ValueError: issuer must be non-empty
    """

    issuer: str
    audience: str | Sequence[str]
    jwks_url: str

    allowed_algs: Sequence[str] = ("RS256",)
    leeway_s: int = 0

    jwks_timeout_s: int = 3
    jwks_cache_ttl_s: int = 300
    jwks_max_cached_keys: int = 16

    required_scopes: Sequence[str] = ()
    required_permissions: Sequence[str] = ()
    scope_claim: str = "scope"
    permissions_claim: str = "permissions"

    def __post_init__(self) -> None:
        """Validate and normalize configuration values after initialization.

        This method runs automatically after dataclass initialization. It
        strips whitespace from string values, normalizes sequences to tuples,
        and validates all constraints.

        Raises:
            ValueError: If any validation constraint is violated.
        """
        issuer = self.issuer.strip()
        if not issuer:
            raise ValueError("issuer must be non-empty")
        object.__setattr__(self, "issuer", issuer)

        jwks_url = self.jwks_url.strip()
        if not jwks_url:
            raise ValueError("jwks_url must be non-empty")
        object.__setattr__(self, "jwks_url", jwks_url)

        audiences = tuple(a.strip() for a in _normalize_str_sequence(self.audience))
        if not audiences or any(not a for a in audiences):
            raise ValueError("audience must be non-empty")
        object.__setattr__(self, "audience", audiences)

        allowed_algs = tuple(a.strip() for a in _normalize_str_sequence(self.allowed_algs))
        if not allowed_algs or any(not a for a in allowed_algs):
            raise ValueError("allowed_algs must be non-empty")
        if any(a.lower() == "none" for a in allowed_algs):
            raise ValueError("allowed_algs must not include 'none'")
        object.__setattr__(self, "allowed_algs", allowed_algs)

        if self.leeway_s < 0:
            raise ValueError("leeway_s must be >= 0")

        if self.jwks_timeout_s <= 0:
            raise ValueError("jwks_timeout_s must be > 0")
        if not 0 < self.jwks_cache_ttl_s <= 24 * 60 * 60:
            raise ValueError("jwks_cache_ttl_s must be in (0, 86400]")
        if not 0 < self.jwks_max_cached_keys <= 1024:
            raise ValueError("jwks_max_cached_keys must be in (0, 1024]")

        object.__setattr__(
            self,
            "required_scopes",
            tuple(s.strip() for s in _normalize_str_sequence(self.required_scopes)),
        )
        object.__setattr__(
            self,
            "required_permissions",
            tuple(p.strip() for p in _normalize_str_sequence(self.required_permissions)),
        )

        scope_claim = self.scope_claim.strip()
        if not scope_claim:
            raise ValueError("scope_claim must be non-empty")
        object.__setattr__(self, "scope_claim", scope_claim)

        permissions_claim = self.permissions_claim.strip()
        if not permissions_claim:
            raise ValueError("permissions_claim must be non-empty")
        object.__setattr__(self, "permissions_claim", permissions_claim)

    @property
    def audiences(self) -> tuple[str, ...]:
        """Return the configured audiences as a tuple.

        This property provides consistent tuple access regardless of whether
        the ``audience`` attribute was initialized with a single string or
        a sequence.

        Returns:
            A tuple of audience strings.

        Examples:
            >>> config = AuthConfig(
            ...     issuer="https://example.auth0.com/",
            ...     audience="https://api.example.com",
            ...     jwks_url="https://example.auth0.com/.well-known/jwks.json",
            ... )
            >>> config.audiences
            ('https://api.example.com',)
        """
        # __post_init__ normalizes audience to tuple
        return self.audience  # type: ignore[return-value]

    @property
    def allowed_algorithms(self) -> tuple[str, ...]:
        """Return the allowed algorithms as a tuple.

        This property provides consistent tuple access regardless of whether
        the ``allowed_algs`` attribute was initialized with a single string
        or a sequence.

        Returns:
            A tuple of algorithm name strings.

        Examples:
            >>> config = AuthConfig(
            ...     issuer="https://example.auth0.com/",
            ...     audience="https://api.example.com",
            ...     jwks_url="https://example.auth0.com/.well-known/jwks.json",
            ...     allowed_algs=["RS256", "ES256"],
            ... )
            >>> config.allowed_algorithms
            ('RS256', 'ES256')
        """
        # __post_init__ normalizes allowed_algs to tuple
        return self.allowed_algs  # type: ignore[return-value]

    @property
    def required_scope_set(self) -> set[str]:
        """Return the required scopes as a set for efficient membership testing.

        Empty strings in the ``required_scopes`` sequence are filtered out.

        Returns:
            A set of non-empty scope strings.

        Examples:
            >>> config = AuthConfig(
            ...     issuer="https://example.auth0.com/",
            ...     audience="https://api.example.com",
            ...     jwks_url="https://example.auth0.com/.well-known/jwks.json",
            ...     required_scopes=["read:users", "write:users"],
            ... )
            >>> config.required_scope_set == {"read:users", "write:users"}
            True
        """
        return {s for s in self.required_scopes if s}

    @property
    def required_permission_set(self) -> set[str]:
        """Return the required permissions as a set for efficient membership testing.

        Empty strings in the ``required_permissions`` sequence are filtered out.

        Returns:
            A set of non-empty permission strings.

        Examples:
            >>> config = AuthConfig(
            ...     issuer="https://example.auth0.com/",
            ...     audience="https://api.example.com",
            ...     jwks_url="https://example.auth0.com/.well-known/jwks.json",
            ...     required_permissions=["admin", "editor"],
            ... )
            >>> config.required_permission_set == {"admin", "editor"}
            True
        """
        return {p for p in self.required_permissions if p}
