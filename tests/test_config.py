"""Tests for AuthConfig validation and normalization.

This module tests all validation logic in AuthConfig.__post_init__(),
including required field validation, range checks, algorithm restrictions,
and sequence normalization.
"""

from typing import Any

import pytest

from oidc_jwt_verifier import AuthConfig


def _valid_config_kwargs() -> dict[str, Any]:
    """Return minimal valid config kwargs for testing."""
    return {
        "issuer": "https://issuer.example/",
        "audience": "https://api.example",
        "jwks_url": "https://issuer.example/.well-known/jwks.json",
    }


# ============================================================================
# Required Field Validation
# ============================================================================


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("issuer", ""),
        ("issuer", "   "),
        ("jwks_url", ""),
        ("jwks_url", "   "),
    ],
)
def test_config_empty_required_string_raises_valueerror(field: str, value: str) -> None:
    """AuthConfig rejects empty or whitespace-only issuer and jwks_url."""
    kwargs = _valid_config_kwargs()
    kwargs[field] = value

    with pytest.raises(ValueError, match=f"{field} must be non-empty"):
        AuthConfig(**kwargs)


@pytest.mark.parametrize(
    "audience",
    [
        "",
        "   ",
        [],
        [""],
        ["   "],
        ["valid", ""],
    ],
)
def test_config_empty_audience_raises_valueerror(audience: str | list[str]) -> None:
    """AuthConfig rejects empty or whitespace-only audience values."""
    kwargs = _valid_config_kwargs()
    kwargs["audience"] = audience

    with pytest.raises(ValueError, match="audience must be non-empty"):
        AuthConfig(**kwargs)


# ============================================================================
# Algorithm Validation
# ============================================================================


@pytest.mark.parametrize("alg_none", ["none", "None", "NONE", "nOnE"])
def test_config_alg_none_rejected_case_insensitive(alg_none: str) -> None:
    """AuthConfig blocks alg=none in any case variation at config time."""
    kwargs = _valid_config_kwargs()
    kwargs["allowed_algs"] = (alg_none,)

    with pytest.raises(ValueError, match="must not include 'none'"):
        AuthConfig(**kwargs)


def test_config_alg_none_in_list_rejected() -> None:
    """AuthConfig rejects allowed_algs list containing 'none' among valid algs."""
    kwargs = _valid_config_kwargs()
    kwargs["allowed_algs"] = ("RS256", "none", "RS384")

    with pytest.raises(ValueError, match="must not include 'none'"):
        AuthConfig(**kwargs)


@pytest.mark.parametrize(
    "allowed_algs",
    [
        "",
        [],
        [""],
        ["   "],
    ],
)
def test_config_empty_allowed_algs_rejected(allowed_algs: str | list[str]) -> None:
    """AuthConfig rejects empty or whitespace-only allowed_algs."""
    kwargs = _valid_config_kwargs()
    kwargs["allowed_algs"] = allowed_algs

    with pytest.raises(ValueError, match="allowed_algs must be non-empty"):
        AuthConfig(**kwargs)


# ============================================================================
# Numeric Range Validation
# ============================================================================


@pytest.mark.parametrize(
    ("param", "invalid_value", "error_pattern"),
    [
        ("leeway_s", -1, "leeway_s must be >= 0"),
        ("jwks_timeout_s", 0, "jwks_timeout_s must be > 0"),
        ("jwks_timeout_s", -1, "jwks_timeout_s must be > 0"),
        ("jwks_cache_ttl_s", 0, r"jwks_cache_ttl_s must be in \(0, 86400\]"),
        ("jwks_cache_ttl_s", 86401, r"jwks_cache_ttl_s must be in \(0, 86400\]"),
        ("jwks_max_cached_keys", 0, r"jwks_max_cached_keys must be in \(0, 1024\]"),
        ("jwks_max_cached_keys", 1025, r"jwks_max_cached_keys must be in \(0, 1024\]"),
    ],
)
def test_config_numeric_range_invalid_raises_valueerror(
    param: str, invalid_value: int, error_pattern: str
) -> None:
    """AuthConfig rejects numeric parameters outside valid ranges."""
    kwargs = _valid_config_kwargs()
    kwargs[param] = invalid_value

    with pytest.raises(ValueError, match=error_pattern):
        AuthConfig(**kwargs)


@pytest.mark.parametrize(
    ("param", "valid_boundary"),
    [
        ("leeway_s", 0),
        ("leeway_s", 100),
        ("jwks_timeout_s", 1),
        ("jwks_timeout_s", 100),
        ("jwks_cache_ttl_s", 1),
        ("jwks_cache_ttl_s", 86400),
        ("jwks_max_cached_keys", 1),
        ("jwks_max_cached_keys", 1024),
    ],
)
def test_config_numeric_range_valid_boundaries_accepted(param: str, valid_boundary: int) -> None:
    """AuthConfig accepts numeric parameters at valid boundaries."""
    kwargs = _valid_config_kwargs()
    kwargs[param] = valid_boundary

    config = AuthConfig(**kwargs)
    assert getattr(config, param) == valid_boundary


# ============================================================================
# Claim Name Validation
# ============================================================================


@pytest.mark.parametrize("claim_param", ["scope_claim", "permissions_claim"])
def test_config_empty_claim_name_rejected(claim_param: str) -> None:
    """AuthConfig rejects empty scope_claim or permissions_claim."""
    kwargs = _valid_config_kwargs()
    kwargs[claim_param] = ""

    with pytest.raises(ValueError, match=f"{claim_param} must be non-empty"):
        AuthConfig(**kwargs)


@pytest.mark.parametrize("claim_param", ["scope_claim", "permissions_claim"])
def test_config_whitespace_claim_name_rejected(claim_param: str) -> None:
    """AuthConfig rejects whitespace-only scope_claim or permissions_claim."""
    kwargs = _valid_config_kwargs()
    kwargs[claim_param] = "   "

    with pytest.raises(ValueError, match=f"{claim_param} must be non-empty"):
        AuthConfig(**kwargs)


# ============================================================================
# Normalization Tests
# ============================================================================


def test_config_whitespace_stripping() -> None:
    """AuthConfig strips whitespace from string inputs."""
    config = AuthConfig(
        issuer="  https://issuer.example/  ",
        audience="  https://api.example  ",
        jwks_url="  https://issuer.example/.well-known/jwks.json  ",
        scope_claim="  custom_scope  ",
        permissions_claim="  custom_permissions  ",
    )
    assert config.issuer == "https://issuer.example/"
    assert config.jwks_url == "https://issuer.example/.well-known/jwks.json"
    assert config.audiences == ("https://api.example",)
    assert config.scope_claim == "custom_scope"
    assert config.permissions_claim == "custom_permissions"


def test_config_sequence_to_tuple_normalization() -> None:
    """AuthConfig normalizes sequences to tuples."""
    config = AuthConfig(
        issuer="https://issuer.example/",
        audience=["aud1", "aud2"],  # list
        jwks_url="https://issuer.example/.well-known/jwks.json",
        allowed_algs=["RS256", "RS384"],  # list
        required_scopes=["read:users"],  # list
        required_permissions=["admin"],  # list
    )
    assert isinstance(config.audiences, tuple)
    assert isinstance(config.allowed_algorithms, tuple)
    assert config.audiences == ("aud1", "aud2")
    assert config.allowed_algorithms == ("RS256", "RS384")


def test_config_single_string_audience_to_tuple() -> None:
    """AuthConfig normalizes single string audience to tuple."""
    config = AuthConfig(
        issuer="https://issuer.example/",
        audience="https://api.example",
        jwks_url="https://issuer.example/.well-known/jwks.json",
    )
    assert config.audiences == ("https://api.example",)


def test_config_single_string_alg_to_tuple() -> None:
    """AuthConfig normalizes single string algorithm to tuple."""
    config = AuthConfig(
        issuer="https://issuer.example/",
        audience="https://api.example",
        jwks_url="https://issuer.example/.well-known/jwks.json",
        allowed_algs="RS256",
    )
    assert config.allowed_algorithms == ("RS256",)


# ============================================================================
# Property Tests
# ============================================================================


def test_config_required_scope_set_filters_empty() -> None:
    """required_scope_set filters out empty strings."""
    config = AuthConfig(
        issuer="https://issuer.example/",
        audience="https://api.example",
        jwks_url="https://issuer.example/.well-known/jwks.json",
        required_scopes=("read:users", "", "write:users", "  "),
    )
    # Whitespace is stripped during normalization, resulting in empty strings
    assert config.required_scope_set == {"read:users", "write:users"}


def test_config_required_permission_set_filters_empty() -> None:
    """required_permission_set filters out empty strings."""
    config = AuthConfig(
        issuer="https://issuer.example/",
        audience="https://api.example",
        jwks_url="https://issuer.example/.well-known/jwks.json",
        required_permissions=("admin", "", "editor", "  "),
    )
    assert config.required_permission_set == {"admin", "editor"}


def test_config_defaults() -> None:
    """AuthConfig has correct default values."""
    config = AuthConfig(
        issuer="https://issuer.example/",
        audience="https://api.example",
        jwks_url="https://issuer.example/.well-known/jwks.json",
    )
    assert config.allowed_algorithms == ("RS256",)
    assert config.leeway_s == 0
    assert config.jwks_timeout_s == 3
    assert config.jwks_cache_ttl_s == 300
    assert config.jwks_max_cached_keys == 16
    assert config.required_scope_set == set()
    assert config.required_permission_set == set()
    assert config.scope_claim == "scope"
    assert config.permissions_claim == "permissions"


def test_config_is_frozen() -> None:
    """AuthConfig is immutable (frozen dataclass)."""
    config = AuthConfig(
        issuer="https://issuer.example/",
        audience="https://api.example",
        jwks_url="https://issuer.example/.well-known/jwks.json",
    )

    with pytest.raises(AttributeError):
        config.issuer = "https://new-issuer.example/"  # type: ignore[misc]
