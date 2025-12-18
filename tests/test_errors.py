"""Tests for AuthError and RFC 6750 WWW-Authenticate header generation.

This module tests AuthError construction, status code validation, and
RFC 6750-compliant WWW-Authenticate header generation including proper
escaping of special characters.
"""

import pytest

from oidc_jwt_verifier import AuthError
from oidc_jwt_verifier.errors import _quote_rfc6750_value


# ============================================================================
# AuthError Construction and Validation
# ============================================================================


def test_auth_error_invalid_status_code_raises_valueerror() -> None:
    """AuthError rejects status codes other than 401 or 403."""
    with pytest.raises(ValueError, match="status_code must be 401 or 403"):
        AuthError(code="internal_error", message="Something broke", status_code=500)


@pytest.mark.parametrize("invalid_status", [200, 400, 404, 500, 502])
def test_auth_error_rejects_various_invalid_status_codes(invalid_status: int) -> None:
    """AuthError rejects various non-401/403 status codes."""
    with pytest.raises(ValueError, match="status_code must be 401 or 403"):
        AuthError(code="test", message="test", status_code=invalid_status)


@pytest.mark.parametrize("valid_status", [401, 403])
def test_auth_error_accepts_valid_status_codes(valid_status: int) -> None:
    """AuthError accepts 401 and 403 status codes."""
    error = AuthError(code="test", message="test message", status_code=valid_status)
    assert error.status_code == valid_status
    assert error.code == "test"
    assert error.message == "test message"
    assert str(error) == "test message"


def test_auth_error_required_scopes_stored_as_tuple() -> None:
    """AuthError stores required_scopes as a tuple."""
    error = AuthError(
        code="insufficient_scope",
        message="Insufficient scope",
        status_code=403,
        required_scopes=["read:users", "write:users"],
    )
    assert error.required_scopes == ("read:users", "write:users")
    assert isinstance(error.required_scopes, tuple)


def test_auth_error_empty_required_scopes_default() -> None:
    """AuthError defaults required_scopes to empty tuple."""
    error = AuthError(code="invalid_token", message="Bad token", status_code=401)
    assert error.required_scopes == ()


def test_auth_error_required_permissions_stored_as_tuple() -> None:
    """AuthError stores required_permissions as a tuple."""
    error = AuthError(
        code="insufficient_permissions",
        message="Insufficient permissions",
        status_code=403,
        required_permissions=["admin", "write:users"],
    )
    assert error.required_permissions == ("admin", "write:users")
    assert isinstance(error.required_permissions, tuple)


def test_auth_error_empty_required_permissions_default() -> None:
    """AuthError defaults required_permissions to empty tuple."""
    error = AuthError(code="invalid_token", message="Bad token", status_code=401)
    assert error.required_permissions == ()


# ============================================================================
# WWW-Authenticate Header Generation
# ============================================================================


def test_www_authenticate_header_401_format() -> None:
    """401 errors produce 'invalid_token' in WWW-Authenticate header."""
    error = AuthError(code="token_expired", message="Token is expired", status_code=401)
    header = error.www_authenticate_header()

    assert header.startswith("Bearer ")
    assert 'error="invalid_token"' in header
    assert 'error_description="Token is expired"' in header
    assert "realm=" not in header


def test_www_authenticate_header_with_realm() -> None:
    """Realm parameter appears first in WWW-Authenticate header."""
    error = AuthError(code="invalid_token", message="Bad token", status_code=401)
    header = error.www_authenticate_header(realm="my-api")

    # realm should come first after "Bearer "
    assert header.startswith('Bearer realm="my-api"')
    assert 'error="invalid_token"' in header
    assert 'error_description="Bad token"' in header


def test_www_authenticate_header_403_produces_insufficient_scope() -> None:
    """403 errors produce 'insufficient_scope' in WWW-Authenticate header."""
    error = AuthError(
        code="insufficient_permissions",  # internal code
        message="Missing permissions",
        status_code=403,
    )
    header = error.www_authenticate_header()

    # RFC 6750 maps 403 to insufficient_scope regardless of internal code
    assert 'error="insufficient_scope"' in header
    assert 'error_description="Missing permissions"' in header


def test_www_authenticate_header_403_includes_scope_parameter() -> None:
    """403 errors with required_scopes include scope parameter."""
    error = AuthError(
        code="insufficient_scope",
        message="Insufficient scope",
        status_code=403,
        required_scopes=["read:users", "write:users"],
    )
    header = error.www_authenticate_header()

    assert 'error="insufficient_scope"' in header
    assert 'scope="read:users write:users"' in header


def test_www_authenticate_header_401_includes_scope_when_set() -> None:
    """401 errors include scope parameter when required_scopes is set."""
    error = AuthError(
        code="invalid_token",
        message="Bad token",
        status_code=401,
        required_scopes=["read:users"],
    )
    header = error.www_authenticate_header()

    assert 'error="invalid_token"' in header
    assert 'scope="read:users"' in header


def test_www_authenticate_header_with_realm_and_scopes() -> None:
    """Full header with realm and scopes is properly formatted."""
    error = AuthError(
        code="insufficient_scope",
        message="Insufficient scope",
        status_code=403,
        required_scopes=["admin"],
    )
    header = error.www_authenticate_header(realm="api")

    assert header.startswith('Bearer realm="api"')
    assert 'error="insufficient_scope"' in header
    assert 'error_description="Insufficient scope"' in header
    assert 'scope="admin"' in header


def test_www_authenticate_header_no_scopes_no_scope_param() -> None:
    """Header without required_scopes does not include scope parameter."""
    error = AuthError(
        code="insufficient_scope",
        message="Insufficient scope",
        status_code=403,
        required_scopes=[],  # Empty
    )
    header = error.www_authenticate_header()

    assert "scope=" not in header


def test_www_authenticate_header_403_includes_permissions_parameter() -> None:
    """403 errors with required_permissions include permissions parameter."""
    error = AuthError(
        code="insufficient_permissions",
        message="Insufficient permissions",
        status_code=403,
        required_permissions=["admin", "write:users"],
    )
    header = error.www_authenticate_header()

    assert 'error="insufficient_scope"' in header
    assert 'permissions="admin write:users"' in header


def test_www_authenticate_header_no_permissions_no_permissions_param() -> None:
    """Header without required_permissions does not include permissions parameter."""
    error = AuthError(
        code="insufficient_permissions",
        message="Insufficient permissions",
        status_code=403,
        required_permissions=[],  # Empty
    )
    header = error.www_authenticate_header()

    assert "permissions=" not in header


# ============================================================================
# RFC 6750 Value Escaping
# ============================================================================


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("simple", '"simple"'),
        ("invalid_token", '"invalid_token"'),
        ('has "quotes"', '"has \\"quotes\\""'),
        ("has\\backslash", '"has\\\\backslash"'),
        ("has\nnewline", '"hasnewline"'),
        ("has\rcarriage", '"hascarriage"'),
        ("has\r\nboth", '"hasboth"'),
        ('combo"\r\n\\all', '"combo\\"\\\\all"'),
        ("", '""'),
    ],
)
def test_quote_rfc6750_value_escaping(raw: str, expected: str) -> None:
    """RFC 6750 value quoting escapes special characters correctly."""
    assert _quote_rfc6750_value(raw) == expected


def test_www_authenticate_header_escapes_special_chars_in_message() -> None:
    """Special characters in error message are properly escaped."""
    error = AuthError(
        code="invalid_token",
        message='Token contains "special" chars',
        status_code=401,
    )
    header = error.www_authenticate_header()

    # Double quotes in message should be escaped
    assert 'error_description="Token contains \\"special\\" chars"' in header


def test_www_authenticate_header_escapes_realm() -> None:
    """Special characters in realm are properly escaped."""
    error = AuthError(code="invalid_token", message="Bad token", status_code=401)
    header = error.www_authenticate_header(realm='my "realm"')

    assert 'realm="my \\"realm\\""' in header


def test_www_authenticate_header_strips_newlines_from_message() -> None:
    """Newlines in error message are stripped (invalid in HTTP headers)."""
    error = AuthError(
        code="invalid_token",
        message="Line1\nLine2\rLine3",
        status_code=401,
    )
    header = error.www_authenticate_header()

    # Newlines and carriage returns should be stripped
    assert "\n" not in header
    assert "\r" not in header
    assert "Line1Line2Line3" in header
