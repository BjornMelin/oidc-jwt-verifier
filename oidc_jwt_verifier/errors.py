"""Authentication and authorization error types with RFC 6750 support.

This module defines ``AuthError``, the sole exception type raised by the
JWT verification library. Each error carries a stable code, an HTTP status
code (401 or 403), and a method to generate RFC 6750 WWW-Authenticate
header values for Bearer token authentication challenges.
"""

from collections.abc import Iterable


def _quote_rfc6750_value(value: str) -> str:
    r"""Quote a string for use as an RFC 6750 parameter value.

    RFC 6750 Bearer token authentication uses quoted-string syntax for
    parameter values in the WWW-Authenticate header. This function escapes
    backslashes and double quotes, removes carriage returns and newlines
    (which are invalid in HTTP headers), and wraps the result in double
    quotes.

    Args:
        value: The raw string to be quoted. May contain special characters
            that require escaping.

    Returns:
        A double-quoted string suitable for use as an RFC 6750 parameter
        value. Backslashes and double quotes within the value are escaped.

    Examples:
        >>> _quote_rfc6750_value("invalid_token")
        '"invalid_token"'
        >>> _quote_rfc6750_value('Token has "special" chars')
        '"Token has \\\\"special\\\\" chars"'
        >>> _quote_rfc6750_value("Line1\\nLine2")
        '"Line1Line2"'
    """
    safe = value.replace("\r", "").replace("\n", "")
    safe = safe.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{safe}"'


class AuthError(Exception):
    """Exception raised on authentication or authorization failure.

    This exception provides structured error information including a stable
    error code for programmatic handling, an HTTP status code (401 for
    authentication failures, 403 for authorization failures), and a method
    to generate RFC 6750-compliant WWW-Authenticate header values.

    The exception message is accessible via the standard ``str()`` conversion
    or the ``message`` attribute.

    Attributes:
        code: A stable string identifier for the error type. Common values
            include ``"invalid_token"``, ``"token_expired"``,
            ``"insufficient_scope"``, and ``"missing_token"``. Suitable for
            programmatic error handling and logging.
        message: A human-readable description of the error. This is also
            set as the exception message.
        status_code: The HTTP status code to return. Must be 401
            (Unauthorized) for authentication errors or 403 (Forbidden)
            for authorization errors.
        required_scopes: A tuple of scope strings that were required but
            missing from the token. Populated for ``insufficient_scope``
            errors; empty for other error types.
        required_permissions: A tuple of permission strings that were required
            but missing from the token. Populated for ``insufficient_permissions``
            errors; empty for other error types.

    Raises:
        ValueError: If ``status_code`` is not 401 or 403.

    Examples:
        Creating an authentication error (401):

        >>> error = AuthError(
        ...     code="token_expired",
        ...     message="Token is expired",
        ...     status_code=401,
        ... )
        >>> str(error)
        'Token is expired'
        >>> error.code
        'token_expired'
        >>> error.status_code
        401

        Creating an authorization error (403) with scope requirements:

        >>> error = AuthError(
        ...     code="insufficient_scope",
        ...     message="Insufficient scope",
        ...     status_code=403,
        ...     required_scopes=["read:users", "write:users"],
        ... )
        >>> error.required_scopes
        ('read:users', 'write:users')

        Generating a WWW-Authenticate header:

        >>> error = AuthError(
        ...     code="invalid_token",
        ...     message="Malformed token",
        ...     status_code=401,
        ... )
        >>> error.www_authenticate_header(realm="api")
        'Bearer realm="api", error="invalid_token", error_description="Malformed token"'

        Invalid status code raises ValueError:

        >>> AuthError(code="error", message="msg", status_code=500)
        Traceback (most recent call last):
            ...
        ValueError: status_code must be 401 or 403
    """

    __slots__ = ("code", "message", "required_permissions", "required_scopes", "status_code")

    def __init__(
        self,
        *,
        code: str,
        message: str,
        status_code: int,
        required_scopes: Iterable[str] = (),
        required_permissions: Iterable[str] = (),
    ) -> None:
        """Initialize an authentication or authorization error.

        Args:
            code: A stable string identifier for the error type.
            message: A human-readable error description.
            status_code: The HTTP status code (must be 401 or 403).
            required_scopes: Scopes that were required but missing.
                Defaults to an empty tuple.
            required_permissions: Permissions that were required but missing.
                Defaults to an empty tuple.

        Raises:
            ValueError: If ``status_code`` is not 401 or 403.
        """
        if status_code not in (401, 403):
            raise ValueError("status_code must be 401 or 403")
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.required_scopes = tuple(required_scopes)
        self.required_permissions = tuple(required_permissions)

    def www_authenticate_header(self, *, realm: str | None = None) -> str:
        """Generate an RFC 6750-compliant WWW-Authenticate header value.

        Constructs a Bearer authentication challenge suitable for use as the
        value of an HTTP WWW-Authenticate header. The challenge includes
        the error type (mapped to RFC 6750 error codes) and a description.

        RFC 6750 defines two relevant error codes:
        - ``invalid_token``: Used for 401 errors (authentication failures).
        - ``insufficient_scope``: Used for 403 errors (authorization failures).

        If ``required_scopes`` is non-empty, a ``scope`` parameter is
        included listing the missing scopes.

        Args:
            realm: Optional protection space identifier. If provided, it
                appears first in the challenge parameters. Common values
                include the API name or domain.

        Returns:
            A string suitable for use as the WWW-Authenticate header value.
            The format is ``Bearer param1="value1", param2="value2", ...``.

        Examples:
            Basic authentication error:

            >>> error = AuthError(
            ...     code="invalid_token",
            ...     message="Token is expired",
            ...     status_code=401,
            ... )
            >>> error.www_authenticate_header()
            'Bearer error="invalid_token", error_description="Token is expired"'

            With realm:

            >>> error.www_authenticate_header(realm="my-api")
            'Bearer realm="my-api", error="invalid_token", error_description="Token is expired"'

            Authorization error with required scopes:

            >>> error = AuthError(
            ...     code="insufficient_scope",
            ...     message="Insufficient scope",
            ...     status_code=403,
            ...     required_scopes=["read:users"],
            ... )
            >>> header = error.www_authenticate_header()
            >>> "insufficient_scope" in header
            True
            >>> "read:users" in header
            True
        """
        params: list[str] = []
        if realm is not None:
            params.append(f"realm={_quote_rfc6750_value(realm)}")

        if self.status_code == 403:
            rfc6750_error = "insufficient_scope"
        else:
            rfc6750_error = "invalid_token"

        params.append(f"error={_quote_rfc6750_value(rfc6750_error)}")
        params.append(f"error_description={_quote_rfc6750_value(self.message)}")

        if self.required_scopes:
            scope_str = " ".join(self.required_scopes)
            params.append(f"scope={_quote_rfc6750_value(scope_str)}")

        if self.required_permissions:
            permissions_str = " ".join(self.required_permissions)
            params.append(f"permissions={_quote_rfc6750_value(permissions_str)}")

        return "Bearer " + ", ".join(params)
