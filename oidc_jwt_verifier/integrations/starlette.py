"""Starlette integration helpers.

This module offers middleware and helper functions to apply verifier logic in
Starlette applications while preserving RFC 6750 response semantics.
"""

from __future__ import annotations

from typing import Any

from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from ..async_verifier import AsyncJWTVerifier
from ..errors import AuthError
from ..verifier import JWTVerifier


def auth_error_to_response(
    error: AuthError,
    *,
    realm: str | None = None,
) -> JSONResponse:
    """Convert ``AuthError`` into a Starlette JSON response.

    Args:
        error: Auth error to convert.
        realm: Optional realm for ``WWW-Authenticate`` header.

    Returns:
        JSON response with correct status and RFC 6750 header.
    """
    return JSONResponse(
        {"detail": error.message, "code": error.code},
        status_code=error.status_code,
        headers={"WWW-Authenticate": error.www_authenticate_header(realm=realm)},
    )


def extract_bearer_token(authorization_header: str | None) -> str:
    """Extract a bearer token from ``Authorization`` header value.

    Args:
        authorization_header: Raw header value.

    Returns:
        Bearer token string, or empty string when missing/invalid.
    """
    if authorization_header is None:
        return ""
    parts = authorization_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


async def verify_request_bearer_token(
    request: Request,
    *,
    verifier: JWTVerifier | AsyncJWTVerifier,
) -> dict[str, Any]:
    """Verify bearer token from a Starlette request.

    Args:
        request: Incoming request.
        verifier: Sync or async verifier instance.

    Returns:
        Decoded JWT claims.

    Raises:
        AuthError: On authentication/authorization failure.
    """
    token = extract_bearer_token(request.headers.get("Authorization"))
    if isinstance(verifier, JWTVerifier):
        return await run_in_threadpool(verifier.verify_access_token, token)
    return await verifier.verify_access_token(token)


class BearerAuthMiddleware:
    """Starlette middleware that verifies bearer access tokens.

    Valid claims are stored in ``request.state`` under ``claims_state_key``.

    Args:
        app: Downstream ASGI app.
        verifier: Sync or async verifier.
        realm: Optional realm for RFC 6750 header generation.
        exempt_paths: Paths to skip authentication for.
        claims_state_key: Key used in ``request.state`` for decoded claims.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        verifier: JWTVerifier | AsyncJWTVerifier,
        realm: str | None = None,
        exempt_paths: set[str] | None = None,
        claims_state_key: str = "auth_claims",
    ) -> None:
        """Initialize middleware configuration."""
        self._app = app
        self._verifier = verifier
        self._realm = realm
        self._exempt_paths = exempt_paths or set()
        self._claims_state_key = claims_state_key

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Process request authentication.

        Args:
            scope: ASGI scope.
            receive: ASGI receive callable.
            send: ASGI send callable.
        """
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return

        if scope.get("path") in self._exempt_paths:
            await self._app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        try:
            claims = await verify_request_bearer_token(request, verifier=self._verifier)
        except AuthError as exc:
            response = auth_error_to_response(exc, realm=self._realm)
            await response(scope, receive, send)
            return

        state = scope.setdefault("state", {})
        if isinstance(state, dict):
            state[self._claims_state_key] = claims

        await self._app(scope, receive, send)


__all__ = [
    "BearerAuthMiddleware",
    "auth_error_to_response",
    "extract_bearer_token",
    "verify_request_bearer_token",
]
