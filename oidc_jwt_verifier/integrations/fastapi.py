"""FastAPI integration helpers.

This module provides dependency factories that translate ``AuthError`` into
``fastapi.HTTPException`` while preserving RFC 6750 ``WWW-Authenticate``
headers.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from ..async_verifier import AsyncJWTVerifier
from ..errors import AuthError
from ..verifier import JWTVerifier


def auth_error_to_http_exception(
    error: AuthError,
    *,
    realm: str | None = None,
) -> HTTPException:
    """Translate ``AuthError`` into ``fastapi.HTTPException``.

    Args:
        error: Auth error to convert.
        realm: Optional RFC 6750 realm parameter.

    Returns:
        A FastAPI HTTP exception with status, detail and
        ``WWW-Authenticate`` header.
    """
    return HTTPException(
        status_code=error.status_code,
        detail=error.message,
        headers={"WWW-Authenticate": error.www_authenticate_header(realm=realm)},
    )


def create_async_bearer_dependency(
    verifier: AsyncJWTVerifier,
    *,
    realm: str | None = None,
    auto_error: bool = False,
) -> Callable[[HTTPAuthorizationCredentials | None], Awaitable[dict[str, Any]]]:
    """Create a FastAPI dependency for ``AsyncJWTVerifier``.

    Args:
        verifier: Async verifier instance.
        realm: Optional RFC 6750 realm.
        auto_error: Passed to ``HTTPBearer``. Keep this ``False`` to let the
            library produce uniform ``AuthError`` mapping.

    Returns:
        A dependency callable returning decoded claims on success.
    """
    security = HTTPBearer(auto_error=auto_error)

    async def dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(security),  # noqa: B008
    ) -> dict[str, Any]:
        """Resolve and verify bearer token for one request.

        Args:
            credentials: FastAPI bearer credentials.

        Returns:
            Decoded token claims.

        Raises:
            HTTPException: When authentication/authorization fails.
        """
        token = credentials.credentials if credentials is not None else ""
        try:
            return await verifier.verify_access_token(token)
        except AuthError as exc:
            raise auth_error_to_http_exception(exc, realm=realm) from exc

    return dependency


def create_sync_bearer_dependency(
    verifier: JWTVerifier,
    *,
    realm: str | None = None,
    offload_to_threadpool: bool = True,
    auto_error: bool = False,
) -> Callable[[HTTPAuthorizationCredentials | None], Awaitable[dict[str, Any]]]:
    """Create a FastAPI dependency for sync ``JWTVerifier``.

    Args:
        verifier: Sync verifier instance.
        realm: Optional RFC 6750 realm.
        offload_to_threadpool: Whether to run sync verification in
            ``run_in_threadpool``.
        auto_error: Passed to ``HTTPBearer``.

    Returns:
        A dependency callable returning decoded claims on success.
    """
    security = HTTPBearer(auto_error=auto_error)

    async def dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(security),  # noqa: B008
    ) -> dict[str, Any]:
        """Resolve and verify bearer token for one request.

        Args:
            credentials: FastAPI bearer credentials.

        Returns:
            Decoded token claims.

        Raises:
            HTTPException: When authentication/authorization fails.
        """
        token = credentials.credentials if credentials is not None else ""
        try:
            if offload_to_threadpool:
                claims: dict[str, Any] = await run_in_threadpool(
                    verifier.verify_access_token, token
                )
                return claims
            return verifier.verify_access_token(token)
        except AuthError as exc:
            raise auth_error_to_http_exception(exc, realm=realm) from exc

    return dependency


__all__ = [
    "auth_error_to_http_exception",
    "create_async_bearer_dependency",
    "create_sync_bearer_dependency",
]
