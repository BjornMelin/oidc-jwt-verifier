# Migration Guide

This release adds async and framework integration features without breaking the existing sync API.

## Compatibility Summary

| Existing usage | Required change |
| --- | --- |
| `AuthConfig`, `AuthError`, `JWTVerifier` | None |
| Sync-only installation | None |
| Async usage | Install `oidc-jwt-verifier[async]` |
| FastAPI helpers | Install `oidc-jwt-verifier[fastapi]` |
| Starlette helpers | Install `oidc-jwt-verifier[starlette]` |

## If You Already Use the Sync Verifier

No migration is required.

```python
from oidc_jwt_verifier import AuthConfig, JWTVerifier

verifier = JWTVerifier(AuthConfig(...))
claims = verifier.verify_access_token(token)
```

## Move to Native Async Verification

1. Install async extra: `pip install "oidc-jwt-verifier[async]"`
2. Replace `JWTVerifier` with `AsyncJWTVerifier`
3. Use `await verifier.verify_access_token(...)`
4. Close verifier-owned resources with `await verifier.aclose()` or `async with`

```python
from oidc_jwt_verifier.async_verifier import AsyncJWTVerifier

async with AsyncJWTVerifier(config) as verifier:
    claims = await verifier.verify_access_token(token)
```

## FastAPI Migration

Use `create_async_bearer_dependency()` for async endpoints.

```python
from oidc_jwt_verifier.integrations.fastapi import create_async_bearer_dependency

auth = create_async_bearer_dependency(verifier, realm="api")
```

If you must keep `JWTVerifier`, use `create_sync_bearer_dependency()` with threadpool offload enabled.

## Starlette Migration

Add `BearerAuthMiddleware` and read claims from request state.

```python
app.add_middleware(BearerAuthMiddleware, verifier=verifier, realm="api")
```

## Rollout Checklist

- Install the correct extra for your runtime.
- Reuse long-lived verifier instances.
- Add shutdown cleanup for async verifier ownership paths.
- Confirm `WWW-Authenticate` headers in integration tests.
- Validate required scopes/permissions behavior in your API routes.
