# Migration Guide

This release adds async and framework integration features without breaking the existing sync API.

## Compatibility Summary

| Existing usage | Required change |
| --- | --- |
| `AuthConfig`, `AuthError`, `JWTVerifier` | None |
| Private JWKS reach-ins or custom readiness wrappers | Replace with public lifecycle/readiness APIs |
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

## Adopt the Public JWKS Lifecycle APIs

This release is additive. Existing token verification behavior is unchanged,
but sync and async clients now expose parallel public lifecycle/readiness APIs:

- `get_signing_keys(refresh=False)`
- `healthcheck(refresh=False)`
- direct client key lookup by `kid`

Prefer these public APIs for startup validation, cache priming, and readiness
checks instead of private JWKS reach-ins or custom readiness wrappers.

```python
from oidc_jwt_verifier import JWTVerifier

verifier = JWTVerifier(config)
if not verifier.healthcheck(refresh=True):
    raise RuntimeError("JWKS endpoint is not ready")
```

If you need direct client access:

```python
from oidc_jwt_verifier.jwks import JWKSClient
from oidc_jwt_verifier.async_jwks import AsyncJWKSClient
```

The sync and async lifecycle/readiness APIs are intended to remain parallel
public surfaces.

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
- Replace private JWKS reach-ins and custom readiness wrappers with
  `healthcheck()` and `get_signing_keys()`.
- Use readiness checks at startup or controlled probes, not on every request.
- Confirm `WWW-Authenticate` headers in integration tests.
- Validate required scopes/permissions behavior in your API routes.
