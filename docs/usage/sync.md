# Usage: Sync

## When to Use the Sync Verifier

Use `JWTVerifier` when your service code is synchronous or when you prefer a sync verification path managed by your framework.

## Basic Pattern

```python
from oidc_jwt_verifier import AuthConfig, AuthError, JWTVerifier

config = AuthConfig(
    issuer="https://issuer.example/",
    audience="https://api.example",
    jwks_url="https://issuer.example/.well-known/jwks.json",
    allowed_algs=("RS256",),
)

verifier = JWTVerifier(config)

try:
    claims = verifier.verify_access_token(token)
except AuthError as error:
    status = error.status_code
    www_authenticate = error.www_authenticate_header(realm="api")
```

## Reuse Strategy

- Create one verifier instance per process (or per app instance).
- Reuse it across requests.
- Avoid creating a new verifier for each request.

## JWKS Warmup and Readiness

`JWTVerifier` exposes verifier-level lifecycle/readiness helpers for
`get_signing_keys()` and `healthcheck()`.
Use these methods during startup or controlled readiness checks, not on every
request.

```python
from oidc_jwt_verifier import AuthConfig, JWTVerifier

config = AuthConfig(
    issuer="https://issuer.example/",
    audience="https://api.example",
    jwks_url="https://issuer.example/.well-known/jwks.json",
)

verifier = JWTVerifier(config)

if not verifier.healthcheck(refresh=True):
    raise RuntimeError("JWKS endpoint is not ready")

signing_keys = verifier.get_signing_keys()
```

If you need direct client-level access, import `JWKSClient` from
`oidc_jwt_verifier.jwks` and use the parallel methods
`get_signing_keys(refresh=…)`, `get_signing_key(kid, refresh=…)`, and
`healthcheck(refresh=…)`.

## Multi-Audience, Scope, and Permission Enforcement

`AuthConfig` supports:

- Multiple accepted audiences.
- Required scopes.
- Required permissions.

```python
config = AuthConfig(
    issuer="https://issuer.example/",
    audience=("https://api-a.example", "https://api-b.example"),
    jwks_url="https://issuer.example/.well-known/jwks.json",
    required_scopes=("read:users",),
    required_permissions=("users:read",),
)
```

Missing scope/permission checks produce `AuthError` with `status_code=403`.

## Sync in ASGI Frameworks

For FastAPI and Starlette applications, prefer the async verifier.  
If you need sync verification in FastAPI, use `create_sync_bearer_dependency()` from [FastAPI integration](../integrations/fastapi.md), which can offload to threadpool.
