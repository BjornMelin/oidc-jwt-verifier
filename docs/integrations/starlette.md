# Starlette Integration

Install:

```bash
pip install "oidc-jwt-verifier[starlette]"
```

## Middleware Pattern (Recommended)

`BearerAuthMiddleware` verifies bearer tokens for each HTTP request.
On success, decoded claims are stored in `request.state.auth_claims` by default.

```python
from contextlib import asynccontextmanager

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from oidc_jwt_verifier import AuthConfig
from oidc_jwt_verifier.async_verifier import AsyncJWTVerifier
from oidc_jwt_verifier.integrations.starlette import BearerAuthMiddleware

verifier = AsyncJWTVerifier(
    AuthConfig(
        issuer="https://issuer.example/",
        audience="https://api.example",
        jwks_url="https://issuer.example/.well-known/jwks.json",
    )
)

async def protected(request: Request) -> JSONResponse:
    claims = request.state.auth_claims
    return JSONResponse({"sub": claims.get("sub")})

@asynccontextmanager
async def lifespan(_: Starlette):
    yield
    await verifier.aclose()

app = Starlette(routes=[Route("/protected", protected)], lifespan=lifespan)
app.add_middleware(
    BearerAuthMiddleware,
    verifier=verifier,
    realm="api",
    exempt_paths={"/healthz"},
)
```

## Manual Verification in Endpoints

If you do not want middleware, use `verify_request_bearer_token()` directly.

```python
from starlette.requests import Request
from starlette.responses import JSONResponse

from oidc_jwt_verifier import AuthError
from oidc_jwt_verifier.integrations.starlette import (
    auth_error_to_response,
    verify_request_bearer_token,
)

async def protected(request: Request) -> JSONResponse:
    try:
        claims = await verify_request_bearer_token(request, verifier=verifier)
    except AuthError as exc:
        return auth_error_to_response(exc, realm="api")

    return JSONResponse({"sub": claims.get("sub")})
```

## Sync Verifier Support

`BearerAuthMiddleware` and `verify_request_bearer_token()` accept either:

- `AsyncJWTVerifier` (native async verification)
- `JWTVerifier` (automatically offloaded with `starlette.concurrency.run_in_threadpool`)

## Error Behavior

When verification fails, helper responses include:

- JSON body with `detail` and `code`
- HTTP status from `AuthError.status_code`
- RFC 6750 `WWW-Authenticate` header from `AuthError.www_authenticate_header()`

## Middleware Options

`BearerAuthMiddleware` options:

- `realm`: optional RFC 6750 realm
- `exempt_paths`: exact path matches that skip authentication
- `claims_state_key`: request state key for decoded claims (default: `"auth_claims"`)
