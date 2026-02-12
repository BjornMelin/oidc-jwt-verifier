# FastAPI Integration

Install:

```bash
pip install "oidc-jwt-verifier[fastapi]"
```

## Async Dependency (Recommended)

Use `create_async_bearer_dependency()` with `AsyncJWTVerifier` for native async verification.

```python
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from oidc_jwt_verifier import AuthConfig
from oidc_jwt_verifier.async_verifier import AsyncJWTVerifier
from oidc_jwt_verifier.integrations.fastapi import create_async_bearer_dependency

verifier = AsyncJWTVerifier(
    AuthConfig(
        issuer="https://issuer.example/",
        audience="https://api.example",
        jwks_url="https://issuer.example/.well-known/jwks.json",
    )
)
auth = create_async_bearer_dependency(verifier, realm="api")

@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    await verifier.aclose()

app = FastAPI(lifespan=lifespan)

@app.get("/protected")
async def protected(claims: dict = Depends(auth)):
    return {"sub": claims.get("sub")}
```

## Sync Dependency

If your app still uses `JWTVerifier`, use `create_sync_bearer_dependency()`.

```python
from fastapi import Depends, FastAPI

from oidc_jwt_verifier import AuthConfig, JWTVerifier
from oidc_jwt_verifier.integrations.fastapi import create_sync_bearer_dependency

app = FastAPI()
verifier = JWTVerifier(
    AuthConfig(
        issuer="https://issuer.example/",
        audience="https://api.example",
        jwks_url="https://issuer.example/.well-known/jwks.json",
    )
)
auth = create_sync_bearer_dependency(
    verifier,
    realm="api",
    offload_to_threadpool=True,
)

@app.get("/protected")
async def protected(claims: dict = Depends(auth)):
    return {"sub": claims.get("sub")}
```

## Error Behavior

Helpers convert `AuthError` to `fastapi.HTTPException` and preserve RFC 6750 response headers.

- Status code from `AuthError.status_code`
- Detail from `AuthError.message`
- `WWW-Authenticate` header from `AuthError.www_authenticate_header()`

## Notes

- Reuse verifier instances across requests.
- Keep `HTTPBearer(auto_error=False)` behavior from helper defaults for uniform error mapping.
- Close `AsyncJWTVerifier` at shutdown when it owns its HTTP resources.
