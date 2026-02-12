# Usage: Async

## When to Use the Async Verifier

Use `AsyncJWTVerifier` in ASGI applications and any async code path where blocking network I/O should be avoided.

## Basic Pattern

```python
from oidc_jwt_verifier import AuthConfig, AuthError
from oidc_jwt_verifier.async_verifier import AsyncJWTVerifier

config = AuthConfig(
    issuer="https://issuer.example/",
    audience="https://api.example",
    jwks_url="https://issuer.example/.well-known/jwks.json",
)

async with AsyncJWTVerifier(config) as verifier:
    try:
        claims = await verifier.verify_access_token(token)
    except AuthError as error:
        status = error.status_code
```

## Lifecycle and Resource Ownership

`AsyncJWTVerifier` can own its network resources or use externally-managed resources.

### Verifier-owned resources

- Construct with `AsyncJWTVerifier(config)`.
- Call `await verifier.aclose()` when shutting down.
- Using `async with` is the safest option.

### Externally-managed HTTP client

```python
import httpx
from oidc_jwt_verifier import AuthConfig
from oidc_jwt_verifier.async_verifier import AsyncJWTVerifier

http_client = httpx.AsyncClient(timeout=3.0)
verifier = AsyncJWTVerifier(
    AuthConfig(
        issuer="https://issuer.example/",
        audience="https://api.example",
        jwks_url="https://issuer.example/.well-known/jwks.json",
    ),
    http_client=http_client,
)
```

In this mode, `verifier.aclose()` does not close your injected `http_client`.

## Async JWKS Client (Advanced)

Most applications only need `AsyncJWTVerifier`.  
If you need direct key resolution control, use `AsyncJWKSClient`:

```python
from oidc_jwt_verifier import AuthConfig
from oidc_jwt_verifier.async_jwks import AsyncJWKSClient

client = AsyncJWKSClient.from_config(
    AuthConfig(
        issuer="https://issuer.example/",
        audience="https://api.example",
        jwks_url="https://issuer.example/.well-known/jwks.json",
    )
)
```
