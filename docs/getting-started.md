# Getting Started

## Requirements

- Python `>=3.10`

## Installation

Install only the sync verifier:

```bash
pip install oidc-jwt-verifier
```

Install async support:

```bash
pip install "oidc-jwt-verifier[async]"
```

Install framework helpers:

```bash
pip install "oidc-jwt-verifier[fastapi]"
pip install "oidc-jwt-verifier[starlette]"
```

## First Sync Verification

```python
from oidc_jwt_verifier import AuthConfig, JWTVerifier

config = AuthConfig(
    issuer="https://issuer.example/",
    audience="https://api.example",
    jwks_url="https://issuer.example/.well-known/jwks.json",
)

verifier = JWTVerifier(config)
claims = verifier.verify_access_token(token)
```

## First Async Verification

```python
from oidc_jwt_verifier import AuthConfig
from oidc_jwt_verifier.async_verifier import AsyncJWTVerifier

config = AuthConfig(
    issuer="https://issuer.example/",
    audience="https://api.example",
    jwks_url="https://issuer.example/.well-known/jwks.json",
)

async def verify(token: str) -> dict[str, object]:
    async with AsyncJWTVerifier(config) as verifier:
        return await verifier.verify_access_token(token)
```

## Next Steps

- Configure claim and cache behavior: [Configuration](configuration.md)
- Handle verifier errors correctly: [Errors](errors.md)
- Integrate with your framework:
  - [FastAPI](integrations/fastapi.md)
  - [Starlette](integrations/starlette.md)
