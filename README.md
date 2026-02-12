# oidc-jwt-verifier

[![Release](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FBjornMelin%2Foidc-jwt-verifier%2Fmain%2F.release-please-manifest.json&query=%24%5B%22.%22%5D&label=release&style=flat-square&cacheSeconds=60)](https://github.com/BjornMelin/oidc-jwt-verifier/releases)
[![PyPI](https://img.shields.io/pypi/v/oidc-jwt-verifier?label=pypi&style=flat-square)](https://pypi.org/project/oidc-jwt-verifier/)
[![Python Versions](https://img.shields.io/pypi/pyversions/oidc-jwt-verifier?style=flat-square)](https://pypi.org/project/oidc-jwt-verifier/)
[![Tests](https://img.shields.io/github/actions/workflow/status/BjornMelin/oidc-jwt-verifier/ci.yml?branch=main&label=tests&style=flat-square)](https://github.com/BjornMelin/oidc-jwt-verifier/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/codecov/c/github/BjornMelin/oidc-jwt-verifier?branch=main&style=flat-square)](https://codecov.io/gh/BjornMelin/oidc-jwt-verifier)
[![Docs](https://img.shields.io/badge/docs-live-blue?style=flat-square)](https://oidc-jwt-verifier.bjornmelin.io/)
[![License](https://img.shields.io/github/license/BjornMelin/oidc-jwt-verifier?style=flat-square)](https://github.com/BjornMelin/oidc-jwt-verifier/blob/main/LICENSE)

`oidc-jwt-verifier` is a small, framework-agnostic JWT verification core for OIDC/JWKS issuers.

It provides:

- A hardened sync verifier (`JWTVerifier`)
- A native async verifier (`AsyncJWTVerifier`)
- First-party FastAPI and Starlette integration helpers

## Install

```bash
pip install oidc-jwt-verifier
```

For async/FastAPI/Starlette support:

```bash
pip install "oidc-jwt-verifier[async]"
pip install "oidc-jwt-verifier[fastapi]"
pip install "oidc-jwt-verifier[starlette]"
```

For development:

```bash
uv pip install -e ".[dev]"
```

## Quickstart

```python
from oidc_jwt_verifier import AuthConfig, JWTVerifier

config = AuthConfig(
    issuer="https://example-issuer/",
    audience="https://example-api",
    jwks_url="https://example-issuer/.well-known/jwks.json",
    allowed_algs=("RS256",),
    required_scopes=("read:users",),
)

verifier = JWTVerifier(config)
claims = verifier.verify_access_token(token)
```

## Async quickstart

```python
from oidc_jwt_verifier import AuthConfig
from oidc_jwt_verifier.async_verifier import AsyncJWTVerifier

config = AuthConfig(
    issuer="https://example-issuer/",
    audience="https://example-api",
    jwks_url="https://example-issuer/.well-known/jwks.json",
    allowed_algs=("RS256",),
)

async def verify(token: str) -> dict[str, object]:
    async with AsyncJWTVerifier(config) as verifier:
        return await verifier.verify_access_token(token)
```

## FastAPI integration

```python
from fastapi import Depends, FastAPI
from oidc_jwt_verifier import AuthConfig
from oidc_jwt_verifier.async_verifier import AsyncJWTVerifier
from oidc_jwt_verifier.integrations.fastapi import create_async_bearer_dependency

app = FastAPI()
verifier = AsyncJWTVerifier(
    AuthConfig(
        issuer="https://example-issuer/",
        audience="https://example-api",
        jwks_url="https://example-issuer/.well-known/jwks.json",
    )
)
auth = create_async_bearer_dependency(verifier, realm="api")

@app.get("/protected")
async def protected(claims: dict = Depends(auth)):
    return {"sub": claims.get("sub")}
```

## Starlette integration

```python
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from oidc_jwt_verifier.integrations.starlette import BearerAuthMiddleware

async def protected(request: Request) -> JSONResponse:
    claims = request.state.auth_claims
    return JSONResponse({"sub": claims.get("sub")})

app = Starlette(routes=[Route("/protected", protected)])
app.add_middleware(BearerAuthMiddleware, verifier=verifier, realm="api")
```

## Secure-by-default behavior

The verifier:

- Verifies signature, `iss`, `aud`, `exp`, and `nbf` (when present).
- Uses an explicit algorithm allowlist and rejects `alg=none`.
- Enforces minimum cryptographic key lengths by default (configurable via `enforce_minimum_key_length`).
- Fails closed on malformed tokens, JWKS fetch errors, timeouts, missing keys, and missing `kid`.
- Never derives a JWKS URL from token headers, and rejects tokens that include `jku`, `x5u`, or `crit`.
- Supports Auth0-style multi-audience tokens (`aud` as an array) and enforces required scopes and
  permissions.

Auth0 guidance for API token validation calls out validating the JWT and then checking `aud` and
scopes in the `scope` claim. See the Auth0 docs for details.

## Error handling

The public exception type is `AuthError`.

`AuthError` carries:

- `code`: stable, machine-readable reason
- `status_code`: `401` (authentication) or `403` (authorization)
- `www_authenticate_header()`: an RFC 6750 compatible `WWW-Authenticate` value for Bearer auth

```python
from oidc_jwt_verifier import AuthError

try:
    claims = verifier.verify_access_token(token)
except AuthError as err:
    status = err.status_code
    www_authenticate = err.www_authenticate_header()
```

## Why this library

JWT verification for APIs is easy to get mostly right while still missing important security and
interoperability details. This library is a small, framework-agnostic core that centralizes
conservative verification policy (claims, algorithms, header handling) and authorization checks
(scopes/permissions) so you can reuse it across projects.

For comparisons against common alternatives (PyJWT directly, discovery-driven verifiers, framework
integrations), see `docs/alternatives.md`.

## Documentation

Primary docs are built with MkDocs in `docs/`.

- Getting started: `docs/getting-started.md`
- Sync usage: `docs/usage/sync.md`
- Async usage: `docs/usage/async.md`
- FastAPI integration: `docs/integrations/fastapi.md`
- Starlette integration: `docs/integrations/starlette.md`
- Configuration and security: `docs/configuration.md`, `docs/security.md`
- API reference: `docs/reference.md`

## Contributing

Use [Conventional Commits](https://www.conventionalcommits.org/).  
Release-specific commit guidance for maintainers is documented in `AGENTS.md`.

## References

- Auth0: Validate Access Tokens: `https://auth0.com/docs/secure/tokens/access-tokens/validate-access-tokens`
- Auth0: Validate JSON Web Tokens: `https://auth0.com/docs/secure/tokens/json-web-tokens/validate-json-web-tokens`
- RFC 8725: JSON Web Token Best Current Practices: `https://datatracker.ietf.org/doc/html/rfc8725`
- RFC 9700: Best Current Practice for OAuth 2.0 Security: `https://www.rfc-editor.org/info/rfc9700`
- PyJWT docs and examples: `https://pyjwt.readthedocs.io/en/stable/usage.html`
