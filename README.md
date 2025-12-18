# oidc-jwt-verifier

[![PyPI version](https://img.shields.io/pypi/v/oidc-jwt-verifier)](https://pypi.org/project/oidc-jwt-verifier/)
[![Python versions](https://img.shields.io/pypi/pyversions/oidc-jwt-verifier)](https://pypi.org/project/oidc-jwt-verifier/)
[![Tests](https://github.com/BjornMelin/oidc-jwt-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/BjornMelin/oidc-jwt-verifier/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/BjornMelin/oidc-jwt-verifier/branch/main/graph/badge.svg)](https://codecov.io/gh/BjornMelin/oidc-jwt-verifier)
[![Documentation](https://img.shields.io/badge/docs-live-blue)](https://oidc-jwt-verifier.bjornmelin.io/)
[![License](https://img.shields.io/github/license/BjornMelin/oidc-jwt-verifier)](https://github.com/BjornMelin/oidc-jwt-verifier/blob/main/LICENSE)

`oidc-jwt-verifier` is a small, framework-agnostic JWT verification core for OIDC/JWKS issuers.

It is designed to be shared by higher-level adapters (Dash, Bottle, Lambda, FastAPI) while keeping
security decisions centralized and consistent.

## Install

```bash
pip install oidc-jwt-verifier
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

## Secure-by-default behavior

The verifier:

- Verifies signature, `iss`, `aud`, `exp`, and `nbf` (when present).
- Uses an explicit algorithm allowlist and rejects `alg=none`.
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

## Contributing

We use [Conventional Commits](https://www.conventionalcommits.org/) to automate releases via release-please.

**Commit prefixes:**
- `feat:` - New feature (bumps PATCH pre-v1.0)
- `feat!:` - Breaking change (bumps MINOR pre-v1.0)
- `fix:` - Bug fix (bumps PATCH)
- `docs:` - Documentation only
- `chore:` - Maintenance tasks
- `refactor:` - Code refactoring
- `test:` - Test changes
- `perf:` - Performance improvements

PRs without conventional commit prefixes will not trigger releases.

## References

- Auth0: Validate Access Tokens: `https://auth0.com/docs/secure/tokens/access-tokens/validate-access-tokens`
- Auth0: Validate JSON Web Tokens: `https://auth0.com/docs/secure/tokens/json-web-tokens/validate-json-web-tokens`
- RFC 8725: JSON Web Token Best Current Practices: `https://datatracker.ietf.org/doc/html/rfc8725`
- RFC 9700: Best Current Practice for OAuth 2.0 Security: `https://www.rfc-editor.org/info/rfc9700`
- PyJWT docs and examples: `https://github.com/jpadilla/pyjwt/blob/master/docs/usage.rst`
