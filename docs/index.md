# oidc-jwt-verifier

`oidc-jwt-verifier` is a focused JWT access-token verification library for OIDC/JWKS issuers.

It provides:

- A stable sync verifier (`JWTVerifier`) for existing Python services.
- A native async verifier (`AsyncJWTVerifier`) for ASGI applications.
- First-class FastAPI and Starlette integration helpers.
- Strict fail-closed security defaults with RFC 6750-compatible error headers.

## What This Library Verifies

For each token, the verifier enforces:

- Signature validation against keys from a configured JWKS URL.
- Issuer (`iss`) and audience (`aud`) checks.
- Time-based checks (`exp`, `nbf`).
- Algorithm allowlist enforcement, including rejection of `alg=none`.
- Authorization checks for required scopes and permissions.

It also rejects unsafe JWT header parameters (`jku`, `x5u`, `crit`) and never derives key endpoints from token headers.

## Choose Your Path

- New to the package: [Getting Started](getting-started.md)
- Sync services: [Usage: Sync](usage/sync.md)
- Async/ASGI services: [Usage: Async](usage/async.md)
- Framework integration:
  - [FastAPI](integrations/fastapi.md)
  - [Starlette](integrations/starlette.md)
- Operational details:
  - [Configuration](configuration.md)
  - [Errors](errors.md)
  - [Security](security.md)
  - [Migration](migration.md)

## Design Scope

In scope:

- Verification of signed JWT access tokens with explicit issuer/audience/JWKS configuration.
- Consistent authentication/authorization error semantics.
- Sync and async verification paths with shared policy behavior.

Out of scope:

- OAuth/OIDC client flows.
- OIDC discovery and automatic endpoint derivation.
- Session management.
