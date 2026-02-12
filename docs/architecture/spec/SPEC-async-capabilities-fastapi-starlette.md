# SPEC: Async Capabilities for FastAPI and Starlette

- Status: Implemented
- Date: 2026-02-12

## Goals

- Provide native async JWT verification.
- Keep existing sync API behavior intact.
- Provide first-party FastAPI and Starlette helpers.
- Maintain strict fail-closed security defaults.

## Non-goals

- Removing sync APIs.
- OIDC discovery or dynamic endpoint derivation from token data.
- Built-in telemetry backend integrations.

## Public API Contract

### Sync

- `JWTVerifier.verify_access_token(token: str) -> dict[str, Any]`
- `JWKSClient.get_signing_key_from_jwt(token: str | bytes) -> PyJWK`

### Async

- `AsyncJWTVerifier.verify_access_token(token: str) -> dict[str, Any]`
- `AsyncJWTVerifier.aclose() -> None`
- `AsyncJWKSClient.get_signing_key_from_jwt(token: str | bytes) -> PyJWK`
- `AsyncJWKSClient.aclose() -> None`

### Integrations

FastAPI (`oidc_jwt_verifier.integrations.fastapi`):

- `create_async_bearer_dependency(...)`
- `create_sync_bearer_dependency(...)`
- `auth_error_to_http_exception(...)`

Starlette (`oidc_jwt_verifier.integrations.starlette`):

- `BearerAuthMiddleware`
- `verify_request_bearer_token(...)`
- `auth_error_to_response(...)`

## Packaging Strategy

Optional extras:

- `async`: `httpx`, `anyio`
- `fastapi`: `fastapi` plus async dependencies
- `starlette`: `starlette` plus async dependencies

Base install remains sync-only.

Import boundaries:

- Root import works without async dependencies.
- Async modules require async dependencies.
- Framework integration modules require framework dependencies.

## Shared Policy Model

`oidc_jwt_verifier._policy` defines shared behavior for sync and async verifiers:

- Header checks (`jku`, `x5u`, `crit`, `alg`, `kid`)
- Decode options and claim verification loop
- Decode exception to `AuthError` mapping
- Scope and permission enforcement

## Lifecycle Rules

### AsyncJWKSClient

- Owns and closes internal `httpx.AsyncClient` when created internally.
- Does not close externally injected `httpx.AsyncClient`.

### AsyncJWTVerifier

- Closes internal async JWKS client only when it created that client.
- Does not close externally injected JWKS client.

## Cache and Fetch Behavior

- JWKS document cache with TTL (`jwks_cache_ttl_s`).
- Key cache by `kid` with max size (`jwks_max_cached_keys`).
- On missing `kid`, perform normal lookup, then one forced JWKS refresh, then fail.
- Async fetch supports configurable retry attempts (`max_fetch_attempts`, default `2`).

## Error Semantics

Sync and async paths emit the same `AuthError` taxonomy and status semantics.

- Authentication failures return `401`.
- Authorization failures return `403`.
- `WWW-Authenticate` values are produced by `AuthError.www_authenticate_header()`.

## Security Constraints

- Reject `alg=none`.
- Enforce configured algorithm allowlist.
- Reject `jku`, `x5u`, and `crit` headers.
- Require `kid` for key lookup.
- Never derive JWKS source from token headers.
- Fail closed on parse, fetch, decode, and claim failures.

## Performance Expectations

- Async path should be preferred for async frameworks to avoid blocking behavior.
- Sync verifier remains valid in async frameworks through threadpool helpers when migration is not immediate.
- Performance verification should compare native async path vs sync-threadpool fallback under concurrent load.

## Compatibility and Versioning

- Sync API remains backward compatible.
- Async and framework APIs are additive.
- Release impact is minor-version additive behavior.

## References

- <https://fastapi.tiangolo.com/async/>
- <https://fastapi.tiangolo.com/tutorial/dependencies/>
- <https://www.starlette.io/threadpool/>
- <https://www.starlette.io/>
- <https://anyio.readthedocs.io/en/stable/>
- <https://pyjwt.readthedocs.io/en/stable/>
- <https://pyjwt.readthedocs.io/en/stable/api.html>
- <https://packaging.python.org/en/latest/specifications/declaring-project-metadata/>
- <https://docs.astral.sh/uv/>
- <https://datatracker.ietf.org/doc/html/rfc8725>
- <https://datatracker.ietf.org/doc/html/rfc6750>
- <https://www.rfc-editor.org/rfc/rfc7519>
