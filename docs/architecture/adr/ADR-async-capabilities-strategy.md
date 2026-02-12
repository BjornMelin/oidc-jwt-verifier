# ADR: Async Capabilities Strategy

- Status: Accepted
- Date: 2026-02-12
- Owners: `oidc-jwt-verifier` maintainers

## Context

The package originally provided a sync verification path only.
ASGI applications need non-blocking JWT verification and framework-ready integration.

Constraints:

- Keep sync APIs backward compatible.
- Preserve fail-closed JWT/OIDC behavior.
- Support FastAPI and Starlette with first-party helpers.
- Keep optional dependencies out of the base install.

## Options Considered

1. Sync core only, async adapters via threadpool offload.
2. Full parallel async stack with duplicated policy logic.
3. Shared policy core with separate sync and async transports.
4. Async-first rewrite with sync wrappers.
5. Refined shared-policy architecture with dedicated framework helpers.

## Decision Framework

| Criterion | Weight |
| --- | --- |
| Solution leverage | 35% |
| Application value | 30% |
| Maintenance and cognitive load | 25% |
| Architectural adaptability | 10% |

| Option | Solution leverage | Application value | Maintenance/cognitive load | Adaptability | Weighted total |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1. Threadpool adapters only | 8.5 | 7.6 | 8.8 | 6.8 | 8.08 |
| 2. Parallel async stack | 8.7 | 8.9 | 7.1 | 8.2 | 8.26 |
| 3. Shared-policy core | 9.5 | 9.4 | 9.0 | 9.2 | 9.30 |
| 4. Async-first rewrite | 7.0 | 8.4 | 6.3 | 8.8 | 7.37 |
| 5. Refined shared-policy + helpers (chosen) | 9.6 | 9.5 | 9.1 | 9.4 | **9.41** |

## Decision

Adopt option 5.

Implementation shape:

- Keep sync API: `AuthConfig`, `AuthError`, `JWKSClient`, `JWTVerifier`.
- Add async API: `AsyncJWKSClient`, `AsyncJWTVerifier`.
- Centralize policy logic in internal `_policy.py`.
- Provide integration helpers for FastAPI and Starlette.
- Publish optional extras: `async`, `fastapi`, `starlette`.

## Rationale

- Shared policy avoids behavior drift between sync and async paths.
- Existing sync consumers do not need migration.
- Async users get native non-blocking JWKS fetch and verification.
- Framework users get consistent RFC 6750 error handling out of the box.

## Consequences

Positive:

- Policy parity across runtime models
- Better ASGI performance profile than forced threadpool offload
- Clear optional-dependency boundaries

Costs:

- Larger API and test matrix
- More packaging combinations to validate
- Async lifecycle ownership needs explicit documentation

## Rejected Alternatives

- Threadpool-only adapters: no native async fetch path.
- Duplicated policy in sync/async code: long-term drift risk.
- Async-first rewrite: unnecessary migration cost for sync users.

## Follow-up

- Keep sync/async parity tests mandatory for policy changes.
- Keep integration tests for FastAPI and Starlette behavior.
- Benchmark async path and sync-threadpool fallback under concurrent load.
