# AGENTS.md

OIDC JWT Verifier is a Python library for fail-closed verification of OIDC access tokens using trusted JWKS endpoints. It provides a sync core API with optional async and framework integrations (FastAPI and Starlette).

## Commands

```bash
uv pip install -e ".[dev]"                          # Install
uv run pytest                                        # Test all
uv run pytest tests/test_verifier.py::test_name     # Test single
uv run ruff check . --fix && uv run ruff format .   # Lint/format
uv run ruff check . && uv run ruff format --check . && uv run pytest  # Full QA
uv run --extra docs mkdocs build --strict           # Docs build
```

## Documentation

Google-style docstrings required on all modules, classes, and public functions. Include Args, Returns, Raises, Examples sections. Update docstrings when modifying code behavior. Single line docstrings for test suites.

## Release and Badges

- `release` badge source: `.release-please-manifest.json` on `main`; expect update after a release-please PR merges.
- `pypi` badge source: PyPI; allow short lag while publish/indexing completes.

## Commit Convention

- Use Conventional Commits for all mergeable changes.
- Required release-relevant prefixes: `feat`, `feat!`, `fix`, `perf`, `refactor`, `docs`, `test`, `chore`, `build`, `ci`.
- Release-please ignores non-conventional commit messages for changelog/version automation.
- Pre-1.0 bump behavior in this repo: `feat` bumps patch, `feat!` bumps minor, `fix` bumps patch.

## Testing

Tests use local `ThreadingHTTPServer` fixture (`jwks_server` in `conftest.py`) serving JWKS with request counting for cache verification. RSA keypairs generated via `cryptography`.

Async and framework integration coverage lives in:

- `tests/test_async_verifier.py`
- `tests/test_fastapi_integration.py`
- `tests/test_starlette_integration.py`

### Guidelines

- **Isolation**: Each test must be independent. Use fixtures for setup/teardown, never shared mutable state.
- **Determinism**: No `time.sleep()`, no real network calls. Use fixtures/mocks for external dependencies.
- **Fixtures over mocks**: Prefer real objects with controlled inputs. Mock only at boundaries (network, filesystem).
- **Single assertion focus**: Test one behavior per test. Multiple asserts OK if verifying one logical outcome.
- **Descriptive names**: `test_<unit>_<scenario>_<expected>` e.g. `test_verify_token_expired_raises_401`.
- **Arrange-Act-Assert**: Clear separation. Arrange fixtures, act once, assert results.
- **Error paths**: Test all `Raises` documented in docstrings. Verify error codes and status codes.

### Antipatterns to avoid

- Sleeping for timing (use deterministic waits or mock time)
- Tests depending on execution order
- Shared state between tests
- Catching broad exceptions in tests
- Testing implementation details instead of behavior

## Architecture

JWT verification core for OIDC/JWKS.

Public API:

- Sync: `AuthConfig`, `AuthError`, `JWTVerifier`
- Optional async: `AsyncJWKSClient`, `AsyncJWTVerifier`

Core modules:

- **config.py** - `AuthConfig` dataclass. Validates issuer, audience, JWKS URL, algorithms. Blocks `alg=none`.
- **errors.py** - `AuthError` with `code`, `status_code` (401/403), `www_authenticate_header()`.
- **_policy.py** - shared verification policy for sync and async paths.
- **jwks.py** - `JWKSClient` wraps PyJWT's `PyJWKClient` with caching. Maps errors to `AuthError`.
- **async_jwks.py** - async JWKS client using `httpx.AsyncClient` with TTL and key caching.
- **verifier.py** - `JWTVerifier.verify_access_token()` sync verification path.
- **async_verifier.py** - `AsyncJWTVerifier.verify_access_token()` native async verification path.
- **integrations/fastapi.py** - FastAPI dependency factories and AuthError translation.
- **integrations/starlette.py** - Starlette middleware/helpers and AuthError response mapping.

## Packaging/import boundaries

- Base install is sync-only.
- Async modules require `[async]`.
- FastAPI helpers require `[fastapi]`.
- Starlette helpers require `[starlette]`.

## Security

- Fail-closed.
- Never derives JWKS URL from token headers.
- Explicit algorithm allowlist.
