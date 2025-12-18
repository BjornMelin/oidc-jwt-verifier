# Alternatives and rationale

This project exists because JWT validation for APIs is easy to get *mostly* right while still missing
important security and interoperability details (algorithm allowlists, unsafe header handling,
consistent error responses, and authorization checks like scopes/permissions).

`oidc-jwt-verifier` is intentionally small and policy-driven: you provide explicit configuration
(`issuer`, `audience`, `jwks_url`, allowed algorithms, and required scopes), and the library applies
conservative defaults and consistent error behavior.

## Scope and non-goals

**In scope**

- Verifying signed JWT access tokens for a known OIDC issuer.
- Fetching signing keys from a configured JWKS URL with caching (via PyJWT’s `PyJWKClient`).
- Enforcing claim checks (`iss`, `aud`, `exp`, `nbf`) and authorization policy (required scopes and
  permissions).
- Returning an RFC 6750-compatible `WWW-Authenticate` header via `AuthError`.

**Not in scope**

- OIDC discovery (`.well-known/openid-configuration`) or deriving endpoints from the token.
- Client-side OAuth/OIDC flows, session management, or framework integrations.
- Async key fetching (this library is synchronous by design).

## Comparisons to related packages

### Use PyJWT directly

PyJWT is the underlying JWT implementation and provides the core primitives, including `PyJWKClient`
for fetching and caching signing keys from a JWKS endpoint.

- PyJWT docs: `https://github.com/jpadilla/pyjwt/blob/master/docs/usage.rst`

Choose **PyJWT directly** when you want maximum control and are prepared to implement and review
your own security policy: allowed algorithms, header restrictions, audience/issuer rules, required
scopes/permissions, and consistent API error mapping.

Choose **`oidc-jwt-verifier`** when you want those policy decisions centralized and reused across
multiple apps/frameworks with the same behavior.

### `verify-oidc-token`

`verify-oidc-token` focuses on verifying tokens against an OIDC issuer with a small surface area and
provides a CLI.

- PyPI: `https://pypi.org/project/verify-oidc-token/`

It’s a reasonable choice for scripts and lightweight checks; `oidc-jwt-verifier` is optimized for
server-side API enforcement (repeatable policy + API-friendly errors) rather than being a minimal
verification utility.

### `py-jwt-verifier`

`py-jwt-verifier` supports multiple identity providers and uses OIDC configuration discovery to find
`jwks_uri`, with caching via `requests_cache`.

- PyPI: `https://pypi.org/project/py-jwt-verifier/`

If you want discovery-driven configuration and a more “IdP-agnostic out of the box” flow,
`py-jwt-verifier` may be a better fit. If you prefer explicit configuration (never deriving a JWKS
URL from token contents/headers) and a small verifier you can embed across frameworks,
`oidc-jwt-verifier` is the intended fit.

### `flask-oidc-verifier`

`flask-oidc-verifier` targets Flask specifically.

- PyPI: `https://pypi.org/project/flask-oidc-verifier/`

If you’re all-in on Flask and want an opinionated integration, a framework-specific package can be a
good choice. `oidc-jwt-verifier` is framework-agnostic on purpose so you can share the same policy
across different runtimes (e.g., WSGI, ASGI, Lambda).

### `verify-oidc-identity`

`verify-oidc-identity` is oriented around verifying OIDC ID tokens (identity assertions) and
supports both sync and async flows.

- PyPI: `https://pypi.org/project/verify-oidc-identity/`

If you are primarily validating ID tokens (authentication), prefer an ID-token-oriented library. If
you’re validating API access tokens and enforcing scopes/permissions, `oidc-jwt-verifier` stays
focused on that server-side use case.

### General JOSE/JWT libraries (`Authlib`, `joserfc`, `python-jose`)

General-purpose JOSE/JWT libraries are good foundations, but they typically expect you to supply key
material and policy rather than providing an API-token verifier with JWKS fetching behavior and API
error conventions.

- Authlib (JOSE/JWT): `https://docs.authlib.org/en/latest/jose/jwt.html`
- joserfc: `https://pypi.org/project/joserfc/`
- python-jose: `https://pypi.org/project/python-jose/`

Choose these when you’re building a broader auth stack or need advanced JOSE features. Choose
`oidc-jwt-verifier` when you want a small, opinionated verification core for API access tokens.

### Async key fetching: `pyjwt-key-fetcher`

If you specifically need async JWKS fetching and want something “PyJWT-shaped”, `pyjwt-key-fetcher`
positions itself as an async alternative to `PyJWKClient` and can retrieve OIDC configuration (to
find `jwks_uri`).

- PyPI: `https://pypi.org/project/pyjwt-key-fetcher/`

## Why use `oidc-jwt-verifier`

Use this library when you want:

- A single, reusable verifier across frameworks with explicit issuer/audience/JWKS configuration.
- Conservative defaults around algorithm allowlists and header handling (fail closed).
- Built-in enforcement for scopes/permissions and consistent API-friendly errors (`AuthError`).

