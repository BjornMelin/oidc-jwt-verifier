# Security Model

The verifier is designed to fail closed. If any validation step fails, the token is rejected.

## Hardening Defaults

- Rejects tokens with `alg=none`.
- Enforces explicit algorithm allowlist from `AuthConfig.allowed_algs`.
- Rejects tokens containing `jku`, `x5u`, or `crit` headers.
- Requires `kid` for JWKS key lookup.
- Verifies signature, issuer, audience, and expiration.
- Verifies `nbf` when present.
- Enforces minimum key length by default (`enforce_minimum_key_length=True`).

## JWKS Trust Boundary

- Keys are fetched only from `AuthConfig.jwks_url`.
- The JWKS URL is never derived from token content.
- JWKS fetch and parse failures return authentication errors (`401`).

## Authorization Enforcement

- `required_scopes` and `required_permissions` are enforced after successful authentication.
- Authorization failures return `403`.
- `WWW-Authenticate` includes RFC 6750 semantics.

## Operational Guidance

- Do not log raw bearer tokens.
- Log `AuthError.code` and `AuthError.status_code` for safe diagnostics.
- Reuse verifier instances to avoid unnecessary network and cache churn.
- Keep algorithm allowlists tight and explicit.

## Standards and References

- [RFC 8725: JWT Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [RFC 7519: JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 6750: OAuth 2.0 Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)
- [PyJWT Documentation](https://pyjwt.readthedocs.io/en/stable/)
