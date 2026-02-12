# Errors

The library raises one public exception type: `AuthError`.

`AuthError` contains:

- `code`: stable machine-readable identifier
- `message`: human-readable description
- `status_code`: HTTP `401` or `403`
- `required_scopes`: populated for `insufficient_scope`
- `required_permissions`: populated for `insufficient_permissions`

## Error Handling Pattern

```python
from oidc_jwt_verifier import AuthError

try:
    claims = verifier.verify_access_token(token)
except AuthError as err:
    status = err.status_code
    code = err.code
    header = err.www_authenticate_header(realm="api")
```

## Error Codes

| Code | Status | Meaning |
| --- | ---: | --- |
| `missing_token` | 401 | Token missing or blank. |
| `malformed_token` | 401 | Token format or header is invalid. |
| `forbidden_header` | 401 | Token header contains forbidden fields (`jku`, `x5u`, `crit`). |
| `disallowed_alg` | 401 | Signing algorithm is not permitted. |
| `missing_kid` | 401 | Token header has no usable `kid`. |
| `token_expired` | 401 | `exp` is in the past. |
| `token_not_yet_valid` | 401 | `nbf` is in the future. |
| `invalid_issuer` | 401 | `iss` does not match configured issuer. |
| `invalid_audience` | 401 | `aud` does not match configured audience(s). |
| `missing_claim` | 401 | Required JWT claim is missing. |
| `invalid_token` | 401 | Signature/claim/key validation failed. |
| `jwks_fetch_failed` | 401 | JWKS endpoint request failed (network/HTTP). |
| `jwks_error` | 401 | JWKS payload or key parsing failed. |
| `key_not_found` | 401 | No key in JWKS matched token `kid`. |
| `insufficient_scope` | 403 | Required scopes are missing. |
| `insufficient_permissions` | 403 | Required permissions are missing. |

## RFC 6750 Header Output

Use `AuthError.www_authenticate_header()` to generate standards-compliant bearer challenge headers.

- For `401`, `error` is `invalid_token`.
- For `403`, `error` is `insufficient_scope`.
- Missing scopes/permissions are included when available.

Example output:

```text
Bearer realm="api", error="invalid_token", error_description="Token is expired"
```
