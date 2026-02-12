# Configuration

`AuthConfig` is the canonical verifier configuration object.
It is immutable (`frozen=True`) and validates inputs at construction time.

## Required Fields

- `issuer`: expected `iss` value
- `audience`: expected `aud` value(s), single string or sequence
- `jwks_url`: URL of trusted JWKS endpoint

```python
from oidc_jwt_verifier import AuthConfig

config = AuthConfig(
    issuer="https://issuer.example/",
    audience=("https://api.example", "https://api-backup.example"),
    jwks_url="https://issuer.example/.well-known/jwks.json",
)
```

## Optional Fields

| Field | Default | Description |
| --- | --- | --- |
| `allowed_algs` | `("RS256",)` | Allowed JWT signing algorithms. `none` is always rejected. |
| `leeway_s` | `0` | Clock skew tolerance for `exp`/`nbf` checks. |
| `jwks_timeout_s` | `3.0` | HTTP timeout (seconds) for JWKS fetch requests. |
| `jwks_cache_ttl_s` | `300.0` | JWKS document cache TTL in seconds. |
| `jwks_max_cached_keys` | `16` | Maximum cached signing keys by `kid`. |
| `enforce_minimum_key_length` | `True` | Enforce PyJWT minimum key length checks. |
| `required_scopes` | `()` | Required scopes for authorization success. |
| `required_permissions` | `()` | Required permissions for authorization success. |
| `scope_claim` | `"scope"` | Claim name used for scope extraction. |
| `permissions_claim` | `"permissions"` | Claim name used for permission extraction. |

## Validation Rules

`AuthConfig` raises `ValueError` when configuration is invalid.

Common examples:

- Empty `issuer`, `audience`, or `jwks_url`
- `allowed_algs` missing or containing `none`
- `leeway_s < 0`
- `jwks_timeout_s <= 0`
- `jwks_cache_ttl_s` outside `(0, 86400]`
- `jwks_max_cached_keys` outside `(0, 1024]`

## Authorization Claim Shapes

- `scope_claim`: supports space-delimited string or list of strings
- `permissions_claim`: supports list of strings or space-delimited string

Authorization failures return `AuthError` with HTTP `403`.

## Configuration Tips

- Reuse one config object per issuer/audience policy.
- Keep `allowed_algs` explicit and minimal.
- Point `jwks_url` to a trusted issuer endpoint only.
- Keep `jwks_timeout_s` low in API services to fail fast under network issues.
