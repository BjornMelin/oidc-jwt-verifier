# Alternatives

This project is intentionally narrow: verify API access tokens from a known OIDC issuer with strict defaults and predictable errors.

## When This Package Fits Best

Use `oidc-jwt-verifier` when you want:

- Explicit issuer, audience, and JWKS URL configuration
- Built-in fail-closed JWT hardening
- Scope and permission enforcement
- Matching sync and async verification behavior
- Ready-to-use FastAPI and Starlette integration helpers

## When Another Approach May Fit Better

### Direct PyJWT usage

Use PyJWT directly when you need full control and are willing to own policy and error mapping details.

- <https://pyjwt.readthedocs.io/en/stable/>

### Discovery-driven verifier packages

Use discovery-oriented packages when you prefer automatic OIDC metadata resolution (`.well-known/openid-configuration`) instead of explicit `jwks_url` setup.

### Framework-specific auth packages

Use framework-specific auth libraries when you want deep integration with one framework and are comfortable with tighter framework coupling.

### General JOSE libraries

Use Authlib, joserfc, or python-jose when you need broader JOSE features beyond access-token verification.

- <https://docs.authlib.org/en/latest/jose/jwt.html>
- <https://pypi.org/project/joserfc/>
- <https://pypi.org/project/python-jose/>

## Design Trade-off

`oidc-jwt-verifier` favors explicit configuration and small surface area over auto-discovery and broad feature scope.
That trade-off keeps verification behavior predictable across frameworks and runtime models.
