# API Reference

This page documents the package public API and optional integration modules.

## Core Public API

Available in the base install:

- [`AuthConfig`][oidc_jwt_verifier.AuthConfig]
- [`AuthError`][oidc_jwt_verifier.AuthError]
- [`JWTVerifier`][oidc_jwt_verifier.JWTVerifier]

::: oidc_jwt_verifier.AuthConfig
    options:
      show_source: true
      members_order: source

::: oidc_jwt_verifier.AuthError
    options:
      show_source: true
      members_order: source

::: oidc_jwt_verifier.JWTVerifier
    options:
      show_source: true
      members_order: source

## Optional Async API

Requires `pip install "oidc-jwt-verifier[async]"`.

- `oidc_jwt_verifier.async_jwks.AsyncJWKSClient`
- `oidc_jwt_verifier.async_verifier.AsyncJWTVerifier`

::: oidc_jwt_verifier.async_jwks.AsyncJWKSClient
    options:
      show_source: true
      members_order: source

::: oidc_jwt_verifier.async_verifier.AsyncJWTVerifier
    options:
      show_source: true
      members_order: source

## Optional FastAPI Integration API

Requires `pip install "oidc-jwt-verifier[fastapi]"`.

- `oidc_jwt_verifier.integrations.fastapi.auth_error_to_http_exception`
- `oidc_jwt_verifier.integrations.fastapi.create_async_bearer_dependency`
- `oidc_jwt_verifier.integrations.fastapi.create_sync_bearer_dependency`

::: oidc_jwt_verifier.integrations.fastapi
    options:
      show_source: true
      members_order: source

## Optional Starlette Integration API

Requires `pip install "oidc-jwt-verifier[starlette]"`.

- `oidc_jwt_verifier.integrations.starlette.BearerAuthMiddleware`
- `oidc_jwt_verifier.integrations.starlette.verify_request_bearer_token`
- `oidc_jwt_verifier.integrations.starlette.auth_error_to_response`

::: oidc_jwt_verifier.integrations.starlette
    options:
      show_source: true
      members_order: source
