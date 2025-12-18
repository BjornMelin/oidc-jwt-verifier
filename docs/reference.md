# API Reference

This page documents the public API of the `oidc-jwt-verifier` library.

## Public API

The library exports three main components:

- [`AuthConfig`][oidc_jwt_verifier.AuthConfig] - Configuration dataclass for JWT verification settings
- [`AuthError`][oidc_jwt_verifier.AuthError] - Exception type for authentication/authorization failures
- [`JWTVerifier`][oidc_jwt_verifier.JWTVerifier] - Main verifier class for validating JWTs

---

## Configuration

::: oidc_jwt_verifier.AuthConfig
    options:
      show_source: true
      members_order: source

---

## Errors

::: oidc_jwt_verifier.AuthError
    options:
      show_source: true
      members_order: source

---

## Verifier

::: oidc_jwt_verifier.JWTVerifier
    options:
      show_source: true
      members_order: source
