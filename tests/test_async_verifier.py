"""Async verifier and async JWKS client tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest


pytest.importorskip("httpx")

import httpx
import jwt

from oidc_jwt_verifier import AuthConfig, AuthError, JWTVerifier
from oidc_jwt_verifier.async_jwks import AsyncJWKSClient
from oidc_jwt_verifier.async_verifier import AsyncJWTVerifier
from tests.conftest import jwks_server
from tests.jwt_test_utils import (
    encode_rs256,
    make_rsa_keypair,
    rsa_public_key_to_jwk,
    valid_payload,
)


@pytest.mark.asyncio
async def test_async_valid_token_accepted_and_jwks_cached() -> None:
    """Async verifier accepts valid token and caches JWKS across calls."""
    private_pem, public_key = make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [rsa_public_key_to_jwk(public_key, kid=kid)]}

    issuer = "https://issuer.example/"
    audience = "https://api.example"
    payload = valid_payload(
        issuer=issuer,
        audience=[audience, "https://userinfo.example"],
        scope="read:users",
        permissions=["read:users"],
    )

    with jwks_server(jwks) as local:
        verifier = AsyncJWTVerifier(
            AuthConfig(
                issuer=issuer,
                audience=audience,
                jwks_url=local.url,
                required_scopes=("read:users",),
                required_permissions=("read:users",),
            )
        )
        token = encode_rs256(payload, private_pem=private_pem, kid=kid)

        claims1 = await verifier.verify_access_token(token)
        claims2 = await verifier.verify_access_token(token)
        await verifier.aclose()

    assert claims1["iss"] == issuer
    assert claims2["iss"] == issuer
    assert local.request_count.value == 1


@pytest.mark.asyncio
async def test_async_jwks_client_accepts_bytes_token() -> None:
    """Async JWKS key lookup accepts JWT bytes."""
    private_pem, public_key = make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [rsa_public_key_to_jwk(public_key, kid=kid)]}
    issuer = "https://issuer.example/"
    audience = "https://api.example"
    payload = valid_payload(issuer=issuer, audience=audience)

    with jwks_server(jwks) as local:
        client = AsyncJWKSClient.from_config(
            AuthConfig(
                issuer=issuer,
                audience=audience,
                jwks_url=local.url,
                jwks_timeout_s=1.0,
            )
        )
        token = encode_rs256(payload, private_pem=private_pem, kid=kid)
        signing_key = await client.get_signing_key_from_jwt(
            token.encode("ascii")
        )
        await client.aclose()

    assert signing_key.key_id == kid


@pytest.mark.asyncio
async def test_async_forbidden_header_rejected_before_jwks_fetch() -> None:
    """Forbidden headers fail before any JWKS fetch in async path."""
    private_pem, public_key = make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [rsa_public_key_to_jwk(public_key, kid=kid)]}
    issuer = "https://issuer.example/"
    audience = "https://api.example"
    payload = valid_payload(issuer=issuer, audience=audience)

    with jwks_server(jwks) as local:
        verifier = AsyncJWTVerifier(
            AuthConfig(
                issuer=issuer,
                audience=audience,
                jwks_url=local.url,
                jwks_timeout_s=1,
            )
        )
        token = jwt.encode(
            payload,
            private_pem,
            algorithm="RS256",
            headers={"kid": kid, "jku": "https://evil.example/jwks.json"},
        )

        with pytest.raises(AuthError) as excinfo:
            await verifier.verify_access_token(token)
        await verifier.aclose()

    assert excinfo.value.code == "forbidden_header"
    assert excinfo.value.status_code == 401
    assert local.request_count.value == 0


@pytest.mark.asyncio
async def test_async_disallowed_alg_rejected_without_jwks_fetch() -> None:
    """HS256 token is rejected before JWKS lookup in async verifier."""
    issuer = "https://issuer.example/"
    token = jwt.encode(
        valid_payload(issuer=issuer, audience="https://api.example"),
        "this-is-a-test-secret-key-at-least-32-bytes",
        algorithm="HS256",
    )
    verifier = AsyncJWTVerifier(
        AuthConfig(
            issuer=issuer,
            audience="https://api.example",
            jwks_url="http://127.0.0.1:1/jwks.json",
            allowed_algs=("RS256",),
            jwks_timeout_s=0.1,
        )
    )

    with pytest.raises(AuthError) as excinfo:
        await verifier.verify_access_token(token)
    await verifier.aclose()

    assert excinfo.value.code == "disallowed_alg"
    assert excinfo.value.status_code == 401


@pytest.mark.asyncio
async def test_async_and_sync_verifiers_return_same_claims() -> None:
    """Async and sync verifiers produce equivalent payload results."""
    private_pem, public_key = make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [rsa_public_key_to_jwk(public_key, kid=kid)]}

    issuer = "https://issuer.example/"
    audience = "https://api.example"
    payload = valid_payload(
        issuer=issuer,
        audience=[audience, "https://userinfo.example"],
        scope="read:users",
        permissions=["read:users"],
    )

    with jwks_server(jwks) as local:
        config = AuthConfig(
            issuer=issuer,
            audience=audience,
            jwks_url=local.url,
            jwks_timeout_s=1.0,
        )
        async_verifier = AsyncJWTVerifier(config)
        sync_verifier = JWTVerifier(config)
        token = encode_rs256(payload, private_pem=private_pem, kid=kid)

        async_claims = await async_verifier.verify_access_token(token)
        sync_claims = sync_verifier.verify_access_token(token)
        await async_verifier.aclose()

    assert async_claims == sync_claims


@pytest.mark.asyncio
async def test_async_insufficient_permissions_returns_403() -> None:
    """Async verifier maps missing permissions to insufficient_permissions."""
    private_pem, public_key = make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [rsa_public_key_to_jwk(public_key, kid=kid)]}

    issuer = "https://issuer.example/"
    audience = "https://api.example"
    payload = valid_payload(
        issuer=issuer,
        audience=audience,
        scope="read:users write:users",
        permissions=["read:users"],
    )

    with jwks_server(jwks) as local:
        verifier = AsyncJWTVerifier(
            AuthConfig(
                issuer=issuer,
                audience=audience,
                jwks_url=local.url,
                required_scopes=("read:users",),
                required_permissions=("read:users", "write:users"),
            )
        )
        token = encode_rs256(payload, private_pem=private_pem, kid=kid)

        with pytest.raises(AuthError) as excinfo:
            await verifier.verify_access_token(token)
        await verifier.aclose()

    assert excinfo.value.code == "insufficient_permissions"
    assert excinfo.value.status_code == 403


@pytest.mark.asyncio
async def test_async_verifier_does_not_close_external_http_client() -> None:
    """Verifier must not close externally supplied HTTP client."""
    private_pem, public_key = make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [rsa_public_key_to_jwk(public_key, kid=kid)]}
    issuer = "https://issuer.example/"
    audience = "https://api.example"
    payload: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "exp": int(
            (datetime.now(tz=timezone.utc) + timedelta(seconds=60)).timestamp()
        ),
    }

    with jwks_server(jwks) as local:
        client = httpx.AsyncClient(timeout=1.0)
        verifier = AsyncJWTVerifier(
            AuthConfig(
                issuer=issuer,
                audience=audience,
                jwks_url=local.url,
                jwks_timeout_s=1.0,
            ),
            http_client=client,
        )
        token = encode_rs256(payload, private_pem=private_pem, kid=kid)

        claims = await verifier.verify_access_token(token)
        await verifier.aclose()
        response = await client.get(local.url)
        await client.aclose()

    assert claims["iss"] == issuer
    assert response.status_code == 200
