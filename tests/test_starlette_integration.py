"""Starlette integration helper tests."""

from __future__ import annotations

import pytest

from oidc_jwt_verifier import AuthConfig
from oidc_jwt_verifier.async_verifier import AsyncJWTVerifier
from oidc_jwt_verifier.integrations.starlette import BearerAuthMiddleware
from tests.conftest import jwks_server
from tests.jwt_test_utils import (
    encode_rs256,
    make_rsa_keypair,
    rsa_public_key_to_jwk,
    valid_payload,
)


@pytest.mark.asyncio
async def test_starlette_middleware_sets_claims_on_request_state() -> None:
    """Middleware verifies bearer token and stores claims in request.state."""
    import httpx
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    private_pem, public_key = make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [rsa_public_key_to_jwk(public_key, kid=kid)]}
    issuer = "https://issuer.example/"
    audience = "https://api.example"
    payload = valid_payload(issuer=issuer, audience=audience)

    async def protected(request: Request) -> JSONResponse:
        claims = request.state.auth_claims
        return JSONResponse({"iss": claims["iss"]})

    with jwks_server(jwks) as local:
        verifier = AsyncJWTVerifier(
            AuthConfig(issuer=issuer, audience=audience, jwks_url=local.url, jwks_timeout_s=1.0)
        )
        app = Starlette(routes=[Route("/protected", protected)])
        app.add_middleware(BearerAuthMiddleware, verifier=verifier, realm="api")

        token = encode_rs256(payload, private_pem=private_pem, kid=kid)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get("/protected", headers={"Authorization": f"Bearer {token}"})
        await verifier.aclose()

    assert response.status_code == 200
    assert response.json()["iss"] == issuer


@pytest.mark.asyncio
async def test_starlette_middleware_returns_rfc6750_header_on_missing_token() -> None:
    """Missing bearer token returns 401 with RFC 6750 header."""
    import httpx
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    async def protected(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    verifier = AsyncJWTVerifier(
        AuthConfig(
            issuer="https://issuer.example/",
            audience="https://api.example",
            jwks_url="http://127.0.0.1:1/jwks.json",
            jwks_timeout_s=0.1,
        )
    )
    app = Starlette(routes=[Route("/protected", protected)])
    app.add_middleware(BearerAuthMiddleware, verifier=verifier, realm="api")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/protected")
    await verifier.aclose()

    assert response.status_code == 401
    header = response.headers.get("WWW-Authenticate", "")
    assert "invalid_token" in header
    assert 'realm="api"' in header
