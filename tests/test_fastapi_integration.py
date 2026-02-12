"""FastAPI integration helper tests."""

from __future__ import annotations

from typing import Any

import pytest

from oidc_jwt_verifier import AuthConfig
from oidc_jwt_verifier.async_verifier import AsyncJWTVerifier
from oidc_jwt_verifier.integrations.fastapi import (
    create_async_bearer_dependency,
)
from tests.conftest import jwks_server
from tests.jwt_test_utils import (
    encode_rs256,
    make_rsa_keypair,
    rsa_public_key_to_jwk,
    valid_payload,
)


@pytest.mark.asyncio
async def test_fastapi_async_dependency_accepts_valid_token() -> None:
    """FastAPI helper dependency returns claims for valid bearer token."""
    import httpx
    from fastapi import Depends, FastAPI

    private_pem, public_key = make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [rsa_public_key_to_jwk(public_key, kid=kid)]}
    issuer = "https://issuer.example/"
    audience = "https://api.example"
    payload = valid_payload(
        issuer=issuer,
        audience=audience,
        scope="read:users",
        permissions=["read:users"],
    )

    with jwks_server(jwks) as local:
        verifier = AsyncJWTVerifier(
            AuthConfig(
                issuer=issuer,
                audience=audience,
                jwks_url=local.url,
                jwks_timeout_s=1.0,
            )
        )
        auth_dep = create_async_bearer_dependency(verifier, realm="api")
        app = FastAPI()

        @app.get("/protected")
        async def protected(
            claims: dict[str, Any] = Depends(auth_dep),  # noqa: B008
        ) -> dict[str, Any]:
            return {"sub": claims.get("sub", "missing"), "iss": claims["iss"]}

        token = encode_rs256(payload, private_pem=private_pem, kid=kid)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await client.get(
                "/protected", headers={"Authorization": f"Bearer {token}"}
            )
        await verifier.aclose()

    assert response.status_code == 200
    assert response.json()["iss"] == issuer


@pytest.mark.asyncio
async def test_fastapi_async_dependency_returns_rfc6750_headers_on_403() -> (
    None
):
    """FastAPI helper maps AuthError to RFC 6750 WWW-Authenticate header."""
    import httpx
    from fastapi import Depends, FastAPI

    private_pem, public_key = make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [rsa_public_key_to_jwk(public_key, kid=kid)]}
    issuer = "https://issuer.example/"
    audience = "https://api.example"
    payload = valid_payload(
        issuer=issuer,
        audience=audience,
        scope="read:users",
        permissions=["read:users"],
    )

    with jwks_server(jwks) as local:
        verifier = AsyncJWTVerifier(
            AuthConfig(
                issuer=issuer,
                audience=audience,
                jwks_url=local.url,
                required_scopes=("write:users",),
            )
        )
        auth_dep = create_async_bearer_dependency(verifier, realm="api")
        app = FastAPI()

        @app.get("/protected")
        async def protected(
            _: dict[str, Any] = Depends(auth_dep),  # noqa: B008
        ) -> dict[str, str]:
            return {"status": "ok"}

        token = encode_rs256(payload, private_pem=private_pem, kid=kid)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            response = await client.get(
                "/protected", headers={"Authorization": f"Bearer {token}"}
            )
        await verifier.aclose()

    assert response.status_code == 403
    header = response.headers.get("WWW-Authenticate", "")
    assert "insufficient_scope" in header
    assert 'realm="api"' in header
