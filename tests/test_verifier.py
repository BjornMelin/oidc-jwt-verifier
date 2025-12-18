import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from oidc_jwt_verifier import AuthConfig, AuthError, JWTVerifier
from tests.conftest import jwks_server


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _rsa_public_key_to_jwk(public_key: rsa.RSAPublicKey, *, kid: str) -> dict[str, str]:
    numbers = public_key.public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {"kty": "RSA", "use": "sig", "kid": kid, "n": _b64url(n), "e": _b64url(e)}


def _make_rsa_keypair() -> tuple[bytes, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_pem, private_key.public_key()


def _encode_rs256(
    payload: dict[str, Any],
    *,
    private_pem: bytes,
    kid: str | None,
) -> str:
    headers: dict[str, Any] = {}
    if kid is not None:
        headers["kid"] = kid
    return jwt.encode(payload, private_pem, algorithm="RS256", headers=headers)


def test_valid_token_accepted_and_jwks_cached() -> None:
    private_pem, public_key = _make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [_rsa_public_key_to_jwk(public_key, kid=kid)]}

    issuer = "https://issuer.example/"
    audience = "https://api.example"
    now = datetime.now(tz=timezone.utc)

    payload = {
        "iss": issuer,
        "aud": [audience, "https://userinfo.example"],
        "exp": int((now + timedelta(seconds=60)).timestamp()),
        "nbf": int((now - timedelta(seconds=1)).timestamp()),
        "scope": "read:users",
        "permissions": ["read:users"],
    }

    with jwks_server(jwks) as local:
        config = AuthConfig(
            issuer=issuer,
            audience=audience,
            jwks_url=local.url,
            allowed_algs=("RS256",),
            jwks_timeout_s=1.0,
            jwks_cache_ttl_s=300,
            jwks_max_cached_keys=8,
            required_scopes=("read:users",),
            required_permissions=("read:users",),
        )
        verifier = JWTVerifier(config)
        token = _encode_rs256(payload, private_pem=private_pem, kid=kid)

        claims1 = verifier.verify_access_token(token)
        claims2 = verifier.verify_access_token(token)

        assert claims1["iss"] == issuer
        assert claims2["iss"] == issuer
        assert local.request_count.value == 1


def test_wrong_issuer_rejected() -> None:
    private_pem, public_key = _make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [_rsa_public_key_to_jwk(public_key, kid=kid)]}

    issuer = "https://issuer.example/"
    now = datetime.now(tz=timezone.utc)
    payload = {
        "iss": "https://wrong.example/",
        "aud": "https://api.example",
        "exp": int((now + timedelta(seconds=60)).timestamp()),
    }

    with jwks_server(jwks) as local:
        verifier = JWTVerifier(
            AuthConfig(
                issuer=issuer,
                audience="https://api.example",
                jwks_url=local.url,
                jwks_timeout_s=1.0,
            )
        )
        token = _encode_rs256(payload, private_pem=private_pem, kid=kid)

        with pytest.raises(AuthError) as excinfo:
            verifier.verify_access_token(token)

        err = excinfo.value
        assert err.code == "invalid_issuer"
        assert err.status_code == 401


def test_wrong_audience_rejected_including_multi_audience_token() -> None:
    private_pem, public_key = _make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [_rsa_public_key_to_jwk(public_key, kid=kid)]}

    issuer = "https://issuer.example/"
    now = datetime.now(tz=timezone.utc)
    payload = {
        "iss": issuer,
        "aud": ["https://api.example", "https://userinfo.example"],
        "exp": int((now + timedelta(seconds=60)).timestamp()),
    }

    with jwks_server(jwks) as local:
        verifier = JWTVerifier(
            AuthConfig(
                issuer=issuer,
                audience="https://wrong.example",
                jwks_url=local.url,
                jwks_timeout_s=1.0,
            )
        )
        token = _encode_rs256(payload, private_pem=private_pem, kid=kid)

        with pytest.raises(AuthError) as excinfo:
            verifier.verify_access_token(token)

        err = excinfo.value
        assert err.code == "invalid_audience"
        assert err.status_code == 401


def test_multi_expected_audiences_supported() -> None:
    private_pem, public_key = _make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [_rsa_public_key_to_jwk(public_key, kid=kid)]}

    issuer = "https://issuer.example/"
    now = datetime.now(tz=timezone.utc)
    payload = {
        "iss": issuer,
        "aud": "https://api-2.example",
        "exp": int((now + timedelta(seconds=60)).timestamp()),
    }

    with jwks_server(jwks) as local:
        verifier = JWTVerifier(
            AuthConfig(
                issuer=issuer,
                audience=("https://api-1.example", "https://api-2.example"),
                jwks_url=local.url,
                jwks_timeout_s=1.0,
            )
        )
        token = _encode_rs256(payload, private_pem=private_pem, kid=kid)

        claims = verifier.verify_access_token(token)
        assert claims["aud"] == "https://api-2.example"


def test_expired_and_nbf_rejected() -> None:
    private_pem, public_key = _make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [_rsa_public_key_to_jwk(public_key, kid=kid)]}

    issuer = "https://issuer.example/"
    audience = "https://api.example"
    now = datetime.now(tz=timezone.utc)

    expired_payload = {
        "iss": issuer,
        "aud": audience,
        "exp": int((now - timedelta(seconds=1)).timestamp()),
    }
    future_nbf_payload = {
        "iss": issuer,
        "aud": audience,
        "exp": int((now + timedelta(seconds=60)).timestamp()),
        "nbf": int((now + timedelta(seconds=60)).timestamp()),
    }

    with jwks_server(jwks) as local:
        verifier = JWTVerifier(
            AuthConfig(
                issuer=issuer,
                audience=audience,
                jwks_url=local.url,
                jwks_timeout_s=1.0,
            )
        )

        expired_token = _encode_rs256(expired_payload, private_pem=private_pem, kid=kid)
        with pytest.raises(AuthError) as excinfo:
            verifier.verify_access_token(expired_token)
        assert excinfo.value.code == "token_expired"
        assert excinfo.value.status_code == 401

        nbf_token = _encode_rs256(future_nbf_payload, private_pem=private_pem, kid=kid)
        with pytest.raises(AuthError) as excinfo:
            verifier.verify_access_token(nbf_token)
        assert excinfo.value.code == "token_not_yet_valid"
        assert excinfo.value.status_code == 401


def test_disallowed_alg_rejected_without_jwks_fetch() -> None:
    issuer = "https://issuer.example/"

    # HS256 token: should fail fast before any JWKS call.
    token = jwt.encode(
        {
            "iss": issuer,
            "aud": "https://api.example",
            "exp": int((datetime.now(tz=timezone.utc) + timedelta(seconds=60)).timestamp()),
        },
        "secret",
        algorithm="HS256",
    )

    verifier = JWTVerifier(
        AuthConfig(
            issuer=issuer,
            audience="https://api.example",
            jwks_url="http://127.0.0.1:1/jwks.json",
            allowed_algs=("RS256",),
            jwks_timeout_s=0.1,
        )
    )

    with pytest.raises(AuthError) as excinfo:
        verifier.verify_access_token(token)
    assert excinfo.value.code == "disallowed_alg"
    assert excinfo.value.status_code == 401


def test_required_scopes_and_permissions_enforced() -> None:
    private_pem, public_key = _make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [_rsa_public_key_to_jwk(public_key, kid=kid)]}

    issuer = "https://issuer.example/"
    audience = "https://api.example"
    now = datetime.now(tz=timezone.utc)
    payload = {
        "iss": issuer,
        "aud": audience,
        "exp": int((now + timedelta(seconds=60)).timestamp()),
        "scope": "read:users",
        "permissions": ["read:users"],
    }

    with jwks_server(jwks) as local:
        verifier = JWTVerifier(
            AuthConfig(
                issuer=issuer,
                audience=audience,
                jwks_url=local.url,
                jwks_timeout_s=1.0,
                required_scopes=("delete:users",),
                required_permissions=("read:users", "write:users"),
            )
        )
        token = _encode_rs256(payload, private_pem=private_pem, kid=kid)

        with pytest.raises(AuthError) as excinfo:
            verifier.verify_access_token(token)
        assert excinfo.value.code == "insufficient_scope"
        assert excinfo.value.status_code == 403


def test_jwks_fetch_failure_fails_closed() -> None:
    issuer = "https://issuer.example/"
    audience = "https://api.example"
    now = datetime.now(tz=timezone.utc)

    # Token shape is valid, but JWKS URL is unreachable. We only need a header parseable token
    # with RS256 + kid to exercise JWKS fetch failure.
    token = ".".join(
        [
            _b64url(json.dumps({"alg": "RS256", "kid": "kid-1", "typ": "JWT"}).encode("utf-8")),
            _b64url(
                json.dumps(
                    {
                        "iss": issuer,
                        "aud": audience,
                        "exp": int((now + timedelta(seconds=60)).timestamp()),
                    }
                ).encode("utf-8")
            ),
            _b64url(b"signature"),
        ]
    )

    verifier = JWTVerifier(
        AuthConfig(
            issuer=issuer,
            audience=audience,
            jwks_url="http://127.0.0.1:1/jwks.json",
            jwks_timeout_s=0.2,
        )
    )

    with pytest.raises(AuthError) as excinfo:
        verifier.verify_access_token(token)

    assert excinfo.value.code in {"jwks_fetch_failed", "jwks_error"}
    assert excinfo.value.status_code == 401


def test_missing_kid_rejected() -> None:
    private_pem, public_key = _make_rsa_keypair()
    jwks = {"keys": [_rsa_public_key_to_jwk(public_key, kid="test-key-1")]}

    issuer = "https://issuer.example/"
    audience = "https://api.example"
    now = datetime.now(tz=timezone.utc)
    payload = {
        "iss": issuer,
        "aud": audience,
        "exp": int((now + timedelta(seconds=60)).timestamp()),
    }

    with jwks_server(jwks) as local:
        verifier = JWTVerifier(
            AuthConfig(
                issuer=issuer,
                audience=audience,
                jwks_url=local.url,
                jwks_timeout_s=1.0,
            )
        )
        token = _encode_rs256(payload, private_pem=private_pem, kid=None)

        with pytest.raises(AuthError) as excinfo:
            verifier.verify_access_token(token)
        assert excinfo.value.code == "missing_kid"
        assert excinfo.value.status_code == 401


@pytest.mark.parametrize(
    "extra_header",
    [
        {"jku": "https://evil.example/jwks.json"},
        {"x5u": "https://evil.example/cert.pem"},
        {"crit": ["exp"]},
    ],
)
def test_forbidden_headers_rejected_before_jwks_fetch(extra_header: dict[str, Any]) -> None:
    private_pem, public_key = _make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [_rsa_public_key_to_jwk(public_key, kid=kid)]}

    issuer = "https://issuer.example/"
    audience = "https://api.example"
    now = datetime.now(tz=timezone.utc)
    payload = {
        "iss": issuer,
        "aud": audience,
        "exp": int((now + timedelta(seconds=60)).timestamp()),
    }

    with jwks_server(jwks) as local:
        verifier = JWTVerifier(
            AuthConfig(
                issuer=issuer,
                audience=audience,
                jwks_url=local.url,
                jwks_timeout_s=1.0,
            )
        )
        headers = {"kid": kid, **extra_header}
        token = jwt.encode(payload, private_pem, algorithm="RS256", headers=headers)

        with pytest.raises(AuthError) as excinfo:
            verifier.verify_access_token(token)

        assert excinfo.value.code == "forbidden_header"
        assert excinfo.value.status_code == 401
        assert local.request_count.value == 0


def test_alg_none_and_missing_alg_rejected() -> None:
    issuer = "https://issuer.example/"
    audience = "https://api.example"
    now = datetime.now(tz=timezone.utc)

    base_payload = {
        "iss": issuer,
        "aud": audience,
        "exp": int((now + timedelta(seconds=60)).timestamp()),
    }

    def raw_token(header: dict[str, Any]) -> str:
        return ".".join(
            [
                _b64url(json.dumps(header).encode("utf-8")),
                _b64url(json.dumps(base_payload).encode("utf-8")),
                "",
            ]
        )

    verifier = JWTVerifier(
        AuthConfig(
            issuer=issuer,
            audience=audience,
            jwks_url="http://127.0.0.1:1/jwks.json",
            allowed_algs=("RS256",),
            jwks_timeout_s=0.1,
        )
    )

    with pytest.raises(AuthError) as excinfo:
        verifier.verify_access_token(raw_token({"alg": "none"}))
    assert excinfo.value.code == "disallowed_alg"

    with pytest.raises(AuthError) as excinfo:
        verifier.verify_access_token(raw_token({"kid": "kid-1"}))
    assert excinfo.value.code == "malformed_token"


@pytest.mark.parametrize("missing_claim", ["exp", "iss", "aud"])
def test_missing_required_claims_rejected(missing_claim: str) -> None:
    private_pem, public_key = _make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [_rsa_public_key_to_jwk(public_key, kid=kid)]}

    issuer = "https://issuer.example/"
    audience = "https://api.example"
    now = datetime.now(tz=timezone.utc)
    payload: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "exp": int((now + timedelta(seconds=60)).timestamp()),
    }
    payload.pop(missing_claim)

    with jwks_server(jwks) as local:
        verifier = JWTVerifier(
            AuthConfig(
                issuer=issuer,
                audience=audience,
                jwks_url=local.url,
                jwks_timeout_s=1.0,
            )
        )
        token = _encode_rs256(payload, private_pem=private_pem, kid=kid)

        with pytest.raises(AuthError) as excinfo:
            verifier.verify_access_token(token)

        assert excinfo.value.code == "missing_claim"
        assert excinfo.value.status_code == 401


def test_key_not_found_fails_closed() -> None:
    private_pem, public_key = _make_rsa_keypair()
    jwks = {"keys": [_rsa_public_key_to_jwk(public_key, kid="jwks-kid")]}

    issuer = "https://issuer.example/"
    audience = "https://api.example"
    now = datetime.now(tz=timezone.utc)
    payload = {
        "iss": issuer,
        "aud": audience,
        "exp": int((now + timedelta(seconds=60)).timestamp()),
    }

    with jwks_server(jwks) as local:
        verifier = JWTVerifier(
            AuthConfig(
                issuer=issuer,
                audience=audience,
                jwks_url=local.url,
                jwks_timeout_s=1.0,
            )
        )
        token = _encode_rs256(payload, private_pem=private_pem, kid="token-kid")

        with pytest.raises(AuthError) as excinfo:
            verifier.verify_access_token(token)

        assert excinfo.value.code == "key_not_found"
        assert excinfo.value.status_code == 401
        assert local.request_count.value >= 1
