"""Shared JWT test utilities."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def b64url(data: bytes) -> str:
    """Return base64url encoding without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def rsa_public_key_to_jwk(public_key: rsa.RSAPublicKey, *, kid: str) -> dict[str, str]:
    """Convert an RSA public key to a JWK dict."""
    numbers = public_key.public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {"kty": "RSA", "use": "sig", "kid": kid, "n": b64url(n), "e": b64url(e)}


def make_rsa_keypair(*, key_size: int = 2048) -> tuple[bytes, rsa.RSAPublicKey]:
    """Create RSA private key PEM bytes and public key."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_pem, private_key.public_key()


def encode_rs256(payload: dict[str, Any], *, private_pem: bytes, kid: str | None) -> str:
    """Encode payload as RS256 JWT with optional kid."""
    headers: dict[str, Any] = {}
    if kid is not None:
        headers["kid"] = kid
    return jwt.encode(payload, private_pem, algorithm="RS256", headers=headers)


def valid_payload(
    *,
    issuer: str,
    audience: str | list[str],
    lifetime_s: int = 60,
    include_nbf: bool = True,
    scope: str | None = None,
    permissions: list[str] | None = None,
) -> dict[str, Any]:
    """Create a minimally valid JWT payload for tests."""
    now = datetime.now(tz=timezone.utc)
    payload: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "exp": int((now + timedelta(seconds=lifetime_s)).timestamp()),
    }
    if include_nbf:
        payload["nbf"] = int((now - timedelta(seconds=1)).timestamp())
    if scope is not None:
        payload["scope"] = scope
    if permissions is not None:
        payload["permissions"] = permissions
    return payload
