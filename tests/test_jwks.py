"""Sync JWKS client lifecycle tests."""

from __future__ import annotations

from typing import Any

import pytest
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

from oidc_jwt_verifier import AuthConfig, AuthError
from oidc_jwt_verifier.jwks import JWKSClient
from tests.conftest import jwks_server
from tests.jwt_test_utils import make_rsa_keypair, rsa_public_key_to_jwk


def _make_config(jwks_url: str) -> AuthConfig:
    return AuthConfig(
        issuer="https://issuer.example/",
        audience="https://api.example",
        jwks_url=jwks_url,
        jwks_timeout_s=0.2,
        jwks_cache_ttl_s=300,
        jwks_max_cached_keys=8,
    )


def test_get_signing_keys_uses_cached_jwks_until_refresh() -> None:
    """Signing-key fetches reuse cached JWKS until refresh is requested."""
    _, public_key = make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [rsa_public_key_to_jwk(public_key, kid=kid)]}

    with jwks_server(jwks) as local:
        client = JWKSClient.from_config(_make_config(local.url))

        initial = client.get_signing_keys()
        cached = client.get_signing_keys()
        refreshed = client.get_signing_keys(refresh=True)

    assert [key.key_id for key in initial] == [kid]
    assert [key.key_id for key in cached] == [kid]
    assert [key.key_id for key in refreshed] == [kid]
    assert local.request_count.value == 2


def test_get_signing_key_supports_direct_lookup_and_forced_refresh() -> None:
    """Direct key lookup works with cached and forced-refresh flows."""
    _, public_key = make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [rsa_public_key_to_jwk(public_key, kid=kid)]}

    with jwks_server(jwks) as local:
        client = JWKSClient.from_config(_make_config(local.url))

        cached = client.get_signing_key(kid)
        refreshed = client.get_signing_key(kid, refresh=True)

    assert cached.key_id == kid
    assert refreshed.key_id == kid
    assert local.request_count.value == 2


def test_get_signing_key_refresh_miss_raises_key_not_found() -> None:
    """Forced refresh miss returns the stable key_not_found error."""
    _, public_key = make_rsa_keypair()
    jwks = {"keys": [rsa_public_key_to_jwk(public_key, kid="test-key-1")]}

    with jwks_server(jwks) as local:
        client = JWKSClient.from_config(_make_config(local.url))

        with pytest.raises(AuthError) as excinfo:
            client.get_signing_key("missing-key", refresh=True)

    assert excinfo.value.code == "key_not_found"
    assert excinfo.value.status_code == 401


def test_get_signing_keys_raises_auth_error_for_malformed_jwks() -> None:
    """Malformed JWKS payloads map to AuthError."""
    malformed_jwks: dict[str, Any] = {"keys": "not-a-list"}

    with jwks_server(malformed_jwks) as local:
        client = JWKSClient.from_config(_make_config(local.url))

        with pytest.raises(AuthError) as excinfo:
            client.get_signing_keys()

    assert excinfo.value.code == "jwks_error"


def test_get_signing_keys_maps_non_lookup_client_errors_to_jwks_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Non-lookup PyJWK client errors remain jwks_error."""
    client = JWKSClient.from_config(
        _make_config("https://issuer.example/jwks.json")
    )

    def fail_lookup(*, refresh: bool = False) -> list[object]:
        del refresh
        raise PyJWKClientError("kid must be present in every key")

    monkeypatch.setattr(client._client, "get_signing_keys", fail_lookup)

    with pytest.raises(AuthError) as excinfo:
        client.get_signing_keys()

    assert excinfo.value.code == "jwks_error"
    assert excinfo.value.status_code == 401


def test_get_signing_keys_fetch_failure_raises_jwks_fetch_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fetch failures return the stable jwks_fetch_failed error."""
    client = JWKSClient.from_config(
        _make_config("https://issuer.example/jwks.json")
    )

    def fail_fetch() -> dict[str, object]:
        raise PyJWKClientConnectionError("boom")

    monkeypatch.setattr(client._client, "fetch_data", fail_fetch)

    with pytest.raises(AuthError) as excinfo:
        client.get_signing_keys(refresh=True)

    assert excinfo.value.code == "jwks_fetch_failed"
    assert excinfo.value.status_code == 401


def test_healthcheck_returns_true_for_reachable_jwks() -> None:
    """Healthcheck succeeds when the configured JWKS yields signing keys."""
    _, public_key = make_rsa_keypair()
    kid = "test-key-1"
    jwks = {"keys": [rsa_public_key_to_jwk(public_key, kid=kid)]}

    with jwks_server(jwks) as local:
        client = JWKSClient.from_config(_make_config(local.url))

        healthy = client.healthcheck()
        refreshed = client.healthcheck(refresh=True)

    assert healthy is True
    assert refreshed is True
    assert local.request_count.value == 2


def test_healthcheck_returns_false_on_fetch_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Healthcheck fails closed when the JWKS endpoint is unreachable."""
    client = JWKSClient.from_config(
        _make_config("https://issuer.example/jwks.json")
    )

    def fail_fetch() -> dict[str, object]:
        raise PyJWKClientConnectionError("boom")

    monkeypatch.setattr(client._client, "fetch_data", fail_fetch)

    assert client.healthcheck() is False


def test_healthcheck_returns_false_on_malformed_jwks() -> None:
    """Healthcheck fails closed when the JWKS payload is malformed."""
    malformed_jwks: dict[str, Any] = {"keys": "not-a-list"}

    with jwks_server(malformed_jwks) as local:
        client = JWKSClient.from_config(_make_config(local.url))

        assert client.healthcheck(refresh=True) is False
