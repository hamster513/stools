"""Клиент провайдера: discovery, ключи, обмен кода, проверка id_token."""
from __future__ import annotations

import time

import pytest

from api.oidc import provider
from api.oidc.settings import OidcSettings
from tests.api.fake_oidc import FakeProvider


@pytest.fixture
def fam() -> FakeProvider:
    provider.invalidate_cache()
    return FakeProvider()


def _settings(fam: FakeProvider) -> OidcSettings:
    settings = OidcSettings(
        public_url="https://stools.test",
        issuer_url=fam.issuer,
        client_id=fam.client_id,
        client_secret=fam.client_secret,
    )
    fam.redirect_uri = settings.redirect_uri
    return settings


def test_discovery_is_cached(fam: FakeProvider) -> None:
    first = provider.fetch_discovery(fam.issuer, fam.http_factory)
    fam.calls.clear()
    second = provider.fetch_discovery(fam.issuer, fam.http_factory)
    assert first == second and fam.calls == []


def test_network_failure_is_unavailable(fam: FakeProvider) -> None:
    fam.down = True
    with pytest.raises(provider.ProviderError) as exc:
        provider.fetch_discovery(fam.issuer, fam.http_factory)
    assert exc.value.code == "oidc_unavailable"


def test_foreign_issuer_in_discovery_is_rejected(fam: FakeProvider) -> None:
    fam.advertised_issuer = "https://other.test/realms/corp"
    with pytest.raises(provider.ProviderError) as exc:
        provider.fetch_discovery(fam.issuer, fam.http_factory)
    assert exc.value.code == "oidc_unavailable"
    assert "other.test" in str(exc.value)


def test_malformed_discovery_is_unavailable(fam: FakeProvider) -> None:
    fam.garbage.add("discovery")
    with pytest.raises(provider.ProviderError) as exc:
        provider.fetch_discovery(fam.issuer, fam.http_factory)
    assert exc.value.code == "oidc_unavailable"


def test_malformed_jwks_is_unavailable(fam: FakeProvider) -> None:
    disco = provider.fetch_discovery(fam.issuer, fam.http_factory)
    fam.garbage.add("certs")
    with pytest.raises(provider.ProviderError) as exc:
        provider.fetch_jwks(disco.jwks_uri, fam.http_factory)
    assert exc.value.code == "oidc_unavailable"


def test_jwks_keeps_only_signing_keys(fam: FakeProvider) -> None:
    disco = provider.fetch_discovery(fam.issuer, fam.http_factory)
    keys = provider.fetch_jwks(disco.jwks_uri, fam.http_factory)
    assert [key["kid"] for key in keys] == [fam.kid]


def test_exchange_and_verify_round_trip(fam: FakeProvider) -> None:
    settings = _settings(fam)
    disco = provider.fetch_discovery(fam.issuer, fam.http_factory)
    code = fam.issue_code("sub-1", "ann", "Анна", ["stools-analysts"], nonce="n1")
    tokens = provider.exchange_code(disco, settings, code, "verifier-xyz", fam.http_factory)
    claims = provider.verify_id_token(tokens["id_token"], disco, settings, "n1", fam.http_factory)
    assert claims["sub"] == "sub-1" and claims["groups"] == ["stools-analysts"]


def test_wrong_nonce_audience_or_key_is_rejected(fam: FakeProvider) -> None:
    settings = _settings(fam)
    disco = provider.fetch_discovery(fam.issuer, fam.http_factory)
    good = {"sub": "s", "preferred_username": "ann"}
    for token in (
        fam.id_token_for(good, nonce="other"),
        fam.id_token_for(good, nonce="n1", aud="someone-else"),
        FakeProvider().id_token_for(good, nonce="n1"),  # чужой ключ
    ):
        with pytest.raises(provider.ProviderError) as exc:
            provider.verify_id_token(token, disco, settings, "n1", fam.http_factory)
        assert exc.value.code == "oidc_token"


@pytest.mark.filterwarnings("ignore:The HMAC key")  # короткий секрет здесь намеренный
def test_forged_tokens_are_rejected(fam: FakeProvider) -> None:
    settings = _settings(fam)
    disco = provider.fetch_discovery(fam.issuer, fam.http_factory)
    good = {"sub": "s", "preferred_username": "ann"}
    now = int(time.time())
    forged = {
        "без подписи": fam.id_token_for(good, nonce="n1", alg="none"),
        "подписан секретом клиента": fam.id_token_for(
            good, nonce="n1", alg="HS256", key=fam.client_secret
        ),
        "без kid в заголовке": fam.id_token_for(good, nonce="n1", with_kid=False),
        "просрочен": fam.id_token_for({**good, "exp": now - 60}, nonce="n1"),
        "без sub": fam.id_token_for({"preferred_username": "ann"}, nonce="n1"),
        "чужой issuer": fam.id_token_for(good, nonce="n1", issuer="https://evil.test/realms/corp"),
    }
    for label, token in forged.items():
        with pytest.raises(provider.ProviderError) as exc:
            provider.verify_id_token(token, disco, settings, "n1", fam.http_factory)
        assert exc.value.code == "oidc_token", label


def test_unknown_kid_refetches_jwks_once(fam: FakeProvider) -> None:
    settings = _settings(fam)
    disco = provider.fetch_discovery(fam.issuer, fam.http_factory)
    provider.fetch_jwks(disco.jwks_uri, fam.http_factory)
    fam.rotate_key()
    token = fam.id_token_for({"sub": "s"}, nonce="n1")
    fam.calls.clear()
    claims = provider.verify_id_token(token, disco, settings, "n1", fam.http_factory)
    assert claims["sub"] == "s"
    assert [call for call in fam.calls if call.endswith("/certs")] == [
        "/realms/corp/protocol/openid-connect/certs"
    ]


def test_bad_token_response_is_oidc_token(fam: FakeProvider) -> None:
    settings = _settings(fam)
    disco = provider.fetch_discovery(fam.issuer, fam.http_factory)
    with pytest.raises(provider.ProviderError) as exc:
        provider.exchange_code(disco, settings, "no-such-code", "v", fam.http_factory)
    assert exc.value.code == "oidc_token"


def test_wrong_redirect_uri_is_rejected(fam: FakeProvider) -> None:
    settings = _settings(fam)
    disco = provider.fetch_discovery(fam.issuer, fam.http_factory)
    fam.redirect_uri = "https://stools.test/somewhere-else"
    code = fam.issue_code("s", "ann", "Анна", [], nonce="n1")
    with pytest.raises(provider.ProviderError) as exc:
        provider.exchange_code(disco, settings, code, "v", fam.http_factory)
    assert exc.value.code == "oidc_token"


def test_malformed_token_response_is_oidc_token(fam: FakeProvider) -> None:
    settings = _settings(fam)
    disco = provider.fetch_discovery(fam.issuer, fam.http_factory)
    code = fam.issue_code("s", "ann", "Анна", [], nonce="n1")
    fam.garbage.add("token")
    with pytest.raises(provider.ProviderError) as exc:
        provider.exchange_code(disco, settings, code, "v", fam.http_factory)
    assert exc.value.code == "oidc_token"
