"""Настройки OIDC: маска секрета, проверка полноты при включении, проверка связи."""
from __future__ import annotations

from fastapi.testclient import TestClient

from tests.api.fake_oidc import FakeProvider

FULL = {
    "enabled": False,
    "display_name": "Avanpost",
    "public_url": "https://stools.example.ru/",
    "issuer_url": "https://fam.example.ru/realms/corp",
    "client_id": "stools",
    "client_secret": "s3cr3t",
    "scopes": "openid profile email groups",
    "groups_claim": "groups",
    "login_claim": "preferred_username",
    "name_claim": "name",
}


def _add_oidc_group(client: TestClient) -> None:
    role_id = next(r["id"] for r in client.get("/api/settings/roles").json() if r["name"] == "Аналитик")
    response = client.post(
        "/api/settings/groups",
        json={"name": "stools-analysts", "source": "oidc", "external_name": "stools-analysts", "role_id": role_id},
    )
    assert response.status_code == 201, response.text


def test_defaults_and_redirect_uri(auth_client: TestClient) -> None:
    body = auth_client.get("/api/settings/oidc").json()
    assert body["enabled"] is False and body["client_secret"] == "" and "group_roles" not in body
    assert auth_client.put("/api/settings/oidc", json=FULL).status_code == 204
    body = auth_client.get("/api/settings/oidc").json()
    assert body["client_secret"] == "••••"
    assert body["redirect_uri"] == "https://stools.example.ru/api/auth/oidc/callback"
    assert body["has_secret"] is True


def test_masked_or_empty_secret_does_not_erase_the_stored_one(auth_client: TestClient) -> None:
    auth_client.put("/api/settings/oidc", json=FULL)
    assert auth_client.put("/api/settings/oidc", json={**FULL, "client_secret": "••••"}).status_code == 204
    assert auth_client.put("/api/settings/oidc", json={**FULL, "client_secret": ""}).status_code == 204
    from api.crypto import decrypt
    from api.db.base import get_sessionmaker
    from api.oidc.settings import load_oidc

    with get_sessionmaker()() as db:
        assert decrypt(load_oidc(db).client_secret) == "s3cr3t"


def test_client_secret_is_encrypted_at_rest(auth_client: TestClient) -> None:
    import json

    from api.db.base import get_sessionmaker
    from api.db.models import AppSetting

    assert auth_client.put("/api/settings/oidc", json=FULL).status_code == 204
    with get_sessionmaker()() as db:
        stored = json.loads(db.get(AppSetting, "oidc").value_json)
    assert stored["client_secret"].startswith("enc:v1:") and "s3cr3t" not in stored["client_secret"]


def test_enabling_requires_complete_settings_and_an_oidc_group(auth_client: TestClient) -> None:
    response = auth_client.put("/api/settings/oidc", json={**FULL, "enabled": True, "issuer_url": ""})
    assert response.status_code == 422
    assert "issuer_url" in response.json()["detail"]
    response = auth_client.put("/api/settings/oidc", json={**FULL, "enabled": True})
    assert response.status_code == 422
    assert "нет ни одной группы из OIDC" in response.json()["detail"]
    _add_oidc_group(auth_client)
    assert auth_client.put("/api/settings/oidc", json={**FULL, "enabled": True}).status_code == 204
    assert auth_client.get("/api/auth/oidc/status").json()["enabled"] is True


def test_plain_http_is_rejected_outside_localhost(auth_client: TestClient) -> None:
    insecure = {**FULL, "issuer_url": "http://fam.example.ru/realms/corp"}
    assert auth_client.put("/api/settings/oidc", json=insecure).status_code == 422
    local = {**FULL, "public_url": "http://localhost:8080", "issuer_url": "http://127.0.0.1:8081"}
    assert auth_client.put("/api/settings/oidc", json=local).status_code == 204


def test_old_group_roles_in_the_body_are_ignored(auth_client: TestClient) -> None:
    """Сопоставление «группа → роль» заменено группами из OIDC: старое поле в теле не ошибка и не хранится."""
    old = {**FULL, "group_roles": [{"group": "x", "role": "boss"}]}
    assert auth_client.put("/api/settings/oidc", json=old).status_code == 204
    assert "group_roles" not in auth_client.get("/api/settings/oidc").json()


def test_only_admin_reads_and_writes(client_as) -> None:  # type: ignore[no-untyped-def]
    assert client_as("analyst").get("/api/settings/oidc").status_code == 403
    assert client_as("auditor").put("/api/settings/oidc", json=FULL).status_code == 403


def test_saving_settings_invalidates_discovery_cache(auth_client: TestClient, fam: FakeProvider) -> None:
    """Иначе смена issuer_url ещё десять минут отвечала бы старым discovery."""
    from api.oidc.provider import fetch_discovery

    fetch_discovery(fam.issuer, fam.http_factory)
    fetch_discovery(fam.issuer, fam.http_factory)
    assert len(fam.calls) == 1  # второй вызов пришёлся на кэш

    assert auth_client.put("/api/settings/oidc", json=FULL).status_code == 204

    fetch_discovery(fam.issuer, fam.http_factory)
    assert len(fam.calls) == 2  # кэш сброшен сохранением — снова сходили в сеть


def test_check_reports_endpoints_and_keys(auth_client: TestClient, fam: FakeProvider) -> None:
    result = auth_client.post("/api/settings/oidc/test", json={"issuer_url": fam.issuer}).json()
    assert result["ok"] is True and result["keys"] == 1 and result["endpoints"]["token"].endswith("/token")
    fam.down = True
    from api.oidc import provider

    provider.invalidate_cache()
    result = auth_client.post("/api/settings/oidc/test", json={"issuer_url": fam.issuer}).json()
    assert result["ok"] is False and result["error"]


def test_check_rejects_insecure_issuer_url(auth_client: TestClient) -> None:
    response = auth_client.post("/api/settings/oidc/test", json={"issuer_url": "http://fam.example.ru"})
    assert response.status_code == 422
