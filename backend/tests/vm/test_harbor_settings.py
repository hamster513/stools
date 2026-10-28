"""Подключение к Harbor: настройки в app_setting['vm_harbor'], секрет робота, проверка."""
from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from api.hosts import LOGIN_REJECTED
from api.modules.vm.services.harbor_settings import SECRETS_AGAIN

FIRST = {
    "url": "http://harbor.example.test:8082",
    "robot_name": "robot$reader",
    "robot_secret": "s3cret",
    "verify_tls": False,
    "projects": ["library"],
    "tags_per_repo": 5,
}


def _raw() -> dict[str, Any]:
    from api.db.base import get_sessionmaker
    from api.db.models import AppSetting

    with get_sessionmaker()() as db:
        return dict(json.loads(db.get(AppSetting, "vm_harbor").value_json))


def test_get_default_not_configured(auth_client: TestClient) -> None:
    r = auth_client.get("/api/vm/harbor")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["configured"] is False
    assert body["robot_secret_set"] is False
    assert body["tags_per_repo"] == 10
    assert "robot_secret" not in body


def test_put_stores_encrypted_secret(auth_client: TestClient) -> None:
    r = auth_client.put("/api/vm/harbor", json=FIRST)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["robot_secret_set"] is True and body["configured"] is True
    assert "robot_secret" not in body
    assert "s3cret" not in r.text
    assert body["projects"] == ["library"] and body["tags_per_repo"] == 5
    assert _raw()["robot_secret"].startswith("enc:v1:")
    assert auth_client.get("/api/vm/harbor").json()["robot_secret_set"] is True


def test_put_empty_secret_keeps_old(auth_client: TestClient) -> None:
    assert auth_client.put("/api/vm/harbor", json=FIRST).status_code == 200
    r = auth_client.put("/api/vm/harbor", json={**FIRST, "robot_secret": "", "tags_per_repo": 7})
    assert r.status_code == 200, r.text
    assert r.json()["robot_secret_set"] is True and r.json()["tags_per_repo"] == 7

    from api.crypto import decrypt

    assert decrypt(_raw()["robot_secret"]) == "s3cret"


def test_url_change_requires_secret_again(auth_client: TestClient) -> None:
    assert auth_client.put("/api/vm/harbor", json=FIRST).status_code == 200
    r = auth_client.put("/api/vm/harbor", json={**FIRST, "url": "http://other.example.test", "robot_secret": ""})
    assert r.status_code == 422
    assert r.json()["detail"] == SECRETS_AGAIN
    ok = auth_client.put("/api/vm/harbor", json={**FIRST, "url": "http://other.example.test", "robot_secret": "n"})
    assert ok.status_code == 200, ok.text


@pytest.mark.parametrize("url", ["ftp://x", "http://x/", "http://" + "a" * 600])
def test_bad_url_rejected(auth_client: TestClient, url: str) -> None:
    assert auth_client.put("/api/vm/harbor", json={**FIRST, "url": url}).status_code == 422


@pytest.mark.parametrize(
    "patch",
    [
        {"projects": ["Bad Name"]},
        {"projects": ["a/b"]},
        {"projects": [""]},
        {"tags_per_repo": 0},
        {"tags_per_repo": 101},
        {"robot_name": "r" * 129},
    ],
)
def test_bad_fields_rejected(auth_client: TestClient, patch: dict[str, Any]) -> None:
    assert auth_client.put("/api/vm/harbor", json={**FIRST, **patch}).status_code == 422


def test_test_requires_configured(auth_client: TestClient) -> None:
    assert auth_client.post("/api/vm/harbor/test").status_code == 400


def test_test_reports_class_only(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from api.modules.vm.routers import harbor as router

    assert auth_client.put("/api/vm/harbor", json=FIRST).status_code == 200
    state = {"deny": True}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/systeminfo"):
            return httpx.Response(200, json={"harbor_version": "v2.11.0-abcdef"})
        if state["deny"]:
            return httpx.Response(401, text="secret details harbor.example.test")
        return httpx.Response(200, json=[])

    monkeypatch.setattr(
        router, "make_harbor_client", lambda conn, timeout=60.0: httpx.Client(transport=httpx.MockTransport(handler))
    )

    r = auth_client.post("/api/vm/harbor/test")
    assert r.status_code == 200, r.text
    assert r.json() == {"ok": False, "message": LOGIN_REJECTED}

    state["deny"] = False
    r = auth_client.post("/api/vm/harbor/test")
    assert r.json()["ok"] is True and "v2.11.0" in r.json()["message"]
