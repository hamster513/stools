"""Подключение к базе знаний: секреты не показываются, пустые — не затирают прежние."""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.api.fake_kb import TOKEN, FakeKb

BODY = {"host": "mp.corp.local", "api_token": TOKEN}


def test_defaults_hide_secrets(auth_client: TestClient) -> None:
    body = auth_client.get("/api/siem/kb").json()
    assert body["host"] == "" and body["kb_port"] == 8091 and body["verify_tls"] is False
    assert body["api_token_set"] is False and body["configured"] is False
    assert "api_token" not in body


def test_put_keeps_secrets_when_empty(auth_client: TestClient, db_session: Any) -> None:
    r = auth_client.put("/api/siem/kb", json=BODY)
    assert r.status_code == 200, r.text
    assert r.json()["configured"] is True and r.json()["api_token_set"] is True

    r = auth_client.put("/api/siem/kb", json={**BODY, "api_token": "", "kb_port": 8091})
    assert r.status_code == 200, r.text
    assert r.json()["api_token_set"] is True

    from api.db.models import AppSetting
    from api.modules.siem.services.kb_settings import load_connection

    db_session.expire_all()
    stored = db_session.get(AppSetting, "siem_kb").value_json
    fields = json.loads(stored)
    assert fields["api_token"].startswith("enc:v1:") and TOKEN not in fields["api_token"]
    unsealed = load_connection(db_session).unsealed()
    assert unsealed.api_token == TOKEN


def test_address_change_requires_secrets_again(auth_client: TestClient) -> None:
    assert auth_client.put("/api/siem/kb", json=BODY).status_code == 200
    r = auth_client.put("/api/siem/kb", json={**BODY, "host": "other.corp.local", "api_token": ""})
    assert r.status_code == 422 and "заново" in r.json()["detail"]
    # С новым токеном смена адреса проходит.
    assert auth_client.put("/api/siem/kb", json={**BODY, "host": "other.corp.local"}).status_code == 200


def test_bad_host_rejected(auth_client: TestClient) -> None:
    assert auth_client.put("/api/siem/kb", json={**BODY, "host": "https://mp.corp.local/x"}).status_code == 422


def test_auditor_reads_but_cannot_save(client_as: Callable[[str], TestClient]) -> None:
    auditor = client_as("auditor")
    assert auditor.get("/api/siem/kb").status_code == 200
    assert auditor.put("/api/siem/kb", json=BODY).status_code == 403


def test_test_requires_configured_connection(auth_client: TestClient) -> None:
    assert auth_client.post("/api/siem/kb/test").status_code == 400


def test_test_reports_version_and_database(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeKb()
    monkeypatch.setattr("api.modules.siem.routers.kb.make_client", fake.http_factory)
    assert auth_client.put("/api/siem/kb", json=BODY).status_code == 200
    body = auth_client.post("/api/siem/kb/test").json()
    assert body == {
        "ok": True, "message": "база знаний 27.1.1234 отвечает, БД контента: Default",
        "version": "27.1.1234", "database": "Default",
    }
    assert fake.calls[0].headers["Authorization"] == f"Bearer {TOKEN}"


def test_test_reports_error_class_only(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeKb()
    fake.unauthorized = True
    monkeypatch.setattr("api.modules.siem.routers.kb.make_client", fake.http_factory)
    auth_client.put("/api/siem/kb", json=BODY)
    body = auth_client.post("/api/siem/kb/test").json()
    assert body["ok"] is False and body["message"] == "вход отклонён"
    assert "mp.corp.local" not in body["message"]
