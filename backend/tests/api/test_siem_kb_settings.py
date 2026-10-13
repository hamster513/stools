"""Подключение к базе знаний: секреты не показываются, пустые — не затирают прежние."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi.testclient import TestClient

BODY = {"host": "mp.corp.local", "username": "svc", "password": "p1", "client_secret": "s1"}


def test_defaults_hide_secrets(auth_client: TestClient) -> None:
    body = auth_client.get("/api/siem/kb").json()
    assert body["host"] == "" and body["kb_port"] == 8091 and body["verify_tls"] is False
    assert body["password_set"] is False and body["client_secret_set"] is False and body["configured"] is False
    assert "password" not in body and "client_secret" not in body


def test_put_keeps_secrets_when_empty(auth_client: TestClient, db_session: Any) -> None:
    r = auth_client.put("/api/siem/kb", json=BODY)
    assert r.status_code == 200, r.text
    assert r.json()["configured"] is True and r.json()["password_set"] is True

    r = auth_client.put("/api/siem/kb", json={**BODY, "password": "", "client_secret": "", "kb_port": 8091})
    assert r.status_code == 200, r.text
    assert r.json()["password_set"] is True and r.json()["client_secret_set"] is True

    from api.db.models import AppSetting
    from api.modules.siem.services.kb_settings import load_connection

    db_session.expire_all()
    stored = db_session.get(AppSetting, "siem_kb").value_json
    assert "p1" not in stored and "s1" not in stored and "enc:v1:" in stored
    unsealed = load_connection(db_session).unsealed()
    assert unsealed.password == "p1" and unsealed.client_secret == "s1"


def test_address_change_requires_secrets_again(auth_client: TestClient) -> None:
    assert auth_client.put("/api/siem/kb", json=BODY).status_code == 200
    r = auth_client.put("/api/siem/kb", json={**BODY, "host": "other.corp.local", "password": "", "client_secret": ""})
    assert r.status_code == 422 and "заново" in r.json()["detail"]
    # С новыми секретами смена адреса проходит.
    assert auth_client.put("/api/siem/kb", json={**BODY, "host": "other.corp.local"}).status_code == 200


def test_bad_host_rejected(auth_client: TestClient) -> None:
    assert auth_client.put("/api/siem/kb", json={**BODY, "host": "https://mp.corp.local/x"}).status_code == 422


def test_auditor_reads_but_cannot_save(client_as: Callable[[str], TestClient]) -> None:
    auditor = client_as("auditor")
    assert auditor.get("/api/siem/kb").status_code == 200
    assert auditor.put("/api/siem/kb", json=BODY).status_code == 403
