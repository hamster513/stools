"""Настройки модели живут в общих настройках; SIEM хранит только своё."""
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from api.llm_settings import load_llm


def test_llm_roundtrip(auth_client: TestClient, db_session: Any) -> None:
    body = auth_client.get("/api/settings/llm").json()
    assert body["base_url"] == "" and body["enabled"] is True
    body["base_url"] = "http://ollama:11434"
    body["enabled"] = True
    assert auth_client.put("/api/settings/llm", json=body).status_code == 204
    assert auth_client.get("/api/settings/llm").json()["base_url"] == "http://ollama:11434"
    assert load_llm(db_session).configured is True


def test_test_endpoint_reports_unreachable_model(auth_client: TestClient) -> None:
    result = auth_client.post("/api/settings/llm/test", json={"base_url": "http://127.0.0.1:1", "model": "x", "timeout": 1}).json()
    assert result["ok"] is False and result["error"]


def test_siem_settings_keep_only_attack_section(auth_client: TestClient) -> None:
    body = auth_client.get("/api/siem/settings").json()
    assert set(body) == {"attack"}
    assert auth_client.put("/api/siem/settings", json={"attack": {"top_k": 20}}).status_code == 204
    assert auth_client.get("/api/siem/settings").json()["attack"]["top_k"] == 20
    assert auth_client.post("/api/siem/settings/test-llm", json={}).status_code == 404


def test_models_use_unsaved_address_and_preserve_settings(auth_client, monkeypatch, db_session):
    import io
    import json

    from api.platform.routers import llm

    calls = []
    def get(url, timeout):
        calls.append((url, timeout))
        return io.BytesIO(json.dumps({"models": [{"name": "bge-m3:latest"}, {"name": "qwen3:8b"}, {"name": "qwen3:8b"}]}).encode())
    monkeypatch.setattr(llm.urllib.request, "urlopen", get)
    before = load_llm(db_session)
    result = auth_client.post("/api/settings/llm/models", json={"base_url": " http://ollama:11434/ "})
    assert result.status_code == 200
    assert result.json() == {"models": ["bge-m3:latest", "qwen3:8b"]}
    assert calls == [("http://ollama:11434/api/tags", 10)]
    assert load_llm(db_session) == before


def test_models_reject_invalid_response_and_non_admin(auth_client, client_as, monkeypatch):
    import io

    from api.platform.routers import llm

    url = "/api/settings/llm/models"
    assert client_as("auditor").post(url, json={"base_url": "http://ollama:11434"}).status_code == 403
    assert auth_client.post(url, json={"base_url": "file:///etc/passwd"}).status_code == 422
    monkeypatch.setattr(llm.urllib.request, "urlopen", lambda *a, **kw: io.BytesIO(b'{"models":null}'))
    assert auth_client.post(url, json={"base_url": "http://ollama:11434"}).status_code == 502
    monkeypatch.setattr(llm.urllib.request, "urlopen", lambda *a, **kw: io.BytesIO(b'{"models":[]}'))
    assert auth_client.post(url, json={"base_url": "http://ollama:11434"}).json() == {"models": []}
