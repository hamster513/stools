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
