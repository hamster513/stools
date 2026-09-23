"""`/docs`, `/redoc`, `/openapi.json` закрыты по умолчанию (H4/L10 аудита
2026-09-23): инструмент хранит инвентарь инфраструктуры, схема API наружу
не нужна. Включаются только флагом `Settings.expose_docs` для отладки.
"""
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient


def test_docs_closed_by_default(client: TestClient) -> None:
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_docs_open_with_flag(app_settings: Any, monkeypatch: Any) -> None:
    """`docs_url` и другие задаются один раз при создании приложения
    (api/main.py), поэтому здесь собирается отдельный экземпляр через
    `create_app()`, а не переиспользуется `client` (тот собран заранее
    с флагом по умолчанию)."""
    monkeypatch.setenv("STOOLS_EXPOSE_DOCS", "true")
    from api.main import create_app

    with TestClient(create_app()) as client:
        assert client.get("/docs").status_code == 200
        assert client.get("/redoc").status_code == 200
        assert client.get("/openapi.json").status_code == 200
