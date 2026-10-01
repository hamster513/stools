"""Каркас модуля: роутер подключён, задачи читаются любой ролью."""
from __future__ import annotations

from collections.abc import Callable

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.modules.assets.models import AssetZone


def test_jobs_list_is_empty_for_auditor(client_as: Callable[[str], TestClient]) -> None:
    response = client_as("auditor").get("/api/assets/jobs")
    assert response.status_code == 200, response.text
    assert response.json() == []


def test_jobs_require_session(client: TestClient) -> None:
    assert client.get("/api/assets/jobs").status_code == 401


def test_zone_reference_is_a_table(db_session: Session) -> None:
    """Справочник зон — таблица миграции; предустановленные строки очищает TRUNCATE
    между тестами, поэтому здесь проверяется только, что запись в неё работает."""
    db_session.add(AssetZone(name="Lab", title="Стенд", description=""))
    db_session.commit()
    assert db_session.get(AssetZone, "Lab") is not None
