"""GET /api/settings/data-status: сводка свежести данных всех модулей."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from api.modules import MODULE_ROUTERS
from api.platform import data_status
from api.platform.data_status import DataItem, collect, register_data_status, registered_modules


def test_data_status_returns_items(auth_client: TestClient) -> None:
    response = auth_client.get("/api/settings/data-status")
    assert response.status_code == 200, response.text
    assert isinstance(response.json()["items"], list)


def test_data_status_open_to_auditor(client_as: Callable[[str], TestClient]) -> None:
    assert client_as("auditor").get("/api/settings/data-status").status_code == 200


def test_data_status_serializes_item_and_provider_error(
    auth_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(data_status, "_PROVIDERS", {})
    when = dt.datetime(2026, 10, 1, 12, 0, tzinfo=dt.UTC)

    def broken(db: object) -> list[DataItem]:
        raise RuntimeError("boom")

    register_data_status("aaa", lambda db: [DataItem("aaa", "k", "Заголовок", "reference", when, "fresh", "src", "d", "#a")])
    register_data_status("bbb", broken)
    items = auth_client.get("/api/settings/data-status").json()["items"]
    assert items[0] == {
        "module": "aaa", "key": "k", "title": "Заголовок", "kind": "reference",
        "updated_at": when.isoformat(), "state": "fresh", "source": "src", "detail": "d", "anchor": "#a",
    }
    assert items[1]["module"] == "bbb" and items[1]["state"] == "missing"
    assert items[1]["updated_at"] is None and items[1]["detail"] == "ошибка: RuntimeError"


def test_collect_survives_db_error_in_provider(db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ошибка SQL в одном провайдере не должна ломать сессию для следующих."""
    monkeypatch.setattr(data_status, "_PROVIDERS", {})

    def broken(db: Any) -> list[DataItem]:
        db.execute(text("SELECT * FROM no_such_table"))
        return []

    def healthy(db: Any) -> list[DataItem]:
        db.execute(text("SELECT 1"))
        return [DataItem("bbb", "k", "T", "source", None, "fresh", None, "", "")]

    register_data_status("aaa", broken)
    register_data_status("bbb", healthy)
    items = collect(db_session)
    assert [(i.module, i.key, i.state, i.detail) for i in items] == [
        ("aaa", "error", "missing", "ошибка: ProgrammingError"),
        ("bbb", "k", "fresh", ""),
    ]


@pytest.mark.xfail(strict=True, reason="провайдеры появятся в задаче 2")
def test_all_modules_registered() -> None:
    assert registered_modules() == {r.prefix.split("/")[2] for r in MODULE_ROUTERS}
