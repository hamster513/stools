"""GET /api/settings/data-status: сводка свежести данных всех модулей."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from api.modules import MODULE_ROUTERS
from api.platform import data_status
from api.platform.data_status import DataItem, register_data_status, registered_modules


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


@pytest.mark.xfail(strict=True, reason="провайдеры появятся в задаче 2")
def test_all_modules_registered() -> None:
    assert registered_modules() == {r.prefix.split("/")[2] for r in MODULE_ROUTERS}
