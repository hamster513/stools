"""Решение по находке SIEM — общий статус платформы: обоснование обязательно
при «Принят риск», и статус переживает новый снапшот — он привязан к ключу
находки (object_uuid, kind, field, значение), а не к id находки конкретного
снапшота (спека §4.2, спека статусов §3)."""
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from tests.api.conftest import upload_and_wait


def _kind1(client: TestClient, snapshot_id: int, **params: Any) -> dict[str, Any]:
    response = client.get("/api/siem/findings", params={"snapshot_id": snapshot_id, "kind": 1, **params})
    items = response.json()["items"]
    assert items
    return dict(items[0])


def _put(client: TestClient, key: str, **change: Any) -> Any:
    return client.put("/api/findings/state", json={"module": "siem", "scope_id": 0, "key": key, **change})


def test_risk_accepted_without_reason_is_422(auth_client: TestClient, snapshot_id: int) -> None:
    finding = _kind1(auth_client, snapshot_id)
    assert _put(auth_client, finding["key"], status="risk_accepted").status_code == 422


def test_risk_accepted_with_reason_updates_status(auth_client: TestClient, snapshot_id: int) -> None:
    finding = _kind1(auth_client, snapshot_id)
    response = _put(auth_client, finding["key"], status="risk_accepted", comment="проверено вручную")
    assert response.status_code == 200, response.text

    item = _kind1(auth_client, snapshot_id, status="all")
    assert item["id"] == finding["id"] and item["status"] == "risk_accepted"

    # Без фильтра по kind в фасете видно обе находки: класс 1 — принят риск,
    # класс 2 остался новым.
    unfiltered = auth_client.get("/api/siem/findings", params={"snapshot_id": snapshot_id}).json()
    assert unfiltered["facets"]["status"] == {
        "new": 1, "in_work": 0, "risk_accepted": 1, "false_positive": 0, "fixed": 0, "resolved": 0, "reopened": 0,
    }


def test_in_work_does_not_require_reason(auth_client: TestClient, snapshot_id: int) -> None:
    finding = _kind1(auth_client, snapshot_id)
    response = _put(auth_client, finding["key"], status="in_work")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "in_work"


def test_status_survives_new_snapshot(
    auth_client: TestClient, snapshot_id: int, kb_zip_bytes_v2: bytes
) -> None:
    finding = _kind1(auth_client, snapshot_id)
    accept = _put(auth_client, finding["key"], status="risk_accepted", comment="штатное поведение")
    assert accept.status_code == 200, accept.text

    body = upload_and_wait(auth_client, kb_zip_bytes_v2, filename="kb2.zip")
    second_id = body["snapshot_id"]
    assert second_id != snapshot_id

    item = _kind1(auth_client, second_id, status="all")
    # id находки другой (новая строка в новом снапшоте), но ключ и статус —
    # те же: решение найдено по (object_uuid, kind, field, значение).
    assert item["id"] != finding["id"]
    assert item["key"] == finding["key"] and item["status"] == "risk_accepted"


def test_back_to_new_reopens_the_finding(auth_client: TestClient, snapshot_id: int) -> None:
    finding = _kind1(auth_client, snapshot_id)
    _put(auth_client, finding["key"], status="risk_accepted", comment="временно")
    reset = _put(auth_client, finding["key"], status="new")
    assert reset.status_code == 200, reset.text

    assert _kind1(auth_client, snapshot_id)["status"] == "new"
