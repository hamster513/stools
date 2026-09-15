"""Вердикт находки: обязательное обоснование при accepted, и переживание
нового снапшота — статус привязан к (object_uuid, kind, field, value_hash),
а не к id находки конкретного снапшота (спека §4.2)."""
from __future__ import annotations

from fastapi.testclient import TestClient

from tests.api.conftest import upload_and_wait


def _kind1_finding_id(client: TestClient, snapshot_id: int) -> int:
    response = client.get("/api/siem/findings", params={"snapshot_id": snapshot_id, "kind": 1})
    items = response.json()["items"]
    assert items
    return int(items[0]["id"])


def test_accepted_without_reason_is_422(auth_client: TestClient, snapshot_id: int) -> None:
    finding_id = _kind1_finding_id(auth_client, snapshot_id)
    response = auth_client.post(
        "/api/siem/findings/verdict", json={"finding_id": finding_id, "status": "accepted"}
    )
    assert response.status_code == 422


def test_accepted_with_reason_updates_status(auth_client: TestClient, snapshot_id: int) -> None:
    finding_id = _kind1_finding_id(auth_client, snapshot_id)
    response = auth_client.post(
        "/api/siem/findings/verdict",
        json={"finding_id": finding_id, "status": "accepted", "reason": "проверено вручную"},
    )
    assert response.status_code == 204

    listing = auth_client.get(
        "/api/siem/findings", params={"snapshot_id": snapshot_id, "kind": 1}
    ).json()
    item = next(i for i in listing["items"] if i["id"] == finding_id)
    assert item["status"] == "accepted"

    # Без фильтра по kind в фасете видно обе находки: класс 1 принят,
    # класс 2 остался open.
    unfiltered = auth_client.get(
        "/api/siem/findings", params={"snapshot_id": snapshot_id}
    ).json()
    assert unfiltered["facets"]["status"] == {"open": 1, "accepted": 1, "in_progress": 0}


def test_in_progress_does_not_require_reason(auth_client: TestClient, snapshot_id: int) -> None:
    finding_id = _kind1_finding_id(auth_client, snapshot_id)
    response = auth_client.post(
        "/api/siem/findings/verdict", json={"finding_id": finding_id, "status": "in_progress"}
    )
    assert response.status_code == 204


def test_verdict_survives_new_snapshot(
    auth_client: TestClient, snapshot_id: int, kb_zip_bytes_v2: bytes
) -> None:
    finding_id = _kind1_finding_id(auth_client, snapshot_id)
    accept = auth_client.post(
        "/api/siem/findings/verdict",
        json={"finding_id": finding_id, "status": "accepted", "reason": "штатное поведение"},
    )
    assert accept.status_code == 204

    body = upload_and_wait(auth_client, kb_zip_bytes_v2, filename="kb2.zip")
    second_id = body["snapshot_id"]
    assert second_id != snapshot_id

    listing = auth_client.get(
        "/api/siem/findings", params={"snapshot_id": second_id, "kind": 1}
    ).json()
    assert listing["items"], "находка класса 1 должна остаться и во втором снапшоте"
    # id находки другой (новая строка в новом снапшоте), но статус —
    # тот же самый вердикт, найденный по (object_uuid, kind, field, value_hash).
    assert listing["items"][0]["status"] == "accepted"


def test_open_clears_stored_verdict(auth_client: TestClient, snapshot_id: int) -> None:
    finding_id = _kind1_finding_id(auth_client, snapshot_id)
    auth_client.post(
        "/api/siem/findings/verdict",
        json={"finding_id": finding_id, "status": "accepted", "reason": "временно"},
    )
    reset = auth_client.post(
        "/api/siem/findings/verdict", json={"finding_id": finding_id, "status": "open"}
    )
    assert reset.status_code == 204

    listing = auth_client.get(
        "/api/siem/findings", params={"snapshot_id": snapshot_id, "kind": 1}
    ).json()
    assert listing["items"][0]["status"] == "open"
