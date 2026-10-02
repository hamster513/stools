"""Фасеты /api/siem/findings: считаются по остальным активным фильтрам, но не
по своему собственному измерению (контракт, «Находки»)."""
from __future__ import annotations

from fastapi.testclient import TestClient


def test_facets_present_all_known_values_with_zero_counts(
    auth_client: TestClient, snapshot_id: int
) -> None:
    response = auth_client.get("/api/siem/findings", params={"snapshot_id": snapshot_id})
    assert response.status_code == 200
    facets = response.json()["facets"]

    assert facets["kind"] == {"1": 1, "2": 1, "3": 0, "4": 0, "5": 0}
    assert facets["status"] == {
        "new": 2, "in_work": 0, "risk_accepted": 0, "false_positive": 0, "fixed": 0, "resolved": 0, "reopened": 0,
    }
    assert set(facets["in_table"]) == {"true", "false"}
    assert facets["in_table"]["true"] == 1
    assert facets["in_table"]["false"] == 1


def test_facet_does_not_collapse_to_selected_value(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Выбрав kind=1, фасет по kind обязан по-прежнему показывать оба класса —
    иначе счётчик всегда показывал бы только выбранное значение."""
    response = auth_client.get(
        "/api/siem/findings", params={"snapshot_id": snapshot_id, "kind": 1}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert all(item["kind"] == 1 for item in body["items"])
    # Фасет по kind не фильтруется по себе же — оба класса всё ещё видны.
    assert body["facets"]["kind"] == {"1": 1, "2": 1, "3": 0, "4": 0, "5": 0}
    # А вот фасет по object_type уже учитывает kind=1 (единственная другая
    # активная фильтрация здесь) — оба измерения независимы.
    assert body["facets"]["object_type"]["correlation"] == 1


def test_q_filters_by_object_name(auth_client: TestClient, snapshot_id: int) -> None:
    response = auth_client.get(
        "/api/siem/findings", params={"snapshot_id": snapshot_id, "q": "Impacket"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["object_name"] == "DEMO_HC_002_029_Impacket"
