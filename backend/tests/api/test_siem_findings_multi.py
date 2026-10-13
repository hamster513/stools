"""Многозначные фасеты находок SIEM: внутри фасета — «ИЛИ», два значения дают сумму итогов
по каждому порознь; `all` — фильтра нет."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

URL = "/api/siem/findings"


def _top_two(client: TestClient, snapshot_id: int, facet: str) -> tuple[str, str]:
    """Два самых частых значения фасета на синтетике — без жёстко зашитых подписей."""
    counts = client.get(URL, params={"snapshot_id": snapshot_id}).json()["facets"][facet]
    a, b = sorted(counts, key=lambda k: -counts[k])[:2]
    return a, b


@pytest.mark.parametrize("facet", ["kind", "object_type", "polarity", "shape", "field", "assignee"])
def test_two_values_sum_up(auth_client: TestClient, snapshot_id: int, facet: str) -> None:
    a, b = ("me", "none") if facet == "assignee" else _top_two(auth_client, snapshot_id, facet)

    def total(v: str) -> int:
        r = auth_client.get(URL, params={"snapshot_id": snapshot_id, facet: v})
        assert r.status_code == 200, r.text
        return int(r.json()["total"])

    assert total(f"{a},{b}") == total(a) + total(b) > 0


def test_kind_list_and_all(auth_client: TestClient, snapshot_id: int) -> None:
    full = auth_client.get(URL, params={"snapshot_id": snapshot_id}).json()["total"]
    assert auth_client.get(URL, params={"snapshot_id": snapshot_id, "kind": "1,2"}).json()["total"] == full == 2
    assert auth_client.get(URL, params={"snapshot_id": snapshot_id, "kind": "all", "polarity": "all"}).json()["total"] == full
    assert auth_client.get(URL, params={"snapshot_id": snapshot_id, "kind": "1,x"}).status_code == 422
