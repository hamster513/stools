"""Многозначные фасеты списка находок AD (общий код с KSC, `collector_routes`): внутри фасета —
«ИЛИ», поэтому два значения дают сумму итогов по каждому порознь."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from tests.ad.synthetic import build_export


def _snapshot(client: TestClient) -> int:
    r = client.post("/api/ad/snapshots/file", files={"file": ("ad.json", json.dumps(build_export()).encode(), "application/json")})
    assert r.status_code == 202, r.text
    assert client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()["status"] == "done"
    domain_id = client.get("/api/ad/domains").json()[0]["id"]
    return int(client.get(f"/api/ad/snapshots?domain_id={domain_id}").json()[0]["id"])


@pytest.mark.parametrize(("param", "a", "b"), [
    ("check", "Kerberoast", "DCSync"),
    ("severity", "Critical", "High"),
    ("delta", "new", "same"),
    ("assignee", "me", "none"),
])
def test_two_values_sum_up(auth_client: TestClient, param: str, a: str, b: str) -> None:
    snap = _snapshot(auth_client)
    url = f"/api/ad/snapshots/{snap}/findings?{param}="

    def total(v: str) -> int:
        r = auth_client.get(url + v)
        assert r.status_code == 200, r.text
        return int(r.json()["total"])

    assert total(f"{a},{b}") == total(a) + total(b) > 0


def test_all_means_no_filter(auth_client: TestClient) -> None:
    snap = _snapshot(auth_client)
    full = auth_client.get(f"/api/ad/snapshots/{snap}/findings").json()["total"]
    assert auth_client.get(f"/api/ad/snapshots/{snap}/findings?check=all").json()["total"] == full
    assert auth_client.get(f"/api/ad/snapshots/{snap}/findings?severity=all&assignee=all").json()["total"] == full


def test_unknown_delta_in_list_is_rejected(auth_client: TestClient) -> None:
    snap = _snapshot(auth_client)
    assert auth_client.get(f"/api/ad/snapshots/{snap}/findings?delta=new,bogus").status_code == 422
