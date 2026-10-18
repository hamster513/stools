"""Многозначные фасеты списка находок AD (общий код с KSC, `collector_routes`): значения — повтором
ключа, внутри фасета «ИЛИ», поэтому два значения дают сумму итогов по каждому порознь."""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.ad.synthetic import NOW, build_export
from tests.api.conftest import TEST_LOGIN


def _upload(client: TestClient, raw: dict[str, Any]) -> None:
    r = client.post("/api/ad/snapshots/file", files={"file": ("ad.json", json.dumps(raw).encode(), "application/json")})
    assert r.status_code == 202, r.text
    assert client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()["status"] == "done"


def _snapshot(client: TestClient) -> int:
    """Два снапшота (во втором — новый Kerberoast, чтобы у `delta` было и `new`, и `same`), одна
    находка назначена вызывающему — у `assignee` есть и `me`, и `none`."""
    _upload(client, build_export())
    later = build_export(now=NOW + dt.timedelta(days=7))
    for o in later["objects"]:
        if o.get("sam") == "helpdesk":
            o["spn"] = ["HTTP/help.corp.local"]
    _upload(client, later)
    domain_id = client.get("/api/ad/domains").json()[0]["id"]
    snap = int(client.get(f"/api/ad/snapshots?domain_id={domain_id}").json()[0]["id"])
    key = client.get(f"/api/ad/snapshots/{snap}/findings", params={"check": "DCSync"}).json()["items"][0]["key"]
    r = client.put("/api/findings/state", json={"module": "ad", "scope_id": domain_id, "key": key,
                                                "status": "in_work", "assignee": TEST_LOGIN})
    assert r.status_code == 200, r.text
    return snap


@pytest.mark.parametrize(("param", "a", "b"), [
    ("check", "Kerberoast", "DCSync"),
    ("severity", "Critical", "High"),
    ("delta", "new", "same"),
    ("assignee", "me", "none"),
])
def test_two_values_sum_up(auth_client: TestClient, param: str, a: str, b: str) -> None:
    snap = _snapshot(auth_client)

    def total(*values: str) -> int:
        r = auth_client.get(f"/api/ad/snapshots/{snap}/findings", params={param: list(values)})
        assert r.status_code == 200, r.text
        return int(r.json()["total"])

    one, two = total(a), total(b)
    assert one > 0 and two > 0
    assert total(a, b) == one + two


def test_all_means_no_filter(auth_client: TestClient) -> None:
    snap = _snapshot(auth_client)
    url = f"/api/ad/snapshots/{snap}/findings"
    full = auth_client.get(url).json()["total"]
    assert auth_client.get(url, params={"check": "all"}).json()["total"] == full
    assert auth_client.get(url, params={"severity": "all", "assignee": "all"}).json()["total"] == full
    # Старая строка статусов через запятую по-прежнему понятна.
    assert auth_client.get(url, params={"status": "new,in_work"}).json()["total"] == auth_client.get(
        url, params={"status": ["new", "in_work"]}).json()["total"] > 0


def test_unknown_delta_in_list_is_rejected(auth_client: TestClient) -> None:
    snap = _snapshot(auth_client)
    assert auth_client.get(f"/api/ad/snapshots/{snap}/findings", params={"delta": ["new", "bogus"]}).status_code == 422
