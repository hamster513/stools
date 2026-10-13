"""Многозначные фасеты уязвимостей VM: внутри фасета — «ИЛИ», два значения дают сумму итогов по
каждому порознь; `all` — фильтра нет; массовая смена по фильтру принимает те же списки."""
from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from api.modules.vm.models import VmHost
from tests.vm.test_vulns_api import loaded  # noqa: F401 — фикстура синтетического импорта


def _total(client: TestClient, **params: str) -> int:
    r = client.get("/api/vm/vulns", params=params)
    assert r.status_code == 200, r.text
    return int(r.json()["total"])


def _top_two(client: TestClient, facet: str) -> tuple[str, str]:
    counts = client.get("/api/vm/vulns", params={"status": "all"}).json()["facets"][facet]
    a, b = sorted((k for k in counts if counts[k]), key=lambda k: -counts[k])[:2]
    return a, b


@pytest.mark.parametrize("facet", ["level", "criticality", "zone", "cvss_source", "os", "assignee"])
def test_two_values_sum_up(loaded: TestClient, facet: str) -> None:  # noqa: F811
    a, b = ("me", "none") if facet == "assignee" else _top_two(loaded, facet)
    assert _total(loaded, **{facet: f"{a},{b}"}) == _total(loaded, **{facet: a}) + _total(loaded, **{facet: b}) > 0


def test_all_means_no_filter(loaded: TestClient) -> None:  # noqa: F811
    full = _total(loaded)
    assert _total(loaded, level="all", zone="all", os="all", criticality="all", cvss_source="all", assignee="all") == full


def test_empty_value_in_list_means_not_set(loaded: TestClient, db_session: Any) -> None:  # noqa: F811
    """'' в наборе — «не задано» (пустая зона у хоста)."""
    from api.modules.vm.findings_adapter import parse_filter
    from api.modules.vm.services.query import count

    db_session.execute(update(VmHost).where(VmHost.zone == "Internal").values(zone=""))
    db_session.commit()
    f = parse_filter({"zone": ["", "DMZ"], "status": "all"}, login="")
    assert count(db_session, f) == _total(loaded, status="all")
    assert count(db_session, parse_filter({"zone": [""], "status": "all"}, login="")) == 1
    # В строке через запятую пустое значение — `-`: и в GET-списке, и в фильтре массовой смены.
    assert count(db_session, parse_filter({"zone": "-", "status": "all"}, login="")) == 1
    assert _total(loaded, zone="-", status="all") == 1
    assert _total(loaded, zone="DMZ,-", status="all") == _total(loaded, status="all")


def test_bulk_filter_takes_lists(loaded: TestClient) -> None:  # noqa: F811
    want = _total(loaded, level="high,critical")
    assert want > 0
    body = {"module": "vm", "scope_id": 0, "filter": {"level": ["high", "critical"]}, "change": {"status": "in_work"}}
    r = loaded.post("/api/findings/bulk", json=body)
    assert r.status_code == 202, r.text
    job = loaded.get(f"/api/vm/jobs/{r.json()['job_id']}").json()
    assert (job["status"], job["processed"]) == ("done", want), job
    assert _total(loaded, status="in_work") == want
    # Та же строка через запятую — как в GET-списке.
    body["filter"] = {"level": "high,critical", "status": "in_work"}
    body["change"] = {"status": "fixed"}
    r = loaded.post("/api/findings/bulk", json=body)
    assert loaded.get(f"/api/vm/jobs/{r.json()['job_id']}").json()["processed"] == want
