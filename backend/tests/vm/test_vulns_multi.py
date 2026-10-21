"""Многозначные фасеты уязвимостей VM: значения — повтором ключа, внутри фасета «ИЛИ», два значения
дают сумму итогов по каждому порознь; `all` — фильтра нет; массовая смена по фильтру принимает списки."""
from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from api.modules.vm.core.weights import Levels
from api.modules.vm.findings_adapter import parse_filter
from api.modules.vm.models import VmHost
from api.modules.vm.services.query import count
from tests.api.conftest import TEST_LOGIN
from tests.vm.test_vulns_api import loaded  # noqa: F401 — фикстура синтетического импорта


def _total(client: TestClient, **params: Any) -> int:
    r = client.get("/api/vm/vulns", params=params)
    assert r.status_code == 200, r.text
    return int(r.json()["total"])


def _top_two(client: TestClient, facet: str) -> tuple[str, str]:
    counts = client.get("/api/vm/vulns", params={"status": "all"}).json()["facets"][facet]
    a, b = sorted((k for k in counts if counts[k]), key=lambda k: -counts[k])[:2]
    return a, b


def _assign_one(client: TestClient) -> None:
    """Одна пара назначена вызывающему — у фасета исполнителя есть и `me`, и `none`."""
    key = client.get("/api/vm/vulns").json()["items"][0]["key"]
    r = client.put("/api/findings/state", json={"module": "vm", "scope_id": 0, "key": key,
                                                "status": "in_work", "assignee": TEST_LOGIN})
    assert r.status_code == 200, r.text


@pytest.mark.parametrize("facet", ["level", "criticality", "zone", "cvss_source", "os", "assignee"])
def test_two_values_sum_up(loaded: TestClient, facet: str) -> None:  # noqa: F811
    _assign_one(loaded)
    a, b = ("me", "none") if facet == "assignee" else _top_two(loaded, facet)
    one, two = _total(loaded, **{facet: a}), _total(loaded, **{facet: b})
    assert one > 0 and two > 0
    assert _total(loaded, **{facet: [a, b]}) == one + two


def test_all_means_no_filter(loaded: TestClient) -> None:  # noqa: F811
    full = _total(loaded)
    assert _total(loaded, level="all", zone="all", os="all", criticality="all", cvss_source="all", assignee="all") == full
    assert _total(loaded, status="new,in_work") == _total(loaded, status=["new", "in_work"]) > 0  # старая строка статусов


def test_value_with_comma_is_one_value(loaded: TestClient, db_session: Any) -> None:  # noqa: F811
    """Свободное значение с запятой не рвётся на части."""
    db_session.execute(update(VmHost).where(VmHost.zone == "Internal").values(os_name="Windows 10, Pro"))
    db_session.commit()
    assert _total(loaded, os="Windows 10, Pro", status="all") == 1
    assert _total(loaded, os=["Windows 10, Pro", "Windows 10"], status="all") == 1
    assert count(db_session, parse_filter({"os": ["Windows 10, Pro"], "status": "all"}, login="", levels=Levels())) == 1


def test_empty_value_in_list_means_not_set(loaded: TestClient, db_session: Any) -> None:  # noqa: F811
    """'' в наборе — «не задано» (пустая зона у хоста); в запросе — `-`."""
    db_session.execute(update(VmHost).where(VmHost.zone == "Internal").values(zone=""))
    db_session.commit()
    assert count(db_session, parse_filter({"zone": ["", "DMZ"], "status": "all"}, login="", levels=Levels())) == _total(loaded, status="all")
    assert count(db_session, parse_filter({"zone": [""], "status": "all"}, login="", levels=Levels())) == 1
    assert count(db_session, parse_filter({"zone": "-", "status": "all"}, login="", levels=Levels())) == 1
    assert _total(loaded, zone="-", status="all") == 1
    assert _total(loaded, zone=["DMZ", "-"], status="all") == _total(loaded, status="all")


def test_bulk_filter_takes_lists(loaded: TestClient) -> None:  # noqa: F811
    want = _total(loaded, level=["high", "critical"])
    assert want > 0
    body = {"module": "vm", "scope_id": 0, "filter": {"level": ["high", "critical"]}, "change": {"status": "in_work"}}
    r = loaded.post("/api/findings/bulk", json=body)
    assert r.status_code == 202, r.text
    job = loaded.get(f"/api/vm/jobs/{r.json()['job_id']}").json()
    assert (job["status"], job["processed"]) == ("done", want), job
    assert _total(loaded, status="in_work") == want
    # Статус в фильтре массовой смены — ещё и строкой через запятую.
    body["filter"] = {"level": ["high", "critical"], "status": "in_work,reopened"}
    body["change"] = {"status": "fixed"}
    r = loaded.post("/api/findings/bulk", json=body)
    assert loaded.get(f"/api/vm/jobs/{r.json()['job_id']}").json()["processed"] == want
