"""«Мои находки»: `status` и `module` — значения через запятую, внутри фильтра «ИЛИ»; `all` — любые статусы."""
from __future__ import annotations

import datetime as dt
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.db.models import AppUser
from tests.findings.conftest import FakeAdapter
from tests.findings.test_api import _as
from tests.findings.test_mine_and_expiry import _put, second  # noqa: F401 — фикстура второго модуля


def _keys(client: TestClient, **params: str) -> list[str]:
    r = client.get("/api/findings/mine", params=params)
    assert r.status_code == 200, r.text
    return sorted(m["key"] for m in r.json())


@pytest.mark.parametrize(("param", "a", "b"), [("module", "test", "test2"), ("status", "in_work", "fixed")])
def test_two_values_sum_up(app_settings: Any, adapter: FakeAdapter, second: FakeAdapter,  # noqa: F811
                           users: dict[str, AppUser], today: dt.date, param: str, a: str, b: str) -> None:
    analyst = _as("analyst1")
    _put(analyst, "test", 1, "a", status="in_work", assignee="analyst1", title="A")
    _put(analyst, "test2", 0, "c", status="in_work", assignee="analyst1", title="C")
    _put(analyst, "test2", 0, "d", status="fixed", assignee="analyst1", title="D")
    _put(analyst, "test", 1, "e", status="risk_accepted", assignee="analyst1", comment="мера",
         risk_until=(today + dt.timedelta(days=5)).isoformat(), title="E")
    one, two = _keys(analyst, **{param: a}), _keys(analyst, **{param: b})
    both = _keys(analyst, **{param: f"{a},{b}"})
    assert one and two and both == sorted(one + two)
    assert _keys(analyst, status="all") == ["a", "c", "d", "e"]
    assert _keys(analyst, status="all", module="test,test2") == ["a", "c", "d", "e"]
