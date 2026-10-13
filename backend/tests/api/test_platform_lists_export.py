"""Выгрузка списков платформы (спека фильтров и экспорта §2.2): «Мои находки» и учётки; новые ручки попадают
в журнал действий общим шаблоном `/api/.+/export$`."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api import audit as audit_module
from api.platform.findings.models import FindingState
from tests.api.conftest import TEST_LOGIN
from tests.export_check import check_export

MINE = ["Модуль", "Находка", "Тяжесть", "Статус", "Срок", "Риск принят до"]
USERS = ["Логин", "Имя", "Роль", "Вход", "Состояние", "Последний вход"]


def test_mine(auth_client: TestClient, db_session: Any, client_as: Callable[[str], TestClient]) -> None:
    db_session.add_all([
        FindingState(module="ad", scope_id=1, key="k-a", status="in_work", assignee=TEST_LOGIN, title="DCSync у svc-sync",
                     severity="High", due_date=dt.date(2026, 10, 1)),
        FindingState(module="ksc", scope_id=1, key="k-b", status="new", assignee=TEST_LOGIN, title="Нет агента на ws01",
                     severity="Medium"),
        FindingState(module="ksc", scope_id=1, key="k-c", status="new", assignee="someone", title="чужая", severity="Low"),
    ])
    db_session.commit()
    rows = check_export(auth_client, "/api/findings/mine/export", MINE, narrow={"module": "ad"})
    listed = auth_client.get("/api/findings/mine").json()
    assert [r[1] for r in rows[1:]] == [i["title"] for i in listed] and len(rows) == 3
    # Просроченная — первой, как на странице; подписи тяжести и статуса — экранные, срок — датой.
    assert rows[1] == ["Active Directory", "DCSync у svc-sync", "высокий", "В работе", "2026-10-01", ""]
    assert client_as("auditor").get("/api/findings/mine/export").status_code == 200


def test_users_only_for_admin(auth_client: TestClient, client_as: Callable[[str], TestClient]) -> None:
    analyst = client_as("analyst")
    rows = check_export(auth_client, "/api/settings/users/export", USERS)
    by_login = {r[0]: r for r in rows[1:]}
    assert by_login["user-analyst"][2:5] == ["аналитик", "пароль", "активен"]
    assert by_login[TEST_LOGIN][2] == "администратор" and by_login[TEST_LOGIN][5]
    assert analyst.get("/api/settings/users/export").status_code == 403
    assert client_as("auditor").get("/api/settings/users/export").status_code == 403


@pytest.mark.parametrize("path", [
    "/api/ad/snapshots/1/findings/export",
    "/api/ksc/snapshots/1/hosts/export",
    "/api/ksc/servers/1/changes/export",
    "/api/siem/rules/export",
    "/api/findings/mine/export",
    "/api/assets/networks/export",
    "/api/toolbox/scrub/jobs/1/findings/export",
    "/api/settings/users/export",
])
def test_new_exports_are_recorded(path: str) -> None:
    assert audit_module._should_record("GET", path, 200, "") is True
