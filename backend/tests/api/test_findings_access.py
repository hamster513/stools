"""Права на находки и справочник исполнителей: уровень проверяется в модуле находки (спека ролей §1.2).

Правило `needed` для /api/findings/* и /api/users/directory ничего не требует,
поэтому границу держат сами ручки.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from api.db.models import AppUser
from api.platform.findings.models import FindingState

VM = {"module": "vm", "scope_id": 0, "key": "srv|10.0.0.1|CVE-2026-0001"}
SIEM = {"module": "siem", "scope_id": 0, "key": "k1"}


def _write_requests(base: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    return [
        ("PUT", "/api/findings/state", {**base, "status": "in_work"}),
        ("POST", "/api/findings/comment", {**base, "text": "x"}),
        ("POST", "/api/findings/bulk", {"module": base["module"], "scope_id": 0, "keys": [base["key"]],
                                        "change": {"status": "in_work"}}),
    ]


def test_write_in_another_module_is_denied(client_as: Any) -> None:
    client = client_as({"vm": "write"})
    for method, path, body in _write_requests(SIEM):
        denied = client.request(method, path, json=body)
        assert denied.status_code == 403, (path, denied.text)
        assert denied.json()["detail"] == "нет доступа: siem, нужен уровень аналитик"
    for method, path, body in _write_requests(VM):
        assert client.request(method, path, json=body).status_code != 403, path


@pytest.mark.parametrize("levels", [{}, {"vm": "read"}])
def test_write_needs_write_level_in_the_module(client_as: Any, levels: dict[str, str]) -> None:
    client = client_as(levels)
    for method, path, body in _write_requests(VM):
        denied = client.request(method, path, json=body)
        assert denied.status_code == 403, (path, denied.text)
        assert denied.json()["detail"] == "нет доступа: vm, нужен уровень аналитик"


def test_threat_hunting_findings_follow_the_siem_level(client_as: Any) -> None:
    th = {"module": "siem_th", "scope_id": 1, "key": "th:1", "status": "in_work"}
    assert client_as({"siem": "write"}).put("/api/findings/state", json=th).status_code != 403
    assert client_as({"vm": "admin"}).put("/api/findings/state", json=th).status_code == 403


def test_unknown_module_is_still_404(client_as: Any) -> None:
    body = {"module": "nope", "scope_id": 0, "key": "k", "status": "in_work"}
    assert client_as({"vm": "write"}).put("/api/findings/state", json=body).status_code == 404


def test_state_and_summary_need_read_in_the_module(client_as: Any) -> None:
    client = client_as({"vm": "read"})
    for path in ("/api/findings/state", "/api/findings/summary"):
        params = {"module": "siem", "scope_id": 0, "key": "k1"}
        assert client.get(path, params=params).status_code == 403, path
    assert client.get("/api/findings/summary", params={"module": "vm", "scope_id": 0}).status_code != 403


# ---- «Мои находки» ---------------------------------------------------------------


def _assign(db: Any, login: str, *rows: tuple[str, str, str, str]) -> None:
    for module, key, status, title in rows:
        db.add(FindingState(module=module, scope_id=0, key=key, status=status, assignee=login, title=title))
    db.commit()


def test_mine_hides_modules_without_read(client_as: Any, db_session: Any) -> None:
    client = client_as({"vm": "read"})
    _assign(db_session, "user-vm-read",
            ("vm", "a", "in_work", "находка vm"), ("siem", "b", "in_work", "находка siem"),
            ("siem_th", "c", "in_work", "находка th"))
    assert [m["title"] for m in client.get("/api/findings/mine").json()] == ["находка vm"]
    assert "находка siem" not in client.get("/api/findings/mine/export").text
    assert "находка vm" in client.get("/api/findings/mine/export").text
    # Явный фильтр по чужому модулю ничего не открывает.
    assert client.get("/api/findings/mine", params={"module": "siem"}).json() == []


def test_mine_shows_threat_hunting_with_siem_read(client_as: Any, db_session: Any) -> None:
    client = client_as({"siem": "read"})
    _assign(db_session, "user-siem-read", ("siem_th", "c", "in_work", "находка th"))
    assert [m["title"] for m in client.get("/api/findings/mine").json()] == ["находка th"]


def test_mine_count_counts_only_modules_with_write(client_as: Any, db_session: Any) -> None:
    client = client_as({"vm": "read", "siem": "write"})
    _assign(db_session, "user-siem-write-vm-read",
            ("vm", "a", "in_work", "vm"), ("siem", "b", "in_work", "siem"), ("siem", "c", "new", "siem 2"))
    assert client.get("/api/findings/mine/count").json() == {"open": 2, "overdue": 0}
    assert client_as({"vm": "read"}).get("/api/findings/mine/count").json() == {"open": 0, "overdue": 0}


# ---- Справочник исполнителей ----------------------------------------------------


def test_directory_lists_users_with_write_in_the_module(
    client_as: Any, make_user: Callable[[str, Any], AppUser], db_session: Any,
) -> None:
    caller = client_as({"vm": "write"})
    make_user("vm-reader", {"vm": "read"})
    make_user("vm-admin", {"vm": "admin"})
    make_user("siem-writer", {"siem": "write"})
    blocked = make_user("vm-blocked", {"vm": "write"})
    blocked.is_active = False
    db_session.commit()
    body = caller.get("/api/users/directory", params={"module": "vm"})
    assert body.status_code == 200, body.text
    assert [u["login"] for u in body.json()] == ["user-vm-write", "vm-admin"]
    assert [u["login"] for u in client_as({"siem": "write"}).get(
        "/api/users/directory", params={"module": "siem_th"}).json()] == ["siem-writer", "user-siem-write"]


def test_directory_needs_module_known_to_the_platform(client_as: Any) -> None:
    caller = client_as({"vm": "admin"})
    assert caller.get("/api/users/directory").status_code == 422
    assert caller.get("/api/users/directory", params={"module": "nope"}).status_code == 422
    assert caller.get("/api/users/directory", params={"module": "platform"}).status_code == 422


def test_directory_needs_write_in_the_module(client_as: Any) -> None:
    denied = client_as({"vm": "read"}).get("/api/users/directory", params={"module": "vm"})
    assert denied.status_code == 403
    assert denied.json()["detail"] == "нет доступа: vm, нужен уровень аналитик"
    assert client_as({"siem": "admin"}).get("/api/users/directory", params={"module": "vm"}).status_code == 403
    assert client_as({}).get("/api/users/directory", params={"module": "vm"}).status_code == 403
