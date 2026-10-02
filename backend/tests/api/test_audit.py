"""Журнал действий: мутации, входы и отказы пишутся, чтение — нет."""
from __future__ import annotations

import csv
import datetime as dt
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

import api.audit as audit_module
from api.db.models import AuditEvent
from api.platform.routers.audit import CSV_HEADER
from tests.api.conftest import TEST_LOGIN, TEST_PASSWORD


def _events(db: Any) -> list[AuditEvent]:
    db.expire_all()
    return list(db.query(AuditEvent).order_by(AuditEvent.id))


def test_login_logout_and_failed_login_are_recorded(client: TestClient, test_user: Any, db_session: Any) -> None:
    client.post("/api/auth/login", json={"login": TEST_LOGIN, "password": "wrong"})
    client.post("/api/auth/login", json={"login": TEST_LOGIN, "password": TEST_PASSWORD})
    client.post("/api/auth/logout")
    events = _events(db_session)
    assert [(e.path, e.status) for e in events] == [
        ("/api/auth/login", 401),
        ("/api/auth/login", 204),
        ("/api/auth/logout", 204),
    ]
    assert events[0].user_id is None and events[0].login == TEST_LOGIN
    assert events[1].user_id == test_user.id and events[1].role == "admin"


def test_reads_are_not_recorded_but_writes_and_denials_are(
    auth_client: TestClient, client_as: Callable[[str], TestClient], db_session: Any
) -> None:
    before = len(_events(db_session))
    auth_client.get("/api/siem/snapshots")
    assert len(_events(db_session)) == before
    auth_client.put("/api/settings/security", json={"session_ttl_hours": 3})
    client_as("auditor").put("/api/settings/security", json={"session_ttl_hours": 3})
    #: Между этими двумя записями ложится ещё одна — вход аудитора внутри
    #: client_as(); ищем по содержимому, а не по хвосту списка.
    events = _events(db_session)
    admin_write = next(e for e in events if e.path == "/api/settings/security" and e.role == "admin")
    denied_write = next(e for e in events if e.path == "/api/settings/security" and e.status == 403)
    assert (admin_write.method, admin_write.path, admin_write.status) == ("PUT", "/api/settings/security", 204)
    assert (denied_write.status, denied_write.role) == (403, "auditor")


def test_summary_keeps_query_but_never_body(auth_client: TestClient, db_session: Any) -> None:
    auth_client.post("/api/siem/snapshots/7/reparse?snapshot_id=7", json={"finding_id": 1, "note": "секрет"})
    last = _events(db_session)[-1]
    assert last.summary == "snapshot_id=7"
    assert "секрет" not in (last.summary or "")


def test_list_filters_and_pages(auth_client: TestClient, db_session: Any) -> None:
    for _ in range(3):
        auth_client.put("/api/settings/security", json={"session_ttl_hours": 3})
    page = auth_client.get("/api/settings/audit", params={"page": 1, "page_size": 2}).json()
    assert page["total"] >= 4 and len(page["items"]) == 2
    assert page["items"][0]["id"] > page["items"][1]["id"]  # новые сверху
    denied = auth_client.get("/api/settings/audit", params={"denied_only": "true"}).json()
    assert all(item["status"] == 403 for item in denied["items"])


def test_csv_export(auth_client: TestClient) -> None:
    auth_client.put("/api/settings/security", json={"session_ttl_hours": 3})
    response = auth_client.get("/api/settings/audit/export.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    text = response.content.decode("utf-8-sig")
    assert text.splitlines()[0] == "время;пользователь;роль;метод;путь;код;ip;сводка"
    assert "/api/settings/security" in text


def test_csv_export_does_not_lose_rows_on_a_long_journal(
    auth_client: TestClient, db_session: Any
) -> None:
    """Журнал отдаётся потоком и партиями по 500 — на границах партий
    строки теряться не должны."""
    at = dt.datetime.now(dt.UTC)
    db_session.add_all(
        AuditEvent(at=at, login="x", method="PUT", path="/many", status=204) for _ in range(1200)
    )
    db_session.commit()
    response = auth_client.get("/api/settings/audit/export.csv")
    assert response.status_code == 200
    rows = list(csv.reader(response.content.decode("utf-8-sig").splitlines(), delimiter=";"))
    assert rows[0] == CSV_HEADER
    assert sum(1 for row in rows if row[4] == "/many") == 1200


def test_old_events_are_purged_at_login(client: TestClient, auth_client: TestClient, db_session: Any) -> None:
    auth_client.put("/api/settings/security", json={"audit_retention_days": 7})
    old = AuditEvent(at=dt.datetime.now(dt.UTC) - dt.timedelta(days=8), login="x", method="PUT", path="/p", status=204)
    db_session.add(old)
    db_session.commit()
    TestClient(client.app).post("/api/auth/login", json={"login": TEST_LOGIN, "password": TEST_PASSWORD})
    #: Не по old.id: идентификатор удалённой строки может достаться записи
    #: самого этого входа — ищем по логину синтетической строки.
    assert not any(e.login == "x" for e in _events(db_session))


def test_broken_audit_write_does_not_fail_the_request(
    auth_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Сбой записи в журнал (обрыв БД и т.п.) не должен превращать уже
    готовый успешный ответ в 500 — см. api.audit.AuditMiddleware.dispatch."""

    def _boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("нет соединения с базой")

    monkeypatch.setattr(audit_module, "record", _boom)
    response = auth_client.put("/api/settings/security", json={"session_ttl_hours": 3})
    assert response.status_code == 204


def test_csv_export_escapes_formula_injection(auth_client: TestClient) -> None:
    """Логин из неудачного входа — чужой ввод; ячейка, начинающаяся с `=`,
    должна прийти в CSV с ведущим апострофом, а не выполниться в Excel."""
    payload_login = '=HYPERLINK("http://x")'
    TestClient(auth_client.app).post("/api/auth/login", json={"login": payload_login, "password": "wrong"})
    response = auth_client.get("/api/settings/audit/export.csv")
    text = response.content.decode("utf-8-sig")
    rows = list(csv.reader(text.splitlines(), delimiter=";"))
    assert any(cell.startswith("'=HYPERLINK") for row in rows for cell in row)


def test_over_long_login_is_still_recorded_but_hidden(client: TestClient, db_session: Any) -> None:
    """Логин длиннее колонки не должен уносить с собой всю запись:
    `String(255)` без обрезки отверг бы вставку, и попытка входа исчезла бы
    из журнала целиком. Длиннее 64 символов — скорее пароль, чем логин
    (L5), поэтому вместо него «—»."""
    client.post("/api/auth/login", json={"login": "a" * 300, "password": "wrong"})
    last = _events(db_session)[-1]
    assert (last.path, last.status, last.login) == ("/api/auth/login", 401, "—")


@pytest.mark.parametrize(
    ("login", "recorded"),
    [("my secret pass", "—"), ("a" * 65, "—"), ("a" * 64, "a" * 64), ("ivanov", "ivanov")],
)
def test_password_typed_into_login_is_not_recorded(
    client: TestClient, db_session: Any, login: str, recorded: str
) -> None:
    client.post("/api/auth/login", json={"login": login, "password": "wrong"})
    assert _events(db_session)[-1].login == recorded


def test_anonymous_noise_is_not_recorded(client: TestClient, db_session: Any) -> None:
    """422/404 без сессии — не действие пользователя (L1)."""
    bad_json = client.put("/api/settings/security", content=b"{bad", headers={"Content-Type": "application/json"})
    assert bad_json.status_code == 422
    assert client.post("/api/nothing-here").status_code == 404
    assert _events(db_session) == []


def test_anonymous_failed_login_is_still_recorded(client: TestClient, db_session: Any) -> None:
    assert client.post("/api/auth/login", json={"login": "nobody"}).status_code == 422
    client.post("/api/auth/login", json={"login": "nobody", "password": "wrong"})
    assert [(e.path, e.status) for e in _events(db_session)] == [
        ("/api/auth/login", 422),
        ("/api/auth/login", 401),
    ]


@pytest.mark.parametrize(
    "path",
    [
        "/api/settings/audit/export.csv",
        "/api/vm/export",
        "/api/ksc/snapshots/999/policies/999/contents",
    ],
)
def test_exports_and_policy_contents_are_recorded(auth_client: TestClient, db_session: Any, path: str) -> None:
    """Чтение, которое уносит данные из системы, пишется в журнал (L5)."""
    status = auth_client.get(path).status_code
    last = _events(db_session)[-1]
    assert (last.method, last.path, last.status) == ("GET", path, status)


def test_retention_below_a_week_is_rejected(auth_client: TestClient) -> None:
    """Иначе администратор стирает историю, поставив срок в один день (L5)."""
    assert auth_client.put("/api/settings/security", json={"audit_retention_days": 1}).status_code == 422
    assert auth_client.put("/api/settings/security", json={"audit_retention_days": 6}).status_code == 422
    assert auth_client.put("/api/settings/security", json={"audit_retention_days": 7}).status_code == 204


def test_stored_short_retention_is_raised_to_a_week(auth_client: TestClient, db_session: Any) -> None:
    """Значение, сохранённое до появления минимума, не ломает вход и не
    сокращает журнал: читается как 7."""
    from api.db.models import AppSetting

    db_session.merge(AppSetting(key="security", value_json='{"audit_retention_days": 1}'))
    db_session.commit()
    assert auth_client.get("/api/settings/security").json()["audit_retention_days"] == 7


@pytest.mark.parametrize(
    ("path", "recorded"),
    [("/api/vm/export", True), ("/api/vm/zones/export", True), ("/api/vm/export/status", False), ("/api/vm/exports", False)],
)
def test_vm_export_pattern_is_anchored(path: str, recorded: bool) -> None:
    assert audit_module._should_record("GET", path, 200, "") is recorded


def test_throttle_index_exists(migrated_database: Any) -> None:
    from sqlalchemy import inspect

    indexes = {ix["name"]: ix["column_names"] for ix in inspect(migrated_database).get_indexes("audit_event")}
    assert indexes["ix_audit_event_path_status_at"] == ["path", "status", "at"]
