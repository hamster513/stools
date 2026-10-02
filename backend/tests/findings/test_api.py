"""API статусов находок: /api/findings/*, справочник пользователей, настройки."""
from __future__ import annotations

import datetime as dt
from typing import Any

from fastapi.testclient import TestClient

from api.db.models import AppUser, AuditEvent
from api.platform.findings import service as svc
from tests.api.conftest import TEST_PASSWORD
from tests.findings.conftest import FakeAdapter

TODAY = svc.today()
Q = {"module": "test", "scope_id": 1}


def _as(login: str) -> TestClient:
    """Клиент под учёткой из фикстуры `users`."""
    from api.main import app

    client = TestClient(app)
    response = client.post("/api/auth/login", json={"login": login, "password": TEST_PASSWORD})
    assert response.status_code == 204, response.text
    return client


def test_state_without_row_is_new(app_settings: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    adapter.first["k1"] = dt.datetime(2026, 9, 1, tzinfo=dt.UTC)
    body = _as("analyst1").get("/api/findings/state", params={**Q, "key": "k1"}).json()
    assert body["status"] == "new" and body["status_title"] == "Новая"
    assert body["assignee"] is None and body["events"] == [] and body["overdue"] is False
    assert body["first_seen_at"].startswith("2026-09-01")
    assert {"module", "scope_id", "key", "assignee_name", "due_date", "risk_until", "reason", "present",
            "updated_by", "updated_at"} <= set(body)


def test_put_status_assignee_due_and_null_clears(app_settings: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    analyst = _as("analyst1")
    past = (TODAY - dt.timedelta(days=1)).isoformat()
    r = analyst.put("/api/findings/state", json={**Q, "key": "k1", "status": "in_work", "assignee": "analyst1", "due_date": past})
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["status"], body["assignee"], body["assignee_name"], body["due_date"], body["overdue"]) == (
        "in_work", "analyst1", "Аналитик Один", past, True)
    assert {e["kind"] for e in body["events"]} == {"status", "assign", "due"}

    # Поле не передано — не трогается; null — очищает.
    r = analyst.put("/api/findings/state", json={**Q, "key": "k1", "due_date": None})
    body = r.json()
    assert body["due_date"] is None and body["assignee"] == "analyst1" and body["status"] == "in_work"

    r = analyst.put("/api/findings/state", json={**Q, "key": "k1", "assignee": "auditor1"})
    assert r.status_code == 422
    r = analyst.put("/api/findings/state", json={**Q, "key": "k1", "status": "resolved"})
    assert r.status_code == 422
    r = analyst.put("/api/findings/state", json={**Q, "key": "k1", "status": "false_positive"})
    assert r.status_code == 422


def test_unknown_module_is_404(app_settings: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    r = _as("analyst1").put("/api/findings/state", json={"module": "nope", "scope_id": 1, "key": "k1", "status": "in_work"})
    assert r.status_code == 404


def test_risk_accept_role_admin(app_settings: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    admin = _as("admin1")
    assert admin.put("/api/settings/findings", json={"risk_accept_role": "admin"}).status_code == 200
    body = {**Q, "key": "k1", "status": "risk_accepted", "comment": "компенсирующая мера"}
    assert _as("analyst1").put("/api/findings/state", json=body).status_code == 403
    assert admin.put("/api/findings/state", json=body).status_code == 200


def test_comment(app_settings: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    r = _as("analyst1").post("/api/findings/comment", json={**Q, "key": "k1", "text": "проверю"})
    assert r.status_code == 200, r.text
    events = r.json()["events"]
    assert [(e["kind"], e["comment"], e["actor"]) for e in events] == [("comment", "проверю", "analyst1")]


def test_bulk_by_keys(app_settings: Any, adapter: FakeAdapter, users: dict[str, AppUser], db_session: Any) -> None:
    analyst = _as("analyst1")
    r = analyst.post("/api/findings/bulk", json={**Q, "keys": ["a", "b", "c"], "change": {"status": "in_work", "assignee": "analyst2"}})
    assert r.status_code == 200, r.text
    assert r.json() == {"changed": 3}
    db_session.expire_all()
    last = db_session.query(AuditEvent).filter(AuditEvent.path == "/api/findings/bulk").one()
    assert last.summary and "test" in last.summary and "3" in last.summary

    too_many = [f"k{i}" for i in range(5001)]
    assert analyst.post("/api/findings/bulk", json={**Q, "keys": too_many, "change": {"status": "in_work"}}).status_code == 422
    # Выбор по фильтру модуль ещё не поддерживает.
    assert analyst.post("/api/findings/bulk", json={**Q, "filter": {"severity": "High"}, "change": {"status": "in_work"}}).status_code == 422


def test_mine(app_settings: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    analyst = _as("analyst1")
    analyst.put("/api/findings/state", json={**Q, "key": "k1", "status": "in_work", "assignee": "analyst1",
                                             "title": "слабый пароль", "severity": "High"})
    analyst.put("/api/findings/state", json={**Q, "key": "k2", "status": "in_work", "assignee": "analyst2"})
    analyst.put("/api/findings/state", json={**Q, "key": "k3", "status": "false_positive", "assignee": "analyst1", "comment": "шум"})
    mine = analyst.get("/api/findings/mine").json()
    assert [(m["key"], m["status"], m["link"], m["title"]) for m in mine] == [("k1", "in_work", "/test/1/k1", "слабый пароль")]
    closed = analyst.get("/api/findings/mine", params={"status": "false_positive,in_work"}).json()
    assert {m["key"] for m in closed} == {"k1", "k3"}
    assert analyst.get("/api/findings/mine", params={"module": "other"}).json() == []


def test_summary(app_settings: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    adapter.set_keys(1, "k1", "k2", "k3")
    analyst = _as("analyst1")
    analyst.put("/api/findings/state", json={**Q, "key": "k1", "status": "in_work"})
    body = analyst.get("/api/findings/summary", params=Q).json()
    assert body["by_status"]["in_work"] == 1 and body["by_status"]["new"] == 2
    assert {"overdue", "risk_expiring", "unassigned"} <= set(body)


def test_users_directory(app_settings: Any, users: dict[str, AppUser]) -> None:
    body = _as("auditor1").get("/api/users/directory").json()
    assert body == [
        {"login": "admin1", "display_name": None},
        {"login": "analyst1", "display_name": "Аналитик Один"},
        {"login": "analyst2", "display_name": None},
    ]


def test_settings_read_all_write_admin(app_settings: Any, users: dict[str, AppUser], db_session: Any) -> None:
    body = _as("auditor1").get("/api/settings/findings").json()
    assert body["counted"]["resolved"] is False and body["risk_max_days"] is None and body["risk_accept_role"] == "analyst"
    assert _as("analyst1").put("/api/settings/findings", json={"risk_max_days": 90}).status_code == 403
    r = _as("admin1").put("/api/settings/findings", json={"risk_max_days": 90})
    assert r.status_code == 200 and r.json()["risk_max_days"] == 90
    db_session.expire_all()
    event = db_session.query(AuditEvent).filter(AuditEvent.path == "/api/settings/findings", AuditEvent.status == 200).one()
    assert event.summary == "изменено: risk_max_days"


def test_auditor_cannot_write(app_settings: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    auditor = _as("auditor1")
    assert auditor.put("/api/findings/state", json={**Q, "key": "k1", "status": "in_work"}).status_code == 403
    assert auditor.post("/api/findings/comment", json={**Q, "key": "k1", "text": "x"}).status_code == 403
    assert auditor.post("/api/findings/bulk", json={**Q, "keys": ["k1"], "change": {"status": "in_work"}}).status_code == 403
    assert auditor.put("/api/settings/findings", json={}).status_code == 403
