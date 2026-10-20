"""API планировщика Threat Hunting: расписание ночного прогона и очередь хантов."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi.testclient import TestClient

from api.modules.siem.hunting.models import ThHunt
from api.modules.siem.hunting.settings import ThSettings, save_th_settings
from tests.siem_hunting.test_nightly import add_hunt

URL = "/api/siem/hunting/scheduler"
ORDER = f"{URL}/order"


def _codes(body: dict[str, Any]) -> list[str]:
    return [h["code"] for h in body["hunts"]]


def test_scheduler_get_returns_queue_in_order(auth_client: TestClient, db_session: Any) -> None:
    # Позиции заданы не по алфавиту: очередь идёт по position, а не по коду.
    add_hunt(db_session, "TH-B", [("Q1", "x = 1"), ("Q2", "x = 2")], position=0)
    add_hunt(db_session, "TH-A", [("Q1", "x = 1")], position=1, enabled=False)
    save_th_settings(db_session, ThSettings(), "t")

    body = auth_client.get(URL).json()

    assert _codes(body) == ["TH-B", "TH-A"]
    assert [h["queries"] for h in body["hunts"]] == [2, 1]
    assert [h["position"] for h in body["hunts"]] == [0, 1]
    assert body["hunts"][1]["enabled"] is False and body["hunts"][0]["last_run"] is None
    assert body["nightly_enabled"] is True and body["window_from"] == "01:00" and body["hunt_pause_s"] == 30
    assert body["next_run_at"] is not None and body["tz"]


def test_scheduler_get_without_schedule_row(auth_client: TestClient) -> None:
    # Расписание ещё не создано (настройки не сохранялись): страница открывается, срока нет.
    body = auth_client.get(URL).json()
    assert body["next_run_at"] is None and body["hunts"] == []


def test_scheduler_put_saves_schedule_and_keeps_other_settings(auth_client: TestClient, db_session: Any) -> None:
    save_th_settings(db_session, ThSettings(retention_days=90), "t")

    r = auth_client.put(URL, json={"nightly_enabled": False, "window_from": "03:30", "hunt_pause_s": 45})

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["nightly_enabled"] is False and body["window_from"] == "03:30" and body["hunt_pause_s"] == 45
    saved = auth_client.get("/api/siem/hunting/settings").json()
    assert saved["retention_days"] == 90
    assert saved["window_from"] == "03:30" and saved["schedule"]["window_from"] == "03:30"
    assert saved["schedule"]["enabled"] is False


def test_scheduler_put_validates_input(auth_client: TestClient) -> None:
    ok: dict[str, Any] = {"nightly_enabled": True, "window_from": "01:00", "hunt_pause_s": 30}
    assert auth_client.put(URL, json=ok | {"window_from": "25:00"}).status_code == 422
    assert auth_client.put(URL, json=ok | {"window_from": "1am"}).status_code == 422
    assert auth_client.put(URL, json=ok | {"hunt_pause_s": 0}).status_code == 422


def _positions(db: Any) -> dict[str, int]:
    db.expire_all()
    return {h.code: h.position for h in db.query(ThHunt).all()}


def test_scheduler_order_rejects_mismatch(auth_client: TestClient, db_session: Any) -> None:
    a = add_hunt(db_session, "TH-A", [("Q1", "x = 1")], position=0)
    b = add_hunt(db_session, "TH-B", [("Q1", "x = 1")], position=1)
    gone = add_hunt(db_session, "TH-GONE", [("Q1", "x = 1")], position=2)
    assert auth_client.delete(f"/api/siem/hunting/hunts/{gone.id}").status_code == 204
    before = _positions(db_session)

    for ids in ([b.id], [b.id, a.id, 9999], [b.id, b.id], [b.id, a.id, gone.id]):
        r = auth_client.put(ORDER, json={"ids": ids})
        assert r.status_code == 422, ids
        assert r.json()["detail"] == "набор хантов не совпадает"

    assert _positions(db_session) == before


def test_scheduler_order_applies(auth_client: TestClient, db_session: Any) -> None:
    a = add_hunt(db_session, "TH-A", [("Q1", "x = 1")], position=0)
    b = add_hunt(db_session, "TH-B", [("Q1", "x = 1")], position=1)
    c = add_hunt(db_session, "TH-C", [("Q1", "x = 1")], position=2)

    r = auth_client.put(ORDER, json={"ids": [c.id, a.id, b.id]})

    assert r.status_code == 200, r.text
    assert _codes(r.json()) == ["TH-C", "TH-A", "TH-B"]
    assert _positions(db_session) == {"TH-C": 0, "TH-A": 1, "TH-B": 2}
    assert _codes(auth_client.get(URL).json()) == ["TH-C", "TH-A", "TH-B"]
    # Порядок виден и в общем списке библиотеки.
    assert [h["code"] for h in auth_client.get("/api/siem/hunting/hunts").json()] == ["TH-C", "TH-A", "TH-B"]


def test_scheduler_auditor_forbidden(client_as: Callable[[str], TestClient], db_session: Any) -> None:
    a = add_hunt(db_session, "TH-A", [("Q1", "x = 1")], position=0)
    auditor = client_as("auditor")
    assert auditor.get(URL).status_code == 200
    body = {"nightly_enabled": True, "window_from": "01:00", "hunt_pause_s": 30}
    assert auditor.put(URL, json=body).status_code == 403
    assert auditor.put(ORDER, json={"ids": [a.id]}).status_code == 403


def test_settings_put_does_not_touch_scheduler_fields(auth_client: TestClient, db_session: Any) -> None:
    """Страница настроек шлёт свою копию полей расписания: залежавшаяся вкладка не должна откатывать Планировщик."""
    auth_client.put(URL, json={"nightly_enabled": False, "window_from": "03:30", "hunt_pause_s": 45})
    stale = auth_client.get("/api/siem/hunting/settings").json()
    stale.pop("schedule", None)
    stale.update({"nightly_enabled": True, "window_from": "01:00", "hunt_pause_s": 30, "retention_days": 10})

    r = auth_client.put("/api/siem/hunting/settings", json=stale)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["retention_days"] == 10
    assert (body["nightly_enabled"], body["window_from"], body["hunt_pause_s"]) == (False, "03:30", 45)
