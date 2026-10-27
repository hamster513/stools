"""Расписание сбора у подключения KSC: маршруты, поле в списке подключений, запуск планировщиком
(та же задача `collect`, что и кнопка, от имени «расписание») и три отказа обработчика."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from api import collector_routes
from api.collector_routes import SCHEDULE_STARTED_BY, SCHEDULE_USER_ID
from api.hosts import take_slot
from api.jobs import start_job
from api.modules.ksc.core import client as client_mod
from api.modules.ksc.models import KscConnection, KscJob, KscSnapshot
from api.platform.scheduler import PlatformSchedule, tick, upsert_schedule
from tests.ksc.fake_ksc import PASSWORD, USER, FakeKsc, http_factory_for

NOW = dt.datetime.now(dt.UTC)
SCHEDULE = {"interval_hours": 1, "window_from": None, "window_to": None, "enabled": True}


@pytest.fixture(autouse=True)
def inline_spawn(monkeypatch: pytest.MonkeyPatch) -> None:
    """Задача сбора по расписанию уходит в поток; в тестах — на месте, иначе поток пережил бы тест."""
    monkeypatch.setattr(collector_routes, "spawn", lambda fn: fn())


@pytest.fixture
def fake(monkeypatch: Any) -> FakeKsc:
    f = FakeKsc()
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(f))
    return f


def _create(client: TestClient, password: str = PASSWORD) -> int:
    r = client.post("/api/ksc/connections", json={"host": "ksc01.corp.local", "username": USER, "password": password})
    assert r.status_code == 201, r.text
    return int(r.json()["id"])


def _schedules(db: Session) -> list[PlatformSchedule]:
    db.expire_all()
    return list(db.execute(select(PlatformSchedule)).scalars())


def _jobs(db: Session) -> list[KscJob]:
    db.expire_all()
    return list(db.execute(select(KscJob).order_by(KscJob.id)).scalars())


def test_schedule_create_read_and_delete(auth_client: TestClient, db_session: Session) -> None:
    cid = _create(auth_client)
    url = f"/api/ksc/connections/{cid}/schedule"
    assert auth_client.get(url).json() is None
    assert auth_client.get("/api/ksc/connections").json()[0]["schedule"] is None

    r = auth_client.put(url, json={"interval_hours": 24, "window_from": "02:00", "window_to": "05:00", "enabled": True})
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["interval_hours"], body["window_from"], body["window_to"], body["enabled"]) == (24, "02:00", "05:00", True)
    assert body["next_run_at"] is not None and body["tz"]
    (sched,) = _schedules(db_session)
    assert (sched.module, sched.kind, sched.target_id) == ("ksc", "collect", cid)
    assert auth_client.get(url).json()["id"] == sched.id
    listed = auth_client.get("/api/ksc/connections").json()[0]["schedule"]
    assert listed["id"] == sched.id and listed["interval_hours"] == 24 and listed["window_from"] == "02:00"

    r = auth_client.put(url, json={"interval_hours": 12, "window_from": None, "window_to": None, "enabled": False})
    assert r.status_code == 200 and r.json()["id"] == sched.id and r.json()["enabled"] is False
    assert len(_schedules(db_session)) == 1

    assert auth_client.put(url, json={"interval_hours": 12, "window_from": "02:00", "window_to": None, "enabled": True}).status_code == 422
    assert auth_client.put(url, json={"interval_hours": 12, "window_from": "2:00", "window_to": "05:00", "enabled": True}).status_code == 422
    assert auth_client.put(url, json={"interval_hours": 0, "window_from": None, "window_to": None, "enabled": True}).status_code == 422
    assert auth_client.put(url, json={"interval_hours": 721, "window_from": None, "window_to": None, "enabled": True}).status_code == 422

    assert auth_client.delete(url).status_code == 204
    assert _schedules(db_session) == []
    assert auth_client.get(url).json() is None
    assert auth_client.delete(url).status_code == 204

    assert auth_client.get("/api/ksc/connections/999999/schedule").status_code == 404
    assert auth_client.put("/api/ksc/connections/999999/schedule", json=SCHEDULE).status_code == 404
    assert auth_client.delete("/api/ksc/connections/999999/schedule").status_code == 404


def test_delete_connection_drops_schedule(auth_client: TestClient, db_session: Session) -> None:
    cid = _create(auth_client)
    assert auth_client.put(f"/api/ksc/connections/{cid}/schedule", json=SCHEDULE).status_code == 200
    assert len(_schedules(db_session)) == 1
    assert auth_client.delete(f"/api/ksc/connections/{cid}").status_code == 204
    assert _schedules(db_session) == []


def test_auditor_reads_but_cannot_change_schedule(auth_client: TestClient, client_as: Callable[[str], TestClient]) -> None:
    cid = _create(auth_client)
    url = f"/api/ksc/connections/{cid}/schedule"
    auditor = client_as("auditor")
    assert auditor.get(url).status_code == 200
    assert auditor.put(url, json=SCHEDULE).status_code == 403
    assert auditor.delete(url).status_code == 403
    # Расписание подключения — настройка модуля: аналитику нельзя, администратору KSC можно.
    assert client_as("analyst").put(url, json=SCHEDULE).status_code == 403
    assert client_as({"ksc": "admin"}).put(url, json=SCHEDULE).status_code == 200


def test_scheduler_tick_runs_collect(
    auth_client: TestClient, db_session: Session, fake: FakeKsc, monkeypatch: pytest.MonkeyPatch,
) -> None:
    at_start: list[tuple[str, str, str]] = []

    def spawn_checking(fn: Callable[[], None]) -> None:
        # Строка задачи до начала работы: как у сбора кнопкой, в `message` — адрес сервера.
        (job,) = _jobs(db_session)
        at_start.append((job.kind, job.started_by, job.message))
        fn()

    monkeypatch.setattr(collector_routes, "spawn", spawn_checking)
    cid = _create(auth_client)
    r = auth_client.put(f"/api/ksc/connections/{cid}/schedule", json=SCHEDULE)
    assert r.status_code == 200, r.text
    started = tick(db_session, NOW + dt.timedelta(hours=2))
    assert len(started) == 1
    assert at_start == [("collect", SCHEDULE_STARTED_BY, "ksc01.corp.local")]
    (job,) = _jobs(db_session)
    assert job.id == started[0] and job.status == "done", job.error
    (snap,) = db_session.execute(select(KscSnapshot)).scalars().all()
    assert snap.source == "online"
    # Итог — тот же, что у сбора кнопкой.
    assert (job.stage, job.message) == ("done", f"снапшот #{snap.id}: находок {snap.findings}")
    (sched,) = _schedules(db_session)
    assert sched.last_job_id == job.id and sched.last_run_at is not None
    assert sched.next_run_at == NOW + dt.timedelta(hours=3)
    (item,) = auth_client.get("/api/ksc/jobs").json()
    assert (item["kind"], item["started_by"]) == ("collect", SCHEDULE_STARTED_BY)


def test_tick_waits_while_module_job_is_running(auth_client: TestClient, db_session: Session, fake: FakeKsc) -> None:
    cid = _create(auth_client)
    assert auth_client.put(f"/api/ksc/connections/{cid}/schedule", json=SCHEDULE).status_code == 200
    busy = start_job(db_session, KscJob, "collect", "tester", message="вручную")
    now = NOW + dt.timedelta(hours=2)
    assert tick(db_session, now) == []
    assert [j.id for j in _jobs(db_session)] == [busy]
    (sched,) = _schedules(db_session)
    # Повтор через период тика, а не через интервал: занято — не «отработало».
    assert sched.next_run_at == now + dt.timedelta(seconds=60)
    assert sched.enabled is True and sched.last_job_id is None
    assert fake.calls == []


def test_tick_waits_while_slots_are_taken(auth_client: TestClient, db_session: Session, fake: FakeKsc) -> None:
    cid = _create(auth_client)
    assert auth_client.put(f"/api/ksc/connections/{cid}/schedule", json=SCHEDULE).status_code == 200
    slots = [take_slot("ksc", SCHEDULE_USER_ID) for _ in range(2)]
    try:
        now = NOW + dt.timedelta(hours=2)
        assert tick(db_session, now) == []
        assert _jobs(db_session) == []
        (sched,) = _schedules(db_session)
        assert sched.next_run_at == now + dt.timedelta(seconds=60) and sched.enabled is True
    finally:
        for slot in slots:
            slot.release()
    # Слоты свободны — следующий тик запускает сбор, и слот после задачи освобождён.
    assert len(tick(db_session, NOW + dt.timedelta(hours=2, minutes=1))) == 1
    assert _jobs(db_session)[-1].status == "done"
    extra = take_slot("ksc", SCHEDULE_USER_ID)
    extra.release()


def test_connection_without_password_disables_schedule(auth_client: TestClient, db_session: Session, fake: FakeKsc) -> None:
    cid = _create(auth_client, password="")
    assert auth_client.put(f"/api/ksc/connections/{cid}/schedule", json=SCHEDULE).status_code == 200
    assert tick(db_session, NOW + dt.timedelta(hours=2)) == []
    (sched,) = _schedules(db_session)
    assert sched.enabled is False and sched.last_job_id is None
    assert _jobs(db_session) == [] and fake.calls == []
    assert auth_client.get(f"/api/ksc/connections/{cid}/schedule").json()["enabled"] is False
    # Выключенное расписание тик больше не трогает.
    assert tick(db_session, NOW + dt.timedelta(hours=4)) == []


def test_schedule_of_missing_connection_is_removed(auth_client: TestClient, db_session: Session, fake: FakeKsc) -> None:
    cid = _create(auth_client)
    assert auth_client.put(f"/api/ksc/connections/{cid}/schedule", json=SCHEDULE).status_code == 200
    # Подключение пропало мимо маршрута (у строки расписания нет внешнего ключа на подключение).
    db_session.delete(db_session.get(KscConnection, cid))
    db_session.commit()
    upsert_schedule(db_session, module="ksc", kind="collect", target_id=999_999, interval_hours=1,
                    window_from=None, window_to=None, enabled=True, now=NOW - dt.timedelta(hours=1), tz="UTC")
    db_session.commit()
    assert len(_schedules(db_session)) == 2
    assert tick(db_session, NOW + dt.timedelta(hours=2)) == []
    assert _schedules(db_session) == []
    assert _jobs(db_session) == [] and fake.calls == []
