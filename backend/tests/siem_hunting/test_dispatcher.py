"""Диспетчер задач раздела: ночной прогон важнее большого ханта, очередь по одной, продолжение после перезапуска, чистка событий."""
from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from sqlalchemy import func, select, update

from api.jobs import RESTART_ERROR, run_job, start_job
from api.modules.siem.hunting import dispatcher
from api.modules.siem.hunting.deep import run_deep
from api.modules.siem.hunting.dispatcher import (
    dispatch_handler,
    ensure_th_schedules,
    kick,
    nightly_handler,
)
from api.modules.siem.hunting.models import (
    ThDeepHunt,
    ThEvent,
    ThFinding,
    ThJob,
    ThQuery,
    ThRun,
    ThRunQuery,
)
from api.modules.siem.hunting.nightly import create_run
from api.modules.siem.hunting.retention import purge
from api.modules.siem.hunting.settings import ThSettings
from api.modules.siem.hunting.windows import target_date_for
from api.platform.scheduler import PlatformSchedule
from tests.siem_hunting.fake_events import FakeEvents
from tests.siem_hunting.test_deep import NOW, D, H, new_deep, ts
from tests.siem_hunting.test_nightly import Clock, Sleeper, add_hunt, events, set_th

#: Пояс инсталляции в тестах — умолчание настроек (UTC).
TZ = "UTC"
TODAY = target_date_for(NOW, "01:00", TZ)


@pytest.fixture(autouse=True)
def controlled(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[Callable[[], None]]]:
    """Задачи диспетчера не уходят в поток: их запуск копится в списке, тест исполняет их сам."""
    started: list[Callable[[], None]] = []
    monkeypatch.setattr(dispatcher, "spawn", started.append)
    monkeypatch.setattr(dispatcher, "sleep", Sleeper())
    monkeypatch.setattr(dispatcher, "clock", Clock(NOW))
    yield started
    dispatcher._starting.clear()


def drain(started: list[Callable[[], None]]) -> None:
    while started:
        started.pop(0)()


def filters(fake: FakeEvents) -> list[str]:
    return [json.loads(c.content)["filter"] for c in fake.calls]


def test_pauses_for_nightly_and_resumes(db_session: Any, fake: FakeEvents, controlled: list[Any]) -> None:
    set_th(db_session, hot_days=1, slice_hours=3)
    add_hunt(db_session, "TH-WIN-001", [("Q1", "q-night")])
    period_from = NOW - D - 6 * H
    deep = new_deep(db_session, period_from)
    deep_id = deep.id
    fake.events_by_time_from = {ts(NOW - D): events(2), ts(period_from): events(1)}
    job_id = start_job(db_session, ThJob, "deep", "t")

    def night_comes(seconds: float) -> None:
        # Во время паузы после первого куска наступает ночь: прогон на дату в очереди.
        if db_session.scalar(select(func.count()).select_from(ThRun)) == 0:
            create_run(db_session, TODAY, ThSettings(), TZ)

    run_job(ThJob, job_id, lambda db, h: run_deep(db, h, deep_id, sleeper=night_comes, clock=Clock(NOW)))
    db_session.expire_all()
    got = db_session.get(ThDeepHunt, deep_id)
    assert (got.status, got.slices_done, got.next_slice_from) == ("paused", 1, NOW - D)
    assert db_session.get(ThJob, job_id).status == "done"
    assert len(fake.calls) == 1

    # Ночной первым, затем большой хант продолжает со второго куска.
    night_job = kick(db_session)
    assert night_job is not None and db_session.get(ThJob, night_job).kind == "nightly"
    drain(controlled)
    db_session.expire_all()
    run = db_session.scalar(select(ThRun))
    assert run.status == "done" and run.job_id == night_job
    got = db_session.get(ThDeepHunt, deep_id)
    assert (got.status, got.slices_done, got.events) == ("done", 3, 3)
    assert ["q-night" in f for f in filters(fake)] == [False, True, False, False]
    deep_windows = [(json.loads(c.content)["timeFrom"], json.loads(c.content)["timeTo"])
                    for c in fake.calls if "q-deep" in json.loads(c.content)["filter"]]
    assert deep_windows == [
        (ts(NOW - D), ts(NOW)), (ts(NOW - D - 3 * H), ts(NOW - D)), (ts(period_from), ts(NOW - D - 3 * H)),
    ]
    (finding,) = db_session.scalars(select(ThFinding).where(ThFinding.deep_id == deep_id)).all()
    assert finding.event_count == 3 and finding.partial is False
    assert [j.kind for j in db_session.scalars(select(ThJob).order_by(ThJob.id))] == ["deep", "nightly", "deep"]


def test_queue_fifo_one_at_a_time(db_session: Any, fake: FakeEvents, controlled: list[Any]) -> None:
    first = new_deep(db_session, NOW - D, title="первый")
    second = new_deep(db_session, NOW - D, title="второй")
    first_id, second_id = first.id, second.id
    job1 = kick(db_session, started_by="analyst")
    assert job1 is not None and len(controlled) == 1
    assert db_session.get(ThJob, job1).started_by == "analyst"
    # Задача уже заведена, поток ещё не взял её: второй запуск не стартует.
    assert kick(db_session) is None and len(controlled) == 1

    controlled.pop(0)()
    db_session.expire_all()
    assert db_session.get(ThDeepHunt, first_id).status == "done"
    assert db_session.get(ThDeepHunt, second_id).status == "queued"
    assert len(controlled) == 1  # по завершении первого диспетчер сам взял второй

    drain(controlled)
    db_session.expire_all()
    assert db_session.get(ThDeepHunt, second_id).status == "done"
    jobs = db_session.scalars(select(ThJob).order_by(ThJob.id)).all()
    assert [(j.kind, j.status) for j in jobs] == [("deep", "done"), ("deep", "done")]
    assert db_session.get(ThDeepHunt, first_id).job_id == jobs[0].id
    assert db_session.get(ThDeepHunt, second_id).job_id == jobs[1].id
    assert kick(db_session) is None


def test_dispatcher_resumes_after_restart(db_session: Any, fake: FakeEvents, controlled: list[Any]) -> None:
    add_hunt(db_session, "TH-WIN-001", [("Q1", "q-a"), ("Q2", "q-b")])
    run = create_run(db_session, TODAY, ThSettings(), TZ)
    run_id = run.id
    dead = ThJob(kind="nightly", status="failed", error=RESTART_ERROR, started_by="расписание")
    # Задача «идёт», но её поток умер (уборка при старте не прошла): она не должна держать раздел.
    orphan = ThJob(kind="deep", status="running", started_by="t")
    db_session.add_all([dead, orphan])
    db_session.flush()
    run.status, run.job_id = "running", dead.id
    first_query = db_session.scalar(select(ThQuery).where(ThQuery.query == "q-a"))
    db_session.add(ThRunQuery(run_id=run_id, query_pk=first_query.id, hunt_code="TH-WIN-001", query_id="Q1", status="ok"))
    db_session.commit()
    orphan_id = orphan.id

    job_id = kick(db_session)
    assert job_id is not None and job_id not in (dead.id, orphan_id)
    db_session.expire_all()
    assert (db_session.get(ThJob, orphan_id).status, db_session.get(ThJob, orphan_id).error) == ("failed", RESTART_ERROR)
    drain(controlled)
    db_session.expire_all()
    # Продолжение с первого запроса без итога: Q1 уже был, вызывается только Q2.
    assert len(fake.calls) == 1 and "q-b" in filters(fake)[0]
    got = db_session.get(ThRun, run_id)
    assert (got.status, got.job_id, got.queries_done) == ("done", job_id, 1)
    assert db_session.get(ThJob, job_id).status == "done"


def test_nightly_handler_creates_run_once(db_session: Any, fake: FakeEvents, controlled: list[Any]) -> None:
    ensure_th_schedules(db_session)
    db_session.commit()
    rows = {(s.kind, s.interval_hours, s.window_from, s.enabled) for s in db_session.scalars(select(PlatformSchedule))}
    assert rows == {("th_nightly", 24, "01:00", True), ("th_dispatch", 1, None, True)}
    sched = db_session.scalar(select(PlatformSchedule).where(PlatformSchedule.kind == "th_nightly"))

    # Раздел занят большим хантом: прогон встаёт в очередь, планировщику — id занявшей задачи,
    # а не None (иначе он дёргал бы обработчик каждую минуту и сдвинул следующий срок).
    deep = new_deep(db_session, NOW - D)
    busy = kick(db_session)
    assert busy is not None
    assert nightly_handler(db_session, sched) == busy
    assert nightly_handler(db_session, sched) == busy
    runs = db_session.scalars(select(ThRun)).all()
    assert [(r.target_date, r.status) for r in runs] == [(TODAY, "queued")]
    # Большой хант видит ночь между кусками и уступает; ночной прогон стартует по его завершении.
    drain(controlled)
    db_session.expire_all()
    assert db_session.get(ThRun, runs[0].id).status == "done"
    assert db_session.get(ThDeepHunt, deep.id).status == "done"


def test_retention_purges_events_only(db_session: Any) -> None:
    old = ThFinding(kind="nightly", hunt_code="TH-WIN-001", query_id="Q1", period_from=NOW, period_to=NOW,
                    event_count=2, created_at=NOW - 200 * D)
    fresh = ThFinding(kind="nightly", hunt_code="TH-WIN-001", query_id="Q2", period_from=NOW, period_to=NOW,
                      event_count=1, created_at=NOW - 10 * D)
    db_session.add_all([old, fresh])
    db_session.flush()
    db_session.add_all([
        ThEvent(finding_id=old.id, position=0, data_json="{}"),
        ThEvent(finding_id=old.id, position=1, data_json="{}"),
        ThEvent(finding_id=fresh.id, position=0, data_json="{}"),
    ])
    db_session.commit()
    old_id, fresh_id = old.id, fresh.id

    assert purge(db_session, 180, now=NOW) == 1
    db_session.expire_all()
    kept = db_session.get(ThFinding, old_id)
    assert kept is not None and kept.events_purged is True and kept.event_count == 2
    assert db_session.scalar(select(func.count()).select_from(ThEvent).where(ThEvent.finding_id == old_id)) == 0
    assert db_session.get(ThFinding, fresh_id).events_purged is False
    assert db_session.scalar(select(func.count()).select_from(ThEvent).where(ThEvent.finding_id == fresh_id)) == 1
    assert purge(db_session, 180, now=NOW) == 0


def test_nightly_handler_done_night_does_not_kick(db_session: Any, controlled: list[Any]) -> None:
    """Ночь уже обработана: обработчик отдаёт задачу её прогона и ничего не запускает — иначе
    `kick` завёл бы большой хант, и планировщик записал бы его задачу как ночную."""
    ensure_th_schedules(db_session)
    db_session.commit()
    sched = db_session.scalar(select(PlatformSchedule).where(PlatformSchedule.kind == "th_nightly"))
    done = create_run(db_session, TODAY, ThSettings(), TZ)
    done.status, done.job_id = "done", 77
    db_session.commit()
    new_deep(db_session, NOW - D)
    assert nightly_handler(db_session, sched) == 77
    assert controlled == [] and db_session.scalar(select(func.count()).select_from(ThJob)) == 0


def test_pause_does_not_overwrite_cancel(db_session: Any, fake: FakeEvents, controlled: list[Any]) -> None:
    """Отмена записала `cancelled` в строку перед проверкой «пора уступить ночи»: пауза её не затирает,
    задача закрывается отменённой, диспетчер хант не продолжает."""
    set_th(db_session, hot_days=1, slice_hours=3)
    deep = new_deep(db_session, NOW - D - 6 * H)
    deep_id = deep.id
    fake.events_by_time_from = {ts(NOW - D): events(2)}
    job_id = start_job(db_session, ThJob, "deep", "t")
    cancelled_at = NOW - H

    def cancel_then_night(seconds: float) -> None:
        # Ручка отмены успела записать строку, а флаг задачи поток ещё не увидел; тут же приходит ночь.
        if db_session.scalar(select(func.count()).select_from(ThRun)) == 0:
            db_session.execute(update(ThDeepHunt).where(ThDeepHunt.id == deep_id)
                               .values(status="cancelled", finished_at=cancelled_at))
            db_session.commit()
            create_run(db_session, TODAY, ThSettings(), TZ)

    run_job(ThJob, job_id, lambda db, h: run_deep(db, h, deep_id, sleeper=cancel_then_night, clock=Clock(NOW)))
    db_session.expire_all()
    got = db_session.get(ThDeepHunt, deep_id)
    assert (got.status, got.finished_at, got.slices_done) == ("cancelled", cancelled_at, 1)
    assert db_session.get(ThJob, job_id).status == "cancelled"

    drain(controlled)
    night_job = kick(db_session)
    drain(controlled)
    db_session.expire_all()
    assert db_session.get(ThJob, night_job).kind == "nightly"
    assert kick(db_session) is None
    assert db_session.get(ThDeepHunt, deep_id).status == "cancelled"
    assert [j.kind for j in db_session.scalars(select(ThJob).order_by(ThJob.id))] == ["deep", "nightly"]


def _nightly_sched(db: Any, *, fired: bool) -> PlatformSchedule:
    ensure_th_schedules(db)
    db.commit()
    sched = db.scalar(select(PlatformSchedule).where(PlatformSchedule.kind == "th_nightly"))
    if fired:
        sched.last_run_at = NOW - 2 * D
        db.commit()
    return sched


def test_dispatch_creates_missed_nightly_run(db_session: Any, fake: FakeEvents, controlled: list[Any]) -> None:
    """Планировщик уже работал, но ночь за TODAY не завёл (срок уполз за окно): диспетчер
    заводит прогон сам и запускает его."""
    sched = _nightly_sched(db_session, fired=True)
    add_hunt(db_session, "TH-WIN-001", [("Q1", "q-one")])
    dispatch_handler(db_session, sched)
    (run,) = db_session.scalars(select(ThRun)).all()
    assert (run.target_date, run.status) == (TODAY, "queued")
    assert len(controlled) == 1
    job = db_session.scalar(select(ThJob))
    assert job is not None and job.kind == "nightly"
    drain(controlled)
    db_session.expire_all()
    assert db_session.get(ThRun, run.id).status == "done"


def test_dispatch_does_not_create_run_when_scheduler_never_fired(db_session: Any, controlled: list[Any]) -> None:
    sched = _nightly_sched(db_session, fired=False)
    dispatch_handler(db_session, sched)
    assert db_session.scalar(select(func.count()).select_from(ThRun)) == 0
    assert controlled == []


def test_dispatch_does_not_duplicate_existing_run(db_session: Any, controlled: list[Any]) -> None:
    """Прогон даты в любом статусе (отменённый тоже) — ночь уже решена, второй не заводится."""
    sched = _nightly_sched(db_session, fired=True)
    run = create_run(db_session, TODAY, ThSettings(), TZ)
    run.status = "cancelled"
    db_session.commit()
    dispatch_handler(db_session, sched)
    assert [(r.target_date, r.status) for r in db_session.scalars(select(ThRun))] == [(TODAY, "cancelled")]
    assert controlled == []


def test_dispatch_skips_heal_when_nightly_disabled(db_session: Any, controlled: list[Any]) -> None:
    set_th(db_session, nightly_enabled=False)
    sched = _nightly_sched(db_session, fired=True)
    dispatch_handler(db_session, sched)
    assert db_session.scalar(select(func.count()).select_from(ThRun)) == 0
