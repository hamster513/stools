"""Планировщик платформы: расчёт следующего запуска, тик, поток (спека §5)."""
from __future__ import annotations

import datetime as dt
import logging
import threading
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

import api.db.base as db_base
from api.platform import scheduler
from api.platform.scheduler import (
    PlatformSchedule,
    Scheduler,
    delete_schedule,
    next_run,
    register_schedule_kind,
    tick,
    upsert_schedule,
)

UTC = dt.UTC


def at(day: int, hour: int, minute: int = 0) -> dt.datetime:
    return dt.datetime(2026, 10, day, hour, minute, tzinfo=UTC)


# ---- next_run ---------------------------------------------------------------


def test_next_run_without_window_is_after_plus_interval() -> None:
    assert next_run(at(1, 10), 6, None, None) == at(1, 16)


def test_next_run_outside_window_moves_to_next_window_start() -> None:
    assert next_run(at(1, 10), 1, "02:00", "05:00") == at(2, 2)


def test_next_run_before_window_same_day() -> None:
    assert next_run(at(1, 0, 30), 1, "02:00", "05:00") == at(1, 2)


def test_next_run_window_over_midnight_keeps_moment_inside() -> None:
    assert next_run(at(1, 23, 30), 1, "23:00", "01:00") == at(2, 0, 30)


def test_next_run_window_over_midnight_moves_to_evening_start() -> None:
    assert next_run(at(1, 10), 1, "23:00", "01:00") == at(1, 23)


def test_next_run_inside_window_is_not_shifted() -> None:
    assert next_run(at(1, 2), 1, "01:00", "06:00") == at(1, 3)


def test_next_run_window_end_is_exclusive() -> None:
    assert next_run(at(1, 4), 1, "02:00", "05:00") == at(2, 2)


# ---- tick -------------------------------------------------------------------


@pytest.fixture
def handlers(monkeypatch: pytest.MonkeyPatch) -> dict[tuple[str, str], Any]:
    """Пустой реестр на тест: обработчики настоящих модулей тесту не нужны."""
    registry: dict[tuple[str, str], Any] = {}
    monkeypatch.setattr(scheduler, "_handlers", registry)
    return registry


def add(db: Session, *, next_at: dt.datetime, enabled: bool = True, target_id: int = 1,
        kind: str = "run", interval_hours: int = 6) -> PlatformSchedule:
    row = PlatformSchedule(
        module="test", kind=kind, target_id=target_id, interval_hours=interval_hours,
        window_from=None, window_to=None, enabled=enabled, next_run_at=next_at,
    )
    db.add(row)
    db.commit()
    return row


def test_tick_runs_only_due_enabled_schedules(db_session: Session, handlers: dict[Any, Any]) -> None:
    called: list[int] = []

    def handler(_db: Session, sched: PlatformSchedule) -> int:
        called.append(sched.target_id)
        return 100 + sched.target_id

    register_schedule_kind("test", "run", handler)
    now = at(1, 12)
    add(db_session, next_at=at(1, 11), target_id=1)
    add(db_session, next_at=at(1, 13), target_id=2)
    add(db_session, next_at=at(1, 11), target_id=3, enabled=False)

    assert tick(db_session, now) == [101]
    assert called == [1]


def test_tick_records_run_and_next_by_interval(db_session: Session, handlers: dict[Any, Any]) -> None:
    register_schedule_kind("test", "run", lambda _db, _s: 42)
    now = at(1, 12)
    row = add(db_session, next_at=at(1, 11), interval_hours=6)

    tick(db_session, now)

    db_session.expire_all()
    fresh = db_session.get(PlatformSchedule, row.id)
    assert fresh is not None
    assert fresh.last_job_id == 42
    assert fresh.last_run_at == now
    assert fresh.next_run_at == at(1, 18)


def test_tick_busy_handler_postpones_to_next_tick(db_session: Session, handlers: dict[Any, Any]) -> None:
    register_schedule_kind("test", "run", lambda _db, _s: None)
    now = at(1, 12)
    row = add(db_session, next_at=at(1, 11), interval_hours=6)

    assert tick(db_session, now, period_s=60) == []

    db_session.expire_all()
    fresh = db_session.get(PlatformSchedule, row.id)
    assert fresh is not None
    assert fresh.next_run_at == now + dt.timedelta(seconds=60)
    assert fresh.last_job_id is None
    assert fresh.last_run_at is None


def test_tick_handler_error_is_logged_and_others_run(
    db_session: Session, handlers: dict[Any, Any], caplog: pytest.LogCaptureFixture,
) -> None:
    def handler(_db: Session, sched: PlatformSchedule) -> int:
        if sched.target_id == 1:
            raise RuntimeError("обработчик сломан")
        return 7

    register_schedule_kind("test", "run", handler)
    now = at(1, 12)
    broken = add(db_session, next_at=at(1, 10), target_id=1)
    add(db_session, next_at=at(1, 11), target_id=2)

    with caplog.at_level(logging.ERROR, logger="stools.scheduler"):
        assert tick(db_session, now) == [7]

    assert any(r.name == "stools.scheduler" and r.levelno >= logging.ERROR for r in caplog.records)
    db_session.expire_all()
    fresh = db_session.get(PlatformSchedule, broken.id)
    assert fresh is not None
    # Сломанный обработчик не дёргается каждую минуту: следующая попытка — через интервал.
    assert fresh.next_run_at is not None and fresh.next_run_at > now


def test_tick_skips_unknown_kind_until_next_interval(db_session: Session, handlers: dict[Any, Any]) -> None:
    now = at(1, 12)
    row = add(db_session, next_at=at(1, 11), kind="gone")

    assert tick(db_session, now) == []

    db_session.expire_all()
    fresh = db_session.get(PlatformSchedule, row.id)
    assert fresh is not None
    assert fresh.next_run_at == at(1, 18)


# ---- upsert / delete --------------------------------------------------------


def test_upsert_creates_then_updates_by_module_kind_target(db_session: Session) -> None:
    now = at(1, 10)
    first = upsert_schedule(
        db_session, module="test", kind="run", target_id=5, interval_hours=1,
        window_from="02:00", window_to="05:00", enabled=True, now=now,
    )
    db_session.commit()
    assert first.next_run_at == at(2, 2)

    second = upsert_schedule(
        db_session, module="test", kind="run", target_id=5, interval_hours=3,
        window_from=None, window_to=None, enabled=True, now=now,
    )
    db_session.commit()
    assert second.id == first.id
    assert second.next_run_at == at(1, 13)
    assert len(db_session.execute(select(PlatformSchedule)).scalars().all()) == 1


def test_delete_schedule(db_session: Session) -> None:
    row = upsert_schedule(
        db_session, module="test", kind="run", target_id=5, interval_hours=1,
        window_from=None, window_to=None, enabled=True,
    )
    db_session.commit()
    delete_schedule(db_session, row.id)
    db_session.commit()
    assert db_session.get(PlatformSchedule, row.id) is None


# ---- поток ------------------------------------------------------------------


def test_next_run_at_survives_new_scheduler(db_session: Session, handlers: dict[Any, Any]) -> None:
    row = upsert_schedule(
        db_session, module="test", kind="run", target_id=1, interval_hours=24,
        window_from=None, window_to=None, enabled=True,
    )
    db_session.commit()
    planned = row.next_run_at

    sched = Scheduler()
    sched.start(db_base.get_sessionmaker(), period_s=3600)
    sched.stop()

    db_session.expire_all()
    fresh = db_session.get(PlatformSchedule, row.id)
    assert fresh is not None
    assert fresh.next_run_at == planned


def test_thread_runs_overdue_and_survives_tick_error(
    db_session: Session, handlers: dict[Any, Any], monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    ran = threading.Event()

    def handler(_db: Session, _s: PlatformSchedule) -> int:
        ran.set()
        return 1

    register_schedule_kind("test", "run", handler)
    add(db_session, next_at=dt.datetime.now(UTC) - dt.timedelta(hours=1))

    real_tick = scheduler.tick
    calls = {"n": 0}

    def flaky_tick(db: Session, now: dt.datetime, **kw: Any) -> list[int]:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("база моргнула")
        return real_tick(db, now, **kw)

    monkeypatch.setattr(scheduler, "tick", flaky_tick)
    sched = Scheduler()
    with caplog.at_level(logging.ERROR, logger="stools.scheduler"):
        sched.start(db_base.get_sessionmaker(), period_s=0.05)
        try:
            assert ran.wait(5), "просроченное расписание не запущено"
        finally:
            sched.stop()
    assert not sched.alive
    assert any(r.name == "stools.scheduler" for r in caplog.records)
