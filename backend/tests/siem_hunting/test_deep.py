"""Большой хант: нарезка периода на куски, одна находка на все куски, отмена и сбой с сохранением полученного."""
from __future__ import annotations

import datetime as dt
import json
import math
from itertools import pairwise
from typing import Any

import pytest
from sqlalchemy import select

from api.jobs import JobHandle, run_job, start_job
from api.modules.siem.hunting.deep import create_deep, run_deep, slices
from api.modules.siem.hunting.models import ThDeepHunt, ThEvent, ThFinding, ThJob
from tests.siem_hunting.fake_events import TOKEN, FakeEvents
from tests.siem_hunting.test_nightly import Clock, Sleeper, add_hunt, events, set_th

NOW = dt.datetime(2026, 10, 19, 12, 0, tzinfo=dt.UTC)
H = dt.timedelta(hours=1)
D = dt.timedelta(days=1)


def new_deep(db: Any, period_from: dt.datetime, period_to: dt.datetime = NOW, *, query_text: str = "q-deep",
             limit: int = 100, title: str = "deep", hunt: Any = None) -> ThDeepHunt:
    return create_deep(
        db, title=title, hunt=hunt, query=None, query_text=query_text, fields=["time", "event_src.host"],
        labels=["Время", "Узел"], limit=limit, period_from=period_from, period_to=period_to, login="analyst", now=NOW,
    )


def windows(fake: FakeEvents) -> list[tuple[int, int]]:
    return [(json.loads(c.content)["timeFrom"], json.loads(c.content)["timeTo"]) for c in fake.calls]


def ts(moment: dt.datetime) -> int:
    return int(moment.timestamp())


def test_slices_hot_then_cold() -> None:
    # Три месяца назад плюс час: остаток холодной части не кратен 3 ч.
    period_from = dt.datetime(2026, 7, 19, 13, 0, tzinfo=dt.UTC)
    got = slices(period_from, NOW, now=NOW, hot_days=7, slice_hours=3)
    hot_edge = NOW - 7 * D
    assert got[0] == (hot_edge, NOW)
    cold = got[1:]
    assert cold[0][1] == hot_edge
    assert all(b - a == 3 * H for a, b in cold[:-1])
    assert cold[-1] == (period_from, period_from + 2 * H)
    # От свежего к старому, стык в стык: без зазоров и перекрытий.
    assert all(newer[0] == older[1] for newer, older in pairwise(got))
    assert len(got) == 1 + math.ceil((hot_edge - period_from) / (3 * H)) == 681

    # Период целиком в горячем окне — один кусок; целиком глубже — без горячего куска.
    assert slices(NOW - 2 * D, NOW, now=NOW, hot_days=7, slice_hours=3) == [(NOW - 2 * D, NOW)]
    deep_to = NOW - 10 * D
    assert slices(deep_to - 5 * H, deep_to, now=NOW, hot_days=7, slice_hours=3) == [
        (deep_to - 3 * H, deep_to), (deep_to - 5 * H, deep_to - 3 * H),
    ]
    assert slices(NOW, NOW, now=NOW, hot_days=7, slice_hours=3) == []


def test_deep_runs_all_slices_and_persists_one_finding(db_session: Any, fake: FakeEvents) -> None:
    set_th(db_session, hot_days=1, slice_hours=3)
    hunt = add_hunt(db_session, "TH-WIN-001", [("Q1", "q-deep")])
    period_from = NOW - D - 6 * H
    deep = new_deep(db_session, period_from, hunt=hunt)
    assert (deep.status, deep.slices_total, deep.hunt_id, deep.created_by) == ("queued", 3, hunt.id, "analyst")
    fake.events_by_time_from = {ts(NOW - D): events(2), ts(NOW - D - 3 * H): [], ts(period_from): events(1, "ws-0002")}

    job = ThJob(kind="deep", started_by="t")
    db_session.add(job)
    db_session.commit()
    sleeper = Sleeper()
    run_deep(db_session, JobHandle(db_session, job), deep.id, sleeper=sleeper, clock=Clock(NOW))
    db_session.expire_all()

    assert windows(fake) == [
        (ts(NOW - D), ts(NOW)), (ts(NOW - D - 3 * H), ts(NOW - D)), (ts(period_from), ts(NOW - D - 3 * H)),
    ]
    assert sleeper.calls == [5, 5]
    got = db_session.get(ThDeepHunt, deep.id)
    assert (got.status, got.slices_done, got.slices_total, got.events, got.partial) == ("done", 3, 3, 3, False)
    assert got.next_slice_from == period_from and got.finished_at is not None and got.job_id == job.id
    (finding,) = db_session.scalars(select(ThFinding)).all()
    assert (finding.kind, finding.deep_id, finding.run_id, finding.hunt_code) == ("deep", deep.id, None, "TH-WIN-001")
    assert (finding.event_count, finding.limit_hit, finding.partial) == (3, False, False)
    assert (finding.period_from, finding.period_to) == (period_from, NOW)
    assert json.loads(finding.columns_json) == [{"field": "time", "label": "Время"}, {"field": "event_src.host", "label": "Узел"}]
    rows = db_session.scalars(select(ThEvent).where(ThEvent.finding_id == finding.id).order_by(ThEvent.position)).all()
    assert [r.position for r in rows] == [0, 1, 2]
    assert [json.loads(r.data_json)["event_src.host"] for r in rows] == ["ws-0001", "ws-0001", "ws-0002"]


def test_limit_hit_slices_counted(db_session: Any, fake: FakeEvents) -> None:
    set_th(db_session, hot_days=1, slice_hours=3)
    deep = new_deep(db_session, NOW - D - 6 * H, limit=2)
    fake.events_by_time_from = {ts(NOW - D): events(3), ts(NOW - D - 3 * H): events(1)}
    job = ThJob(kind="deep", started_by="t")
    db_session.add(job)
    db_session.commit()
    run_deep(db_session, JobHandle(db_session, job), deep.id, sleeper=Sleeper(), clock=Clock(NOW))
    db_session.expire_all()
    got = db_session.get(ThDeepHunt, deep.id)
    assert (got.limit_hit_slices, got.events) == (1, 3)
    finding = db_session.scalar(select(ThFinding))
    assert (finding.event_count, finding.limit_hit, finding.hunt_code, finding.query_id) == (3, True, "", "")


def test_cancel_keeps_partial_events(db_session: Any, fake: FakeEvents) -> None:
    set_th(db_session, hot_days=1, slice_hours=3)
    deep = new_deep(db_session, NOW - D - 6 * H)
    deep_id = deep.id
    fake.events_by_time_from = {ts(NOW - D): events(2)}
    job_id = start_job(db_session, ThJob, "deep", "t")

    def cancel_on_pause(seconds: float) -> None:
        db_session.execute(ThJob.__table__.update().where(ThJob.id == job_id).values(cancel_requested=True))
        db_session.commit()

    run_job(ThJob, job_id, lambda db, h: run_deep(db, h, deep_id, sleeper=cancel_on_pause, clock=Clock(NOW)))
    db_session.expire_all()
    assert len(fake.calls) == 1
    got = db_session.get(ThDeepHunt, deep_id)
    assert (got.status, got.partial, got.slices_done, got.events) == ("cancelled", True, 1, 2)
    assert got.finished_at is not None
    finding = db_session.scalar(select(ThFinding).where(ThFinding.deep_id == deep_id))
    assert finding.partial is True and finding.event_count == 2
    assert len(db_session.scalars(select(ThEvent).where(ThEvent.finding_id == finding.id)).all()) == 2
    assert db_session.get(ThJob, job_id).status == "cancelled"


def test_failure_keeps_partial_events(db_session: Any, fake: FakeEvents, monkeypatch: pytest.MonkeyPatch) -> None:
    set_th(db_session, hot_days=1, slice_hours=3)
    deep = new_deep(db_session, NOW - D - 6 * H)
    deep_id = deep.id
    fake.events_by_time_from = {ts(NOW - D): events(2)}
    from api.modules.siem.hunting import deep as deep_module

    original = deep_module.EventsClient.search
    calls: list[int] = []

    def second_fails(self: Any, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("mp.corp.local сломался")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(deep_module.EventsClient, "search", second_fails)
    job_id = start_job(db_session, ThJob, "deep", "t")
    run_job(ThJob, job_id, lambda db, h: run_deep(db, h, deep_id, sleeper=Sleeper(), clock=Clock(NOW)))
    db_session.expire_all()
    got = db_session.get(ThDeepHunt, deep_id)
    assert (got.status, got.partial, got.slices_done, got.error) == ("failed", True, 1, "сбой большого ханта: RuntimeError")
    finding = db_session.scalar(select(ThFinding).where(ThFinding.deep_id == deep_id))
    assert finding.partial is True and finding.event_count == 2
    job = db_session.get(ThJob, job_id)
    assert job.status == "failed" and "corp.local" not in (job.error or "") and TOKEN not in (job.error or "")


def test_unconfigured_connection_fails_deep(db_session: Any) -> None:
    deep = new_deep(db_session, NOW - D)
    deep_id = deep.id
    job_id = start_job(db_session, ThJob, "deep", "t")
    run_job(ThJob, job_id, lambda db, h: run_deep(db, h, deep_id, sleeper=Sleeper(), clock=Clock(NOW)))
    db_session.expire_all()
    got = db_session.get(ThDeepHunt, deep_id)
    assert (got.status, got.error) == ("failed", "подключение к MaxPatrol не настроено")
    assert db_session.get(ThJob, job_id).status == "failed"
