"""Ночной прогон: окно от расписания, очередь по библиотеке, повторы, остановка на 401, дедлайн, находки с событиями."""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

import pytest
from sqlalchemy import func, select

from api.db.models import AppSetting
from api.jobs import JobHandle, run_job, start_job
from api.modules.siem.hunting.models import (
    ThEvent,
    ThFinding,
    ThHunt,
    ThJob,
    ThQuery,
    ThRun,
    ThRunQuery,
)
from api.modules.siem.hunting.nightly import (
    TH_MODULE,
    TH_SCOPE,
    create_run,
    finding_key,
    queue_for,
    run_nightly,
    supersede_and_rerun,
)
from api.modules.siem.hunting.settings import ThSettings
from api.modules.siem.services.kb_settings import KbConnection, KbConnectionIn, save_connection
from api.platform.findings.models import FindingState
from tests.siem_hunting.fake_events import TOKEN, FakeEvents

TZ = "Europe/Moscow"
NIGHT = dt.date(2026, 10, 19)
#: 01:00 по Москве 19.10 — конец окна ночи 19.10.
WINDOW_END = dt.datetime(2026, 10, 18, 22, 0, tzinfo=dt.UTC)
T0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


class Clock:
    def __init__(self, now: dt.datetime) -> None:
        self.now = now

    def __call__(self) -> dt.datetime:
        return self.now


class Sleeper:
    """Записывает паузы; `on_sleep` — что сдвинуть во времени теста."""

    def __init__(self, clock: Clock | None = None, step: dt.timedelta | None = None) -> None:
        self.calls: list[float] = []
        self.clock = clock
        self.step = step

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)
        if self.clock and self.step:
            self.clock.now += self.step


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch, db_session: Any) -> FakeEvents:
    fake = FakeEvents()
    monkeypatch.setattr("api.modules.siem.hunting.nightly.make_client", fake.http_factory)
    save_connection(db_session, KbConnectionIn(host="mp.corp.local", api_token=TOKEN), "t")
    return fake


def set_th(db: Any, **values: Any) -> ThSettings:
    data = ThSettings(**values)
    db.add(AppSetting(key="siem_th", value_json=data.model_dump_json()))
    db.commit()
    return data


def add_hunt(db: Any, code: str, queries: list[tuple[str, str]], *, age_days: int = 0, enabled: bool = True,
             fields: list[str] | None = None, labels: list[str] | None = None, limit: int | None = None) -> ThHunt:
    """Хант с запросами `(query_id, условие)`; `age_days` — насколько раньше создан (порядок очереди)."""
    hunt = ThHunt(code=code, name=code, enabled=enabled, created_at=T0 + dt.timedelta(days=100 - age_days))
    db.add(hunt)
    db.flush()
    fields = fields or ["time", "event_src.host"]
    for position, (qid, text) in enumerate(queries):
        db.add(ThQuery(hunt_id=hunt.id, query_id=qid, position=position, query=text,
                       fields_json=json.dumps(fields), labels_json=json.dumps(labels or fields), limit=limit))
    db.commit()
    return hunt


def handle_for(db: Any) -> JobHandle:
    job = ThJob(kind="nightly", started_by="t")
    db.add(job)
    db.commit()
    return JobHandle(db, job)


def run(db: Any, run_id: int, *, sleeper: Sleeper | None = None, clock: Clock | None = None) -> Sleeper:
    sleeper = sleeper or Sleeper()
    run_nightly(db, handle_for(db), run_id, sleeper=sleeper, clock=clock or Clock(WINDOW_END + dt.timedelta(minutes=5)))
    db.expire_all()
    return sleeper


def history(db: Any, run_id: int) -> list[tuple[str, str, str]]:
    rows = db.scalars(select(ThRunQuery).where(ThRunQuery.run_id == run_id).order_by(ThRunQuery.id))
    return [(r.hunt_code, r.query_id, r.status) for r in rows]


def events(n: int, host: str = "ws-0001") -> list[dict[str, Any]]:
    return [{"time": f"2026-10-18T0{i % 10}:00:00Z", "event_src.host": host} for i in range(n)]


def test_window_is_pinned_to_schedule_not_start(db_session: Any, fake: FakeEvents) -> None:
    add_hunt(db_session, "TH-WIN-001", [("Q1", "object.name = 'alpha'")])
    r = create_run(db_session, NIGHT, ThSettings(), TZ)
    assert r.status == "queued" and r.queries_total == 1
    # Прогон стартовал в 15:00 по Москве, а ищет свои сутки до 01:00.
    run(db_session, r.id, clock=Clock(dt.datetime(2026, 10, 19, 12, 0, tzinfo=dt.UTC)))
    got = db_session.get(ThRun, r.id)
    assert got.period_to == WINDOW_END and got.period_from == WINDOW_END - dt.timedelta(days=1)
    body = json.loads(fake.calls[0].content)
    assert body["timeTo"] == int(WINDOW_END.timestamp()) and body["timeTo"] - body["timeFrom"] == 86400


def test_queue_order_and_resume(db_session: Any, fake: FakeEvents) -> None:
    late = add_hunt(db_session, "TH-WIN-002", [("Q1", "q-late-1")], age_days=1)
    early = add_hunt(db_session, "TH-WIN-001", [("Q1", "q-early-1"), ("Q2", "q-early-2"), ("Q3", "q-early-3")], age_days=5)
    add_hunt(db_session, "TH-WIN-003", [("Q1", "q-off")], age_days=9, enabled=False)
    gone = add_hunt(db_session, "TH-WIN-004", [("Q1", "q-gone")], age_days=9)
    gone.deleted_at = T0
    off = db_session.scalar(select(ThQuery).where(ThQuery.query == "q-early-3"))
    off.enabled = False
    # Порядок запросов в ханте — по position, а не по добавлению.
    q1 = db_session.scalar(select(ThQuery).where(ThQuery.query == "q-early-1"))
    q2 = db_session.scalar(select(ThQuery).where(ThQuery.query == "q-early-2"))
    q1.position, q2.position = 5, 1
    db_session.commit()

    r = create_run(db_session, NIGHT, ThSettings(), TZ)
    assert [q.query for q in queue_for(db_session, r)] == ["q-early-2", "q-early-1", "q-late-1"]
    assert r.queries_total == 3

    # Прерванный прогон: два запроса завершены, третий застал перезапуск «в работе».
    db_session.add_all([
        ThRunQuery(run_id=r.id, query_pk=q2.id, hunt_code=early.code, query_id="Q2", status="ok"),
        ThRunQuery(run_id=r.id, query_pk=q1.id, hunt_code=early.code, query_id="Q1", status="failed"),
    ])
    late_q = db_session.scalar(select(ThQuery).where(ThQuery.hunt_id == late.id))
    db_session.add(ThRunQuery(run_id=r.id, query_pk=late_q.id, hunt_code=late.code, query_id="Q1", status="running"))
    r.status = "running"
    db_session.commit()
    assert [q.query for q in queue_for(db_session, r)] == ["q-late-1"]

    run(db_session, r.id)
    assert len(fake.calls) == 1 and "q-late-1" in json.loads(fake.calls[0].content)["filter"]
    assert history(db_session, r.id) == [("TH-WIN-001", "Q2", "ok"), ("TH-WIN-001", "Q1", "failed"), ("TH-WIN-002", "Q1", "ok")]
    assert db_session.get(ThRun, r.id).status == "done"


def test_run_persists_findings_and_history(db_session: Any, fake: FakeEvents) -> None:
    add_hunt(db_session, "TH-WIN-001", [("Q1", "q-one"), ("Q2", "q-two")], age_days=2,
             labels=["Время", "Узел"])
    add_hunt(db_session, "TH-WIN-002", [("Q1", "q-three")], age_days=1)
    fake.events_by_query["q-two"] = events(7)
    r = create_run(db_session, NIGHT, ThSettings(), TZ)
    sleeper = run(db_session, r.id)

    got = db_session.get(ThRun, r.id)
    assert (got.status, got.queries_total, got.queries_done, got.findings, got.error) == ("done", 3, 3, 1, None)
    assert got.started_at is not None and got.finished_at is not None
    assert history(db_session, r.id) == [("TH-WIN-001", "Q1", "ok"), ("TH-WIN-001", "Q2", "ok"), ("TH-WIN-002", "Q1", "ok")]
    (finding,) = db_session.scalars(select(ThFinding)).all()
    assert (finding.kind, finding.hunt_code, finding.query_id, finding.run_id) == ("nightly", "TH-WIN-001", "Q2", r.id)
    assert finding.event_count == 7 and finding.limit_hit is False and finding.partial is False
    assert (finding.period_from, finding.period_to) == (got.period_from, got.period_to)
    assert json.loads(finding.columns_json) == [{"field": "time", "label": "Время"}, {"field": "event_src.host", "label": "Узел"}]
    rows = db_session.scalars(select(ThEvent).where(ThEvent.finding_id == finding.id).order_by(ThEvent.position)).all()
    assert [e.position for e in rows] == list(range(7))
    assert json.loads(rows[0].data_json) == {"time": "2026-10-18T00:00:00Z", "event_src.host": "ws-0001"}
    q2 = db_session.scalar(select(ThRunQuery).where(ThRunQuery.query_id == "Q2"))
    assert q2.events == 7 and q2.finding_id == finding.id and q2.duration_ms is not None
    # Пауза только между запросами: (M − 1) × query_pause_s.
    assert sleeper.calls == [30, 30]


def test_missing_fields_are_blank(db_session: Any, fake: FakeEvents) -> None:
    add_hunt(db_session, "TH-WIN-001", [("Q1", "q-blank")], fields=["time", "src.ip", "event_src.host"])
    fake.events_by_query["q-blank"] = [
        {"time": "t1", "event_src.host": "ws-0001", "body": "лишнее поле"},
        {"time": "t2", "src.ip": None, "event_src.host": 0},
    ]
    r = create_run(db_session, NIGHT, ThSettings(), TZ)
    run(db_session, r.id)
    rows = db_session.scalars(select(ThEvent).order_by(ThEvent.position)).all()
    assert [json.loads(e.data_json) for e in rows] == [
        {"time": "t1", "src.ip": "", "event_src.host": "ws-0001"},
        {"time": "t2", "src.ip": "", "event_src.host": 0},
    ]


def test_500_retries_then_failed_and_run_continues(db_session: Any, fake: FakeEvents) -> None:
    add_hunt(db_session, "TH-WIN-001", [("Q1", "q-flaky"), ("Q2", "q-steady")])
    fake.events_by_query["q-flaky"] = events(1)
    fake.status_once["q-flaky"] = [500, 500]
    r = create_run(db_session, NIGHT, ThSettings(), TZ)
    sleeper = run(db_session, r.id)
    # Ожидание кусками не длиннее 30 с: 10 мин + 20 мин повторов и пауза между запросами.
    assert sum(sleeper.calls) == 600 + 1200 + 30 and max(sleeper.calls) <= 30
    assert history(db_session, r.id) == [("TH-WIN-001", "Q1", "ok"), ("TH-WIN-001", "Q2", "ok")]
    assert db_session.get(ThRun, r.id).findings == 1

    # Повторы кончились: запрос «failed», очередь идёт дальше.
    fake.status_once["q-flaky"] = [500] * 8
    fake.calls.clear()
    r2 = create_run(db_session, NIGHT + dt.timedelta(days=1), ThSettings(), TZ)
    sleeper = run(db_session, r2.id)
    assert sum(sleeper.calls) == 600 + 1200 + 1800 * 5 + 30 and max(sleeper.calls) <= 30
    assert len(fake.calls) == 9
    assert history(db_session, r2.id) == [("TH-WIN-001", "Q1", "failed"), ("TH-WIN-001", "Q2", "ok")]
    failed = db_session.scalar(select(ThRunQuery).where(ThRunQuery.run_id == r2.id, ThRunQuery.query_id == "Q1"))
    assert failed.error is not None and "исчерпаны повторы" in failed.error
    assert TOKEN not in failed.error and "corp.local" not in failed.error
    got = db_session.get(ThRun, r2.id)
    assert got.status == "done" and got.queries_done == 2


def test_401_aborts_run(db_session: Any, fake: FakeEvents) -> None:
    add_hunt(db_session, "TH-WIN-001", [("Q1", "q-a"), ("Q2", "q-b"), ("Q3", "q-c")])
    fake.status_once["q-a"] = [401]
    r = create_run(db_session, NIGHT, ThSettings(), TZ)
    run_id = r.id
    job_id = start_job(db_session, ThJob, "nightly", "t")
    run_job(ThJob, job_id, lambda db, h: run_nightly(db, h, run_id, sleeper=Sleeper(), clock=Clock(WINDOW_END)))
    db_session.expire_all()
    assert len(fake.calls) == 1
    got = db_session.get(ThRun, run_id)
    assert (got.status, got.error) == ("aborted", "вход отклонён") and got.finished_at is not None
    assert [s for _, _, s in history(db_session, run_id)] == ["failed", "aborted", "aborted"]
    assert got.queries_done == 1
    job = db_session.get(ThJob, job_id)
    assert job.status == "failed" and job.error == "вход отклонён"
    rows = db_session.scalars(select(ThRunQuery).where(ThRunQuery.run_id == run_id)).all()
    assert all(TOKEN not in (row.error or "") and "corp.local" not in (row.error or "") for row in rows)


def test_cancel_between_queries(db_session: Any, fake: FakeEvents) -> None:
    add_hunt(db_session, "TH-WIN-001", [("Q1", "q-a"), ("Q2", "q-b")])
    r = create_run(db_session, NIGHT, ThSettings(), TZ)
    run_id = r.id
    job_id = start_job(db_session, ThJob, "nightly", "t")

    def cancel_on_pause(seconds: float) -> None:
        db_session.execute(ThJob.__table__.update().where(ThJob.id == job_id).values(cancel_requested=True))
        db_session.commit()

    run_job(ThJob, job_id, lambda db, h: run_nightly(db, h, run_id, sleeper=cancel_on_pause, clock=Clock(WINDOW_END)))
    db_session.expire_all()
    assert db_session.get(ThRun, run_id).status == "cancelled"
    assert db_session.get(ThJob, job_id).status == "cancelled"
    assert history(db_session, run_id) == [("TH-WIN-001", "Q1", "ok")]


def test_deadline_skips_rest(db_session: Any, fake: FakeEvents) -> None:
    set_th(db_session, nightly_deadline_h=2)
    add_hunt(db_session, "TH-WIN-001", [("Q1", "q-a"), ("Q2", "q-b"), ("Q3", "q-c")])
    r = create_run(db_session, NIGHT, ThSettings(), TZ)
    clock = Clock(WINDOW_END + dt.timedelta(minutes=10))
    # Пауза после первого запроса «длится» 3 часа: ночь вышла за предел.
    run(db_session, r.id, sleeper=Sleeper(clock, dt.timedelta(hours=3)), clock=clock)
    assert len(fake.calls) == 1
    assert history(db_session, r.id) == [("TH-WIN-001", "Q1", "ok"), ("TH-WIN-001", "Q2", "skipped"), ("TH-WIN-001", "Q3", "skipped")]
    skipped = db_session.scalars(select(ThRunQuery).where(ThRunQuery.status == "skipped")).all()
    assert {row.error for row in skipped} == {"не успели за ночь"}
    got = db_session.get(ThRun, r.id)
    assert got.status == "done" and got.queries_done == 1 and "не успели за ночь" in (got.error or "")


def test_limit_hit_flag(db_session: Any, fake: FakeEvents) -> None:
    add_hunt(db_session, "TH-WIN-001", [("Q1", "q-full"), ("Q2", "q-short"), ("Q3", "q-over")], limit=2)
    fake.events_by_query.update({"q-full": events(2), "q-short": events(1), "q-over": events(3)})
    r = create_run(db_session, NIGHT, ThSettings(), TZ)
    run(db_session, r.id)
    assert json.loads(fake.calls[0].content)["limit"] == 2
    got = {f.query_id: (f.event_count, f.limit_hit) for f in db_session.scalars(select(ThFinding))}
    assert got == {"Q1": (2, True), "Q2": (1, False), "Q3": (2, True)}
    assert db_session.scalar(select(func.count()).select_from(ThEvent)) == 5


def test_one_run_per_date_and_rerun_supersedes(db_session: Any, fake: FakeEvents) -> None:
    add_hunt(db_session, "TH-WIN-001", [("Q1", "q-kept"), ("Q2", "q-dropped")])
    fake.events_by_query.update({"q-kept": events(2), "q-dropped": events(3)})
    old = create_run(db_session, NIGHT, ThSettings(), TZ)
    with pytest.raises(ValueError):
        create_run(db_session, NIGHT, ThSettings(), TZ)
    # Идущий прогон не вытесняется: его поток писал бы в заменённый.
    with pytest.raises(ValueError):
        supersede_and_rerun(db_session, NIGHT, "analyst", ThSettings(), TZ)
    run(db_session, old.id)
    kept = db_session.scalar(select(ThFinding).where(ThFinding.query_id == "Q1"))
    dropped = db_session.scalar(select(ThFinding).where(ThFinding.query_id == "Q2"))
    db_session.add(FindingState(module=TH_MODULE, scope_id=TH_SCOPE, key=finding_key(kept.id), status="in_work"))
    db_session.commit()
    kept_id, dropped_id, old_id = kept.id, dropped.id, old.id

    new = supersede_and_rerun(db_session, NIGHT, "analyst", ThSettings(), TZ)
    db_session.expire_all()
    assert new.id != old_id and new.status == "queued" and new.target_date == NIGHT
    assert db_session.get(ThRun, old_id).status == "superseded"
    assert db_session.get(ThFinding, kept_id) is not None
    assert db_session.get(ThFinding, dropped_id) is None
    assert db_session.scalar(select(func.count()).select_from(ThEvent).where(ThEvent.finding_id == dropped_id)) == 0
    assert db_session.scalar(select(func.count()).select_from(ThEvent).where(ThEvent.finding_id == kept_id)) == 2
    with pytest.raises(ValueError):
        create_run(db_session, NIGHT, ThSettings(), TZ)


def test_cancel_during_retry_wait(db_session: Any, fake: FakeEvents) -> None:
    add_hunt(db_session, "TH-WIN-001", [("Q1", "q-a"), ("Q2", "q-b")])
    fake.status_once["q-a"] = [500] * 8
    r = create_run(db_session, NIGHT, ThSettings(), TZ)
    run_id = r.id
    job_id = start_job(db_session, ThJob, "nightly", "t")
    slept: list[float] = []

    def cancel_after_first_slice(seconds: float) -> None:
        slept.append(seconds)
        db_session.execute(ThJob.__table__.update().where(ThJob.id == job_id).values(cancel_requested=True))
        db_session.commit()

    run_job(ThJob, job_id, lambda db, h: run_nightly(db, h, run_id, sleeper=cancel_after_first_slice, clock=Clock(WINDOW_END)))
    db_session.expire_all()
    assert db_session.get(ThRun, run_id).status == "cancelled"
    assert db_session.get(ThJob, job_id).status == "cancelled"
    assert history(db_session, run_id) == [("TH-WIN-001", "Q1", "running")]
    assert sum(slept) <= 60 and len(fake.calls) == 1


def test_deadline_cuts_retry_wait(db_session: Any, fake: FakeEvents) -> None:
    set_th(db_session, nightly_deadline_h=1)
    add_hunt(db_session, "TH-WIN-001", [("Q1", "q-a"), ("Q2", "q-b")])
    fake.status_once["q-a"] = [500] * 8
    r = create_run(db_session, NIGHT, ThSettings(), TZ)
    clock = Clock(WINDOW_END + dt.timedelta(minutes=50))
    # Повтор через 10 мин ещё укладывается в предел, но каждый кусок ожидания «длится» 5 минут.
    sleeper = run(db_session, r.id, sleeper=Sleeper(clock, dt.timedelta(minutes=5)), clock=clock)
    assert len(sleeper.calls) == 1 and len(fake.calls) == 1
    assert history(db_session, r.id) == [("TH-WIN-001", "Q1", "skipped"), ("TH-WIN-001", "Q2", "skipped")]
    skipped = db_session.scalars(select(ThRunQuery).where(ThRunQuery.run_id == r.id)).all()
    assert {row.error for row in skipped} == {"не успели за ночь"}
    got = db_session.get(ThRun, r.id)
    assert got.status == "done" and got.queries_done == 0 and got.error == "не успели за ночь: пропущено запросов 2"


def test_unconfigured_connection_aborts(db_session: Any) -> None:
    db_session.add(AppSetting(key="siem_mp", value_json=KbConnection(host="mp.corp.local").model_dump_json()))
    db_session.commit()
    add_hunt(db_session, "TH-WIN-001", [("Q1", "q-a"), ("Q2", "q-b")])
    r = create_run(db_session, NIGHT, ThSettings(), TZ)
    run_id = r.id
    job_id = start_job(db_session, ThJob, "nightly", "t")
    run_job(ThJob, job_id, lambda db, h: run_nightly(db, h, run_id, sleeper=Sleeper(), clock=Clock(WINDOW_END)))
    db_session.expire_all()
    got = db_session.get(ThRun, run_id)
    assert (got.status, got.error) == ("aborted", "подключение к MaxPatrol не настроено")
    assert [s for _, _, s in history(db_session, run_id)] == ["aborted", "aborted"]
    rows = db_session.scalars(select(ThRunQuery).where(ThRunQuery.run_id == run_id)).all()
    assert all("corp.local" not in (row.error or "") for row in rows) and "corp.local" not in got.error
    job = db_session.get(ThJob, job_id)
    assert job.status == "failed" and "corp.local" not in (job.error or "")


def test_unexpected_error_fails_run(db_session: Any, fake: FakeEvents, monkeypatch: pytest.MonkeyPatch) -> None:
    add_hunt(db_session, "TH-WIN-001", [("Q1", "q-a"), ("Q2", "q-b")])

    def boom(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        raise RuntimeError("mp.corp.local сломался")

    monkeypatch.setattr("api.modules.siem.hunting.nightly.EventsClient.search", boom)
    r = create_run(db_session, NIGHT, ThSettings(), TZ)
    run_id = r.id
    job_id = start_job(db_session, ThJob, "nightly", "t")
    run_job(ThJob, job_id, lambda db, h: run_nightly(db, h, run_id, sleeper=Sleeper(), clock=Clock(WINDOW_END)))
    db_session.expire_all()
    got = db_session.get(ThRun, run_id)
    assert (got.status, got.error) == ("failed", "сбой прогона: RuntimeError")
    (row,) = db_session.scalars(select(ThRunQuery).where(ThRunQuery.run_id == run_id)).all()
    assert (row.query_id, row.status, row.error) == ("Q1", "failed", "сбой прогона: RuntimeError")
    assert db_session.get(ThJob, job_id).status == "failed"
