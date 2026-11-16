"""One dispatcher per database; module jobs continue in their native workers."""
import datetime as dt
import logging
import threading
from collections.abc import Callable

from fastapi import HTTPException
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session

from api.db.models import AppUser
from api.jobs import safe_error
from api.platform.services.access import access_for

from . import service
from .adapters import JobRef, job_state, observed_at, start_task
from .catalog import Task, authorized, resolve
from .models import SyncRun, SyncStep

log = logging.getLogger(__name__)
DISPATCH_LOCK = 731419361
PENDING = ("queued", "waiting")
BAD = ("failed", "blocked", "cancelled", "partial")


def fresh(stamp: dt.datetime | None, now: dt.datetime, minutes: int) -> bool:
    if stamp is None:
        return False
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=dt.UTC)
    return dt.timedelta(0) <= now - stamp <= dt.timedelta(minutes=minutes)


def _fail(row: SyncStep, message: str, now: dt.datetime, status: str = "failed") -> None:
    row.status, row.message, row.finished_at = status, message[:2000], now


def _monitor(db: Session, row: SyncStep, now: dt.datetime) -> None:
    if row.status == "starting":
        _fail(row, "Запуск прерван до подтверждения старта. Проверьте результат и повторите задачу.", now)
        return
    if row.job_model is None or row.job_id is None:
        _fail(row, "Не сохранена ссылка на выполнявшуюся задачу", now)
        return
    state = job_state(db, JobRef(row.job_model, row.job_id))
    if state.status in ("running", "pending", "queued"):
        row.message = state.message
        return
    row.finished_at = state.finished_at or now
    row.result = state.result
    row.message = state.message
    row.status = state.status if state.status in ("done", "partial", "cancelled") else "failed"
    if row.status == "done":
        row.checked_at = row.finished_at


def _finish(db: Session, run: SyncRun, rows: list[SyncStep], now: dt.datetime) -> None:
    roots = [r for r in rows if r.is_root]
    if run.cancel_requested:
        run.status = "cancelled"
    elif all(row.status in service.SUCCESS for row in roots):
        run.status = "done"
    elif any(row.status in (*service.SUCCESS, "partial") for row in roots):
        run.status = "partial"
    else:
        run.status = "failed"
    run.finished_at = now
    for row in rows:
        if row.status in PENDING:
            _fail(row, "Шаг не потребовался", now, "skipped")
    db.commit()


def _authorized_task(db: Session, run: SyncRun, row: SyncStep) -> Task:
    task = resolve(db, row.key)
    if run.user_id is not None:
        user = db.get(AppUser, run.user_id, populate_existing=True)
        if user is None or not user.is_active:
            raise HTTPException(403, "Учётная запись отключена или удалена")
        authorized(task, access_for(db, user.id), options=row.options)
    return task


def _choose(db: Session, run: SyncRun, rows: list[SyncStep], now: dt.datetime) -> SyncStep | None:
    by_key = {row.key: row for row in rows}
    def need(row: SyncStep, max_age: int | None = None) -> tuple[str, SyncStep | None]:
        if row.status in BAD:
            return "bad", None
        try:
            task = _authorized_task(db, run, row)
        except HTTPException as exc:
            _fail(row, str(exc.detail), now)
            return "bad", None
        if row.status in service.SUCCESS:
            if max_age is None or fresh(row.checked_at, now, max_age):
                return "ready", None
            if row.attempts >= 2:
                _fail(row, "Данные успевают устареть внутри запуска; увеличьте допустимый возраст зависимости.", now)
                return "bad", None
            row.status = "queued"
            row.finished_at = None
        if row.status not in PENDING:
            return "waiting", None
        if max_age is not None and not row.is_root:
            stamp = observed_at(db, task)
            if fresh(stamp, now, max_age):
                row.status, row.checked_at, row.finished_at = "fresh", stamp, now
                row.message = "Использованы свежие данные"
                return "ready", None
        waiting = False
        for edge in row.dependencies:
            child = by_key.get(edge["key"])
            if child is None:
                _fail(row, "План запуска повреждён: отсутствует зависимость", now, "blocked")
                return "bad", None
            state, candidate = need(child, edge["max_age_minutes"])
            if candidate is not None:
                return "waiting", candidate
            if state == "bad":
                _fail(row, f"Не выполнена зависимость: {child.title}. {child.message}", now, "blocked")
                return "bad", None
            if state != "ready":
                waiting = True
        return ("waiting", None) if waiting else ("waiting", row)

    waiting = False
    for row in rows:
        if row.is_root:
            try:
                state, candidate = need(row)
            except HTTPException as exc:
                _fail(row, str(exc.detail), now)
                continue
            if candidate is not None:
                return candidate
            waiting |= state == "waiting"
    if not waiting:
        _finish(db, run, rows, now)
    else:
        db.commit()
    return None


def _dispatch(db: Session, now: dt.datetime) -> None:
    running = list(db.scalars(select(SyncStep).where(SyncStep.status.in_(("starting", "running")))
                             .order_by(SyncStep.id).limit(256)))
    for row in running:
        _monitor(db, row, now)
    db.commit()
    if any(row.status == "running" for row in running):
        return

    # Complete/cancel old runs before considering the next queued request.
    for _ in range(100):
        run = db.scalar(select(SyncRun).where(SyncRun.status.in_(service.ACTIVE)).order_by(SyncRun.id).limit(1))
        if run is None:
            return
        rows = service.steps(db, run)
        if run.cancel_requested:
            for row in rows:
                if row.status in PENDING:
                    _fail(row, "Отменено пользователем", now, "cancelled")
            _finish(db, run, rows, now)
            continue
        candidate = _choose(db, run, rows, now)
        if candidate is None:
            if run.status in service.TERMINAL:
                continue
            return
        try:
            task = _authorized_task(db, run, candidate)
            candidate.status = "starting"
            candidate.started_at = now
            candidate.message = ""
            db.commit()
            ref = start_task(db, task, run.actor, candidate.options)
            if ref is None:
                candidate.status = "waiting"
                candidate.message = "Ожидание завершения другой задачи источника"
            else:
                candidate.job_model, candidate.job_id = ref.model, ref.id
                candidate.status = "running"
                candidate.attempts += 1
                run.status = "running"
                run.started_at = run.started_at or now
                from api.platform.scheduler import PlatformSchedule
                schedule = db.scalar(select(PlatformSchedule).where(PlatformSchedule.last_run_id == run.id,
                    PlatformSchedule.module == task.module, PlatformSchedule.kind == task.kind,
                    PlatformSchedule.target_id == task.target_id).limit(1))
                if schedule is not None:
                    schedule.last_job_id = ref.id
            db.commit()
        except Exception as exc:  # noqa: BLE001 — persist a module launch failure as the step outcome
            db.rollback()
            candidate = db.get(SyncStep, candidate.id)
            if candidate is None:
                return
            from .adapters import SourceUnavailable
            if isinstance(exc, SourceUnavailable) and run.origin == "schedule":
                from api.platform.scheduler import PlatformSchedule
                schedule = db.scalar(select(PlatformSchedule).where(PlatformSchedule.last_run_id == run.id).limit(1))
                if schedule is not None:
                    schedule.enabled = False
                    schedule.next_run_at = None
            _fail(candidate, str(exc.detail) if isinstance(exc, HTTPException) else safe_error(exc), now)
            db.commit()
        return


def dispatch(db: Session, now: dt.datetime | None = None) -> None:
    now = now or dt.datetime.now(dt.UTC)
    bind = db.get_bind()
    engine = bind if isinstance(bind, Engine) else bind.engine
    # Session-level lock survives module launchers' commits. It is released on process death.
    with engine.connect() as lock_conn:
        acquired = lock_conn.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": DISPATCH_LOCK})
        if not acquired:
            return
        try:
            _dispatch(db, now)
        finally:
            lock_conn.execute(text("SELECT pg_advisory_unlock(:key)"), {"key": DISPATCH_LOCK})
            lock_conn.commit()


class QueueWorker:
    def __init__(self) -> None:
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self, session_factory: Callable[[], Session]) -> None:
        if self.thread is not None and self.thread.is_alive():
            return
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._loop, args=(session_factory,), name="stools-sync-queue", daemon=True)
        self.thread.start()

    def _loop(self, session_factory: Callable[[], Session]) -> None:
        while not self.stop_event.wait(2):
            try:
                with session_factory() as db:
                    dispatch(db)
            except Exception:
                log.exception("Не удалось обработать очередь синхронизаций")

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=5)
