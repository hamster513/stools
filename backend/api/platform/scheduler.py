"""Планировщик платформы: расписания модулей в `platform_schedule` (спека Assets §5).

Поток в `lifespan` раз в `period_s` берёт включённые расписания с
`next_run_at <= now` и вызывает обработчик, который модуль зарегистрировал
через `register_schedule_kind`. Обработчик запускает обычную задачу модуля
(`start_job`/`run_job`) и возвращает её id; `None` — модуль занят, запуск
откладывается на следующий тик, а не на интервал.

Срок следующего запуска хранится в базе, а не в памяти: после перезапуска
API просроченные расписания уходят на первом же тике. API — один процесс
(как и реестр задач в `api/jobs.py`), поэтому блокировка между копиями
планировщика не нужна.

Окно `window_from..window_to` — время UTC: так же хранятся все даты платформы.
"""
from __future__ import annotations

import datetime as dt
import logging
import threading
from collections.abc import Callable

from sqlalchemy import Boolean, DateTime, Integer, String, UniqueConstraint, select
from sqlalchemy.orm import Mapped, Session, mapped_column, sessionmaker

from api.db.models import Base, _utcnow

log = logging.getLogger("stools.scheduler")


class PlatformSchedule(Base):
    __tablename__ = "platform_schedule"
    #: Одно расписание на цель: форма сети или DNS-сервера правит его, а не добавляет новое.
    __table_args__ = (UniqueConstraint("module", "kind", "target_id", name="uq_platform_schedule_target"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    module: Mapped[str] = mapped_column(String(32))
    kind: Mapped[str] = mapped_column(String(32))
    target_id: Mapped[int] = mapped_column(Integer)
    interval_hours: Mapped[int] = mapped_column(Integer)
    #: HH:MM, оба пустые — без окна.
    window_from: Mapped[str | None] = mapped_column(String(5), nullable=True)
    window_to: Mapped[str | None] = mapped_column(String(5), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    next_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)


#: Обработчик получает сессию тика и расписание; возвращает id запущенной задачи или None (занято).
Handler = Callable[[Session, PlatformSchedule], int | None]

_handlers: dict[tuple[str, str], Handler] = {}


def register_schedule_kind(module: str, kind: str, fn: Handler) -> None:
    _handlers[(module, kind)] = fn


def _minutes(hhmm: str) -> int:
    hours, minutes = hhmm.split(":")
    return int(hours) * 60 + int(minutes)


def next_run(after: dt.datetime, interval_hours: int, window_from: str | None, window_to: str | None) -> dt.datetime:
    """Ближайший момент ≥ after + interval, попадающий в окно HH:MM..HH:MM (конец окна не входит;
    окно через полночь допускается; без окна — ровно after + interval)."""
    candidate = after + dt.timedelta(hours=interval_hours)
    if not window_from or not window_to:
        return candidate
    start, end = _minutes(window_from), _minutes(window_to)
    now = candidate.hour * 60 + candidate.minute
    inside = start <= now < end if start < end else (now >= start or now < end)
    if inside:
        return candidate
    # Вне окна — значит, до его начала сегодня или после конца; во втором случае начало завтра.
    opening = candidate.replace(hour=start // 60, minute=start % 60, second=0, microsecond=0)
    return opening if opening > candidate else opening + dt.timedelta(days=1)


def tick(db: Session, now: dt.datetime, *, period_s: float = 60) -> list[int]:
    """Одна итерация: выбрать enabled с next_run_at <= now, вызвать обработчик, записать
    last_run_at/last_job_id, next_run_at; вернуть id запущенных задач. Каждое расписание —
    своей транзакцией: ошибка одного обработчика не отменяет запуски остальных."""
    due = db.execute(
        select(PlatformSchedule.id)
        .where(PlatformSchedule.enabled.is_(True), PlatformSchedule.next_run_at <= now)
        .order_by(PlatformSchedule.next_run_at, PlatformSchedule.id)
    ).scalars().all()
    started: list[int] = []
    for schedule_id in due:
        sched = db.get(PlatformSchedule, schedule_id)
        if sched is None:
            continue
        module, kind = sched.module, sched.kind
        handler = _handlers.get((module, kind))
        if handler is None:
            log.warning("расписание %s: обработчика %s/%s нет", schedule_id, module, kind)
            sched.next_run_at = next_run(now, sched.interval_hours, sched.window_from, sched.window_to)
            db.commit()
            continue
        try:
            job_id = handler(db, sched)
        except Exception:
            db.rollback()
            log.exception("расписание %s (%s/%s): обработчик упал", schedule_id, module, kind)
            # Следующая попытка — через интервал: сломанный обработчик не должен срабатывать каждую минуту.
            sched = db.get(PlatformSchedule, schedule_id)
            if sched is not None:
                sched.next_run_at = next_run(now, sched.interval_hours, sched.window_from, sched.window_to)
                db.commit()
            continue
        if job_id is None:
            sched.next_run_at = now + dt.timedelta(seconds=period_s)
        else:
            sched.last_run_at = now
            sched.last_job_id = job_id
            sched.next_run_at = next_run(now, sched.interval_hours, sched.window_from, sched.window_to)
            started.append(job_id)
        db.commit()
    return started


def upsert_schedule(
    db: Session,
    *,
    module: str,
    kind: str,
    target_id: int,
    interval_hours: int,
    window_from: str | None,
    window_to: str | None,
    enabled: bool,
    now: dt.datetime | None = None,
) -> PlatformSchedule:
    """Создать или изменить расписание цели; срок пересчитывается от `now`, если поменялись
    интервал, окно или его включили. Фиксирует вызывающий — вместе с самой целью."""
    now = now or _utcnow()
    sched = db.execute(
        select(PlatformSchedule).where(
            PlatformSchedule.module == module, PlatformSchedule.kind == kind, PlatformSchedule.target_id == target_id,
        )
    ).scalar_one_or_none()
    timing = (interval_hours, window_from, window_to)
    if sched is None:
        sched = PlatformSchedule(module=module, kind=kind, target_id=target_id)
        db.add(sched)
        changed = True
    else:
        changed = (sched.interval_hours, sched.window_from, sched.window_to) != timing or (enabled and not sched.enabled)
    sched.interval_hours, sched.window_from, sched.window_to = timing
    sched.enabled = enabled
    if changed:
        sched.next_run_at = next_run(now, interval_hours, window_from, window_to)
    db.flush()
    return sched


def delete_schedule(db: Session, schedule_id: int) -> None:
    sched = db.get(PlatformSchedule, schedule_id)
    if sched is not None:
        db.delete(sched)
        db.flush()


class Scheduler:
    """Поток-тикер. Демон: зависший обработчик не должен держать остановку процесса."""

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, session_factory: sessionmaker[Session], period_s: float = 60) -> None:
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, args=(session_factory, period_s), name="stools-scheduler", daemon=True,
        )
        self._thread.start()

    def stop(self, timeout_s: float = 10) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout_s)
            self._thread = None

    def _loop(self, session_factory: sessionmaker[Session], period_s: float) -> None:
        # Сначала пауза: при старте API база занята уборкой задач, а просроченное подождёт тик.
        while not self._stop.wait(period_s):
            try:
                with session_factory() as db:
                    tick(db, _utcnow(), period_s=period_s)
            except Exception:
                log.exception("тик планировщика не выполнен")
