"""Планировщик платформы: расписания модулей в `platform_schedule` (спека Assets §5).

Поток в `lifespan` раз в `period_s` берёт включённые расписания с
`next_run_at <= now` и вызывает обработчик, который модуль зарегистрировал
через `register_schedule_kind`. Обработчик запускает обычную задачу модуля
(`start_job`/`run_job`) и возвращает её id; `None` — модуль занят, запуск
откладывается на следующий тик, а не на интервал. Обработчик без задачи
(`jobless=True`, например истечение принятых рисков) делает работу сам, в
тике: вернулся без исключения — значит, отработал, и следующий запуск — через
интервал.

Срок следующего запуска хранится в базе, а не в памяти: после перезапуска
API просроченные расписания уходят на первом тике (через `period_s` после
старта). API — один процесс (как и реестр задач в `api/jobs.py`), поэтому
блокировка между копиями планировщика не нужна.

Окно `window_from..window_to` — местное время пояса `STOOLS_TZ` (по умолчанию
UTC); сроки `next_run_at`/`last_run_at` хранятся в UTC, как все даты платформы.
"""
from __future__ import annotations

import datetime as dt
import logging
import re
import threading
from collections.abc import Callable
from zoneinfo import ZoneInfo

from sqlalchemy import Boolean, DateTime, Integer, String, UniqueConstraint, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Mapped, Session, mapped_column, sessionmaker

from api.db.models import Base, _utcnow
from api.settings import get_settings

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
#: Обработчики без задачи: их ответ не id задачи, и `None` не значит «занято».
_jobless: set[tuple[str, str]] = set()


def register_schedule_kind(module: str, kind: str, fn: Handler, *, jobless: bool = False) -> None:
    _handlers[(module, kind)] = fn
    if jobless:
        _jobless.add((module, kind))
    else:
        _jobless.discard((module, kind))


_HHMM = re.compile(r"([01]\d|2[0-3]):[0-5]\d")


def _check_window(window_from: str | None, window_to: str | None) -> None:
    """Окно — оба конца HH:MM или ни одного; иначе ValueError."""
    if (window_from is None) != (window_to is None):
        raise ValueError("окно расписания: задайте оба конца (с и по) или ни одного")
    for value in (window_from, window_to):
        if value is not None and not _HHMM.fullmatch(value):
            raise ValueError(f"окно расписания: {value!r} — не время ЧЧ:ММ (00:00–23:59)")


def _minutes(hhmm: str) -> int:
    hours, minutes = hhmm.split(":")
    return int(hours) * 60 + int(minutes)


def next_run(
    after: dt.datetime, interval_hours: int, window_from: str | None, window_to: str | None, tz: str = "UTC",
) -> dt.datetime:
    """Ближайший момент ≥ after + interval, попадающий в окно HH:MM..HH:MM местного времени `tz`
    (конец окна не входит; окно через полночь допускается; без окна — ровно after + interval).
    Результат — в UTC. Битое окно — ValueError."""
    _check_window(window_from, window_to)
    candidate = after + dt.timedelta(hours=interval_hours)
    if window_from is None or window_to is None:
        return candidate
    local = candidate.astimezone(ZoneInfo(tz))
    start, end = _minutes(window_from), _minutes(window_to)
    now = local.hour * 60 + local.minute
    inside = start <= now < end if start < end else (now >= start or now < end)
    if inside:
        return candidate
    # Вне окна — значит, до его начала сегодня или после конца; во втором случае начало завтра.
    opening = local.replace(hour=start // 60, minute=start % 60, second=0, microsecond=0)
    if opening <= local:
        opening += dt.timedelta(days=1)
    return opening.astimezone(dt.UTC)


def tick(db: Session, now: dt.datetime, *, period_s: float = 60, tz: str = "UTC") -> list[int]:
    """Одна итерация: выбрать enabled с next_run_at <= now, вызвать обработчик, записать
    last_run_at/last_job_id, next_run_at; вернуть id запущенных задач. Каждое расписание —
    своей транзакцией: ошибка одного обработчика не отменяет запуски остальных. Расписание
    с битым окном в базе выключается, а не запускается каждый тик."""
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
        # До обработчика: с битым окном срок не посчитать, и задача запускалась бы каждый тик.
        try:
            nxt = next_run(now, sched.interval_hours, sched.window_from, sched.window_to, tz)
        except ValueError as exc:
            log.warning("расписание %s (%s/%s) выключено: %s", schedule_id, module, kind, exc)
            sched.enabled = False
            sched.next_run_at = None
            db.commit()
            continue
        handler = _handlers.get((module, kind))
        if handler is None:
            log.warning("расписание %s: обработчика %s/%s нет", schedule_id, module, kind)
            sched.next_run_at = nxt
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
                sched.next_run_at = nxt
                db.commit()
            continue
        if (module, kind) in _jobless:
            sched.last_run_at = now
            sched.next_run_at = nxt
        elif job_id is None:
            sched.next_run_at = now + dt.timedelta(seconds=period_s)
        else:
            sched.last_run_at = now
            sched.last_job_id = job_id
            sched.next_run_at = nxt
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
    tz: str | None = None,
) -> PlatformSchedule:
    """Создать или изменить расписание цели; срок пересчитывается от `now`, если поменялись
    интервал, окно или его включили. Фиксирует вызывающий — вместе с самой целью.
    Окно — в поясе `tz` (по умолчанию STOOLS_TZ); битое окно — ValueError до записи."""
    _check_window(window_from, window_to)
    now = now or _utcnow()
    tz = tz or get_settings().tz
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
        sched.next_run_at = next_run(now, interval_hours, window_from, window_to, tz)
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
        if self.alive:
            return
        # Своё событие на каждый поток: прежний, не успевший выйти по stop, остаётся остановленным.
        self._stop = threading.Event()
        tz = get_settings().tz
        self._thread = threading.Thread(
            target=self._loop, args=(session_factory, period_s, tz, self._stop),
            name="stools-scheduler", daemon=True,
        )
        self._thread.start()

    def stop(self, timeout_s: float = 10) -> None:
        self._stop.set()
        if self._thread is None:
            return
        self._thread.join(timeout_s)
        if self._thread.is_alive():
            # Ссылку не сбрасываем: поток ещё в обработчике, и повторный start не должен запустить второй.
            log.warning("планировщик не остановился за %s с: обработчик ещё работает", timeout_s)
            return
        self._thread = None

    def _loop(self, session_factory: sessionmaker[Session], period_s: float, tz: str, stop: threading.Event) -> None:
        # Первый тик — через period_s после старта, не сразу. Уборка «идущих» задач к этому
        # моменту уже прошла: lifespan запускает планировщик после неё.
        while not stop.wait(period_s):
            try:
                with session_factory() as db:
                    tick(db, _utcnow(), period_s=period_s, tz=tz)
            except OperationalError as exc:
                # База недоступна — штатная ситуация при её перезапуске; трассировка каждую минуту не нужна.
                log.warning("тик планировщика пропущен: база недоступна (%s)", str(exc.orig or exc).partition("\n")[0])
            except Exception:
                log.exception("тик планировщика не выполнен")
