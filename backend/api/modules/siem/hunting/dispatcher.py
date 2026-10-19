"""Диспетчер задач Threat Hunting: одна задача раздела за раз, очередь — в базе.

Очередь не хранится отдельно: это прогоны `th_run` в `queued`/`running` и
большие ханты в `running`/`paused`/`queued`. `kick` смотрит, свободен ли
раздел, и запускает следующее: сначала ночной прогон (он важнее), затем
большой хант — прерванный, уступивший ночи, ждущий, по порядку создания.
Пока ночь «должна» идти, большой хант не стартует: иначе он сразу уступил
бы и диспетчер гонял бы его по кругу. По завершении задачи поток сам
вызывает `kick` — следующий из очереди стартует без участия расписания;
расписание `th_dispatch` раз в час подбирает то, что осталось (перезапуск
API, сбой потока), и чистит события по сроку хранения.

«Раздел занят» — задача `th_job` в `running`, которую ведёт этот процесс
или которую `kick` только что завёл (поток её ещё не подхватил). Задача в
`running` без потока — сирота (уборка при старте не прошла, например база
была недоступна): она закрывается как прерванная и раздел не держит. Прогон
или большой хант в `running`, чья задача не живёт, просто продолжается — с
первого запроса без итога или со следующего куска.
"""
from __future__ import annotations

import datetime as dt
import logging
import threading
import time
from collections.abc import Callable

from sqlalchemy import case, select
from sqlalchemy.orm import Session

from api.db.base import get_sessionmaker
from api.jobs import RESTART_ERROR, JobHandle, active_job, is_live, run_job, start_job
from api.modules.siem.hunting import retention
from api.modules.siem.hunting.deep import nightly_due, run_deep
from api.modules.siem.hunting.models import ThDeepHunt, ThJob, ThRun
from api.modules.siem.hunting.nightly import create_run, run_nightly
from api.modules.siem.hunting.settings import (
    dispatch_schedule,
    ensure_th_schedules,
    load_th_settings,
    nightly_schedule,
)
from api.modules.siem.hunting.windows import target_date_for
from api.platform.scheduler import PlatformSchedule
from api.settings import get_settings
from api.timeutil import utcnow

log = logging.getLogger(__name__)

KINDS = ("nightly", "deep")
SCHEDULE_STARTED_BY = "расписание"


def _in_thread(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, name="stools-th", daemon=True).start()


#: Как задача уходит из потока вызвавшего (тик планировщика, запрос API): он не ждёт её конца.
#: Тесты подменяют на сбор в список и исполняют сами.
spawn: Callable[[Callable[[], None]], None] = _in_thread
#: Чем задачи ждут и откуда берут время; тесты подменяют, чтобы не спать по-настоящему.
sleep: Callable[[float], None] = time.sleep
clock: Callable[[], dt.datetime] = utcnow

#: Решение «раздел свободен → завести задачу» — под замком: тик планировщика и запрос API
#: не должны завести две задачи сразу.
_lock = threading.Lock()
#: Задачи, которые `kick` завёл, а поток ещё не взял (`is_live` их пока не знает).
_starting: set[int] = set()


def _busy(db: Session) -> bool:
    """Раздел занят живой задачей; задача в `running` без потока закрывается как прерванная."""
    while (job := active_job(db, ThJob, KINDS)) is not None:
        if job.id in _starting or is_live(ThJob, job.id):
            return True
        log.warning("задача Threat Hunting %s без потока закрыта как прерванная", job.id)
        job.status, job.error, job.finished_at = "failed", RESTART_ERROR, dt.datetime.now(dt.UTC)
        db.commit()
    return False


def _next(db: Session) -> tuple[str, Callable[[Session, JobHandle], None]] | None:
    run_id = db.scalar(
        select(ThRun.id).where(ThRun.status.in_(("queued", "running"))).order_by(ThRun.target_date, ThRun.id).limit(1)
    )
    if run_id is not None:
        return "nightly", lambda s, h: run_nightly(s, h, run_id, sleeper=sleep, clock=clock)
    if nightly_due(db, clock()):
        return None
    order = case({"running": 0, "paused": 1}, value=ThDeepHunt.status, else_=2)
    deep_id = db.scalar(
        select(ThDeepHunt.id)
        .where(ThDeepHunt.status.in_(("running", "paused", "queued")))
        .order_by(order, ThDeepHunt.created_at, ThDeepHunt.id)
        .limit(1)
    )
    if deep_id is not None:
        return "deep", lambda s, h: run_deep(s, h, deep_id, sleeper=sleep, clock=clock)
    return None


def kick(db: Session, *, started_by: str = SCHEDULE_STARTED_BY) -> int | None:
    """Запустить следующую задачу раздела, если он свободен; id заведённой задачи или None."""
    with _lock:
        if _busy(db):
            return None
        chosen = _next(db)
        if chosen is None:
            return None
        kind, fn = chosen
        job_id = start_job(db, ThJob, kind, started_by)
        _starting.add(job_id)
    # Вне замка: подменённый в тестах запуск исполняет задачу на месте, а она в конце сама зовёт kick.
    spawn(lambda: _run_then_kick(job_id, fn))
    return job_id


def _run_then_kick(job_id: int, fn: Callable[[Session, JobHandle], None]) -> None:
    try:
        run_job(ThJob, job_id, fn)
    finally:
        _starting.discard(job_id)
    try:
        with get_sessionmaker()() as db:
            kick(db)
    except Exception:
        # Не страшно: оставшееся подберёт часовое расписание th_dispatch.
        log.exception("следующая задача Threat Hunting не запущена")


def nightly_handler(db: Session, _sched: PlatformSchedule) -> int | None:
    """Обработчик `siem/th_nightly`: прогон на дату ночи (если его ещё нет) и `kick`.
    Если раздел занят большим хантом, прогон ждёт в очереди в базе, а планировщику уходит id
    занявшей задачи: None он понял бы как «повторить через минуту», и запоздалый успех сдвинул
    бы следующий срок за окно — на ночь позже. Прогон на дату уже завершён — ночь обработана:
    планировщику уходит его задача, `kick` не зовётся (он завёл бы большой хант, и планировщик
    записал бы его задачу как ночную)."""
    settings = load_th_settings(db)
    tz = get_settings().tz
    target = target_date_for(clock(), settings.window_from, tz)
    run = db.scalar(select(ThRun).where(ThRun.target_date == target, ThRun.status != "superseded"))
    if run is None:
        run = create_run(db, target, settings, tz)
    elif run.status not in ("queued", "running"):
        return run.job_id
    job_id = kick(db)
    if job_id is None:
        busy = active_job(db, ThJob, KINDS)
        # Прогон на дату уже был: ночь обработана его задачей.
        job_id = busy.id if busy is not None else run.job_id
    return job_id


def _heal_missed_night(db: Session) -> None:
    """Прогон за последнюю ночь, если планировщик его не завёл. Срок ночного расписания
    уползает вперёд на время запуска, и однажды окно ночи кончится раньше, чем срок наступит, —
    ночь пропадёт молча. Диспетчер тикает каждый час и закрывает эту дыру сам. Расписание, ни
    разу не срабатывавшее (свежая установка), оставлено планировщику: первую ночь заводит он."""
    settings = load_th_settings(db)
    sched = nightly_schedule(db)
    if not settings.nightly_enabled or sched is None or not sched.enabled or sched.last_run_at is None:
        return
    tz = get_settings().tz
    # target_date_for отдаёт ночь, чьё окно уже открылось к этому моменту, — её прогон уже должен быть.
    target = target_date_for(clock(), settings.window_from, tz)
    if db.scalar(select(ThRun.id).where(ThRun.target_date == target).limit(1)) is not None:
        return
    create_run(db, target, settings, tz)
    log.info("ночной прогон за %s не был создан планировщиком — создан диспетчером", target)


def dispatch_handler(db: Session, _sched: PlatformSchedule) -> None:
    """Обработчик `siem/th_dispatch` (без задачи, раз в час): завести пропущенную планировщиком
    ночь, подобрать очередь и почистить события."""
    _heal_missed_night(db)
    kick(db)
    retention.purge(db, load_th_settings(db).retention_days, now=clock())


def ensure_hunting_schedules() -> None:
    """Для lifespan: расписания раздела своей сессией. Диспетчер — на ближайший тик: прерванные
    перезапуском прогон и большой хант продолжаются через минуту после старта, а не через час."""
    with get_sessionmaker()() as db:
        ensure_th_schedules(db)
        dispatch = dispatch_schedule(db)
        assert dispatch is not None
        dispatch.next_run_at = utcnow()
        db.commit()
