"""Большой хант: один запрос за месяцы, нарезанный на куски.

MaxPatrol отвечает на длинный период 500-й, поэтому период режется, как в
скрипте владельца: свежие `hot_days` суток (быстрое хранилище) — одним
вызовом, глубже — кусками по `slice_hours` назад до начала периода, с паузой
между кусками. Порядок — от свежего к старому: самое нужное приходит первым.

Нарезка считается от момента создания (`created_at`), а не от «сейчас»:
поставленный в очередь или прерванный хант при продолжении получает те же
куски. Продолжение — с `next_slice_from`: всё новее этой границы уже собрано.
Каждый кусок фиксируется одной транзакцией (события, счётчики, граница),
поэтому отмена, сбой и перезапуск API теряют не больше одного куска, а
события полученных кусков остаются в находке с пометкой «неполная».

Ночной прогон важнее: между кусками хант проверяет, не пришла ли ночь, и
уступает (`paused`) — задача закрывается без ошибки, продолжит диспетчер.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import time
from collections.abc import Callable
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from api.hosts import LOGIN_REJECTED
from api.jobs import JobCancelled, JobHandle, insert_chunked
from api.modules.siem.hunting.events_client import (
    EventsAuthError,
    EventsClient,
    EventsError,
    make_client,
    public_error,
)
from api.modules.siem.hunting.models import ThDeepHunt, ThEvent, ThFinding, ThHunt, ThQuery, ThRun
from api.modules.siem.hunting.nightly import (
    NOT_CONFIGURED,
    RetriesExhausted,
    RunStopped,
    event_rows,
    execute_with_retries,
    persist_finding,
    sliced_wait,
)
from api.modules.siem.hunting.pdql import build_pdql
from api.modules.siem.hunting.settings import ThSettings, load_th_settings, nightly_schedule
from api.modules.siem.hunting.windows import target_date_for
from api.modules.siem.services.kb_settings import load_connection
from api.settings import get_settings
from api.timeutil import as_aware_utc, utcnow

log = logging.getLogger(__name__)

#: У большого ханта нет предела ночи: ожидание прерывают только отмена и уступка ночному прогону.
NO_DEADLINE = dt.datetime.max.replace(tzinfo=dt.UTC)

Slice = tuple[dt.datetime, dt.datetime]


class RowCancelled(JobCancelled):
    """Строку ханта уже отменили (ручка отмены), а задача об этом ещё не узнала: задача
    закрывается отменённой, строка не трогается — отмена уже записала в неё итог."""


def slices(
    period_from: dt.datetime, period_to: dt.datetime, *, now: dt.datetime, hot_days: int, slice_hours: int,
) -> list[Slice]:
    """Куски периода от свежего к старому: горячий `(max(period_from, now − hot_days), period_to)`,
    затем по `slice_hours` назад до `period_from` (последний укорочен). Куски стыкуются без
    зазоров; пустые не включаются, период целиком глубже горячего окна — без горячего куска."""
    hot_edge = max(period_from, now - dt.timedelta(days=hot_days))
    result: list[Slice] = []
    if hot_edge < period_to:
        result.append((hot_edge, period_to))
    end = min(hot_edge, period_to)
    step = dt.timedelta(hours=slice_hours)
    while end > period_from:
        start = max(period_from, end - step)
        result.append((start, end))
        end = start
    return result


def _plan(deep: ThDeepHunt, settings: ThSettings) -> list[Slice]:
    return slices(
        as_aware_utc(deep.period_from), as_aware_utc(deep.period_to), now=as_aware_utc(deep.created_at),
        hot_days=settings.hot_days, slice_hours=settings.slice_hours,
    )


def remaining(deep: ThDeepHunt, settings: ThSettings) -> list[Slice]:
    """Куски, которые ещё не собраны: старше `next_slice_from`. Если настройки нарезки поменялись
    на паузе, кусок на границе подрезается — собранное не запрашивается второй раз."""
    plan = _plan(deep, settings)
    if deep.next_slice_from is None:
        return plan
    edge = as_aware_utc(deep.next_slice_from)
    return [(start, min(end, edge)) for start, end in plan if start < edge]


def create_deep(
    db: Session,
    *,
    title: str,
    hunt: ThHunt | None,
    query: ThQuery | None,
    query_text: str,
    fields: list[str],
    labels: list[str],
    limit: int,
    period_from: dt.datetime,
    period_to: dt.datetime,
    login: str,
    now: dt.datetime | None = None,
    query_id: str | None = None,
    is_full_pdql: bool = False,
) -> ThDeepHunt:
    """Большой хант в очереди со своей копией запроса: правка библиотеки его не меняет.
    `query_id` — номер запроса без самого запроса: повтор ханта, чей запрос библиотеки уже удалён."""
    if period_from >= period_to:
        raise ValueError("период: начало должно быть раньше конца")
    settings = load_th_settings(db)
    deep = ThDeepHunt(
        title=title,
        hunt_id=hunt.id if hunt else None,
        query_id=query.query_id if query else query_id,
        query=query_text,
        is_full_pdql=query.is_full_pdql if query is not None else is_full_pdql,
        fields_json=json.dumps(fields, ensure_ascii=False),
        labels_json=json.dumps(labels, ensure_ascii=False),
        limit=limit,
        period_from=period_from,
        period_to=period_to,
        status="queued",
        created_by=login,
        created_at=now or utcnow(),
    )
    deep.slices_total = len(_plan(deep, settings))
    db.add(deep)
    db.commit()
    return deep


def nightly_due(db: Session, now: dt.datetime) -> bool:
    """Пора уступить ночному прогону: прогон на текущую дату ночи ждёт или идёт, либо срок
    ночного расписания наступил, а прогон на дату ещё не заведён. Срок берётся из расписания,
    а не из часа окна: иначе после установки (прогона на сегодня нет и не будет до следующей
    ночи) большой хант уступал бы целые сутки."""
    settings = load_th_settings(db)
    target = target_date_for(now, settings.window_from, get_settings().tz)
    run = db.scalar(select(ThRun).where(ThRun.target_date == target, ThRun.status != "superseded"))
    if run is not None:
        return run.status in ("queued", "running")
    if not settings.nightly_enabled:
        return False
    sched = nightly_schedule(db)
    return (
        sched is not None and sched.enabled and sched.next_run_at is not None
        and as_aware_utc(sched.next_run_at) <= as_aware_utc(now)
    )


def run_deep(
    db: Session,
    handle: JobHandle,
    deep_id: int,
    *,
    sleeper: Callable[[float], None] = time.sleep,
    clock: Callable[[], dt.datetime] = utcnow,
) -> None:
    """Выполнить (или продолжить) большой хант. Итог фиксируется здесь же; исключение наружу —
    только чтобы `run_job` закрыл задачу как cancelled/failed."""
    deep = db.get(ThDeepHunt, deep_id)
    if deep is None or deep.status not in ("queued", "running", "paused"):
        return
    try:
        _execute(db, handle, deep, load_th_settings(db), sleeper, clock)
    except (RunStopped, RowCancelled):
        raise
    except JobCancelled:
        db.rollback()
        _finish(db, deep, "cancelled", clock, partial=True)
        raise
    except EventsError as exc:
        db.rollback()
        if isinstance(exc, EventsAuthError):
            error = LOGIN_REJECTED
        elif isinstance(exc, RetriesExhausted):
            error = str(exc)
        else:
            error = public_error(exc)
        _finish(db, deep, "failed", clock, error, partial=True)
        raise RunStopped(error) from exc
    except Exception as exc:
        db.rollback()
        # В хант и задачу — только класс: текст исключения может нести адрес. Подробности — в журнал.
        log.exception("сбой большого ханта %s", deep_id)
        error = f"сбой большого ханта: {type(exc).__name__}"
        _finish(db, deep, "failed", clock, error, partial=True)
        raise RunStopped(error) from exc


def _finding(db: Session, deep: ThDeepHunt) -> ThFinding | None:
    return db.scalar(select(ThFinding).where(ThFinding.deep_id == deep.id))


def _finish(
    db: Session, deep: ThDeepHunt, status: str, clock: Callable[[], dt.datetime],
    error: str | None = None, *, partial: bool = False,
) -> None:
    deep.status = status
    deep.error = error
    deep.partial = partial
    deep.finished_at = clock()
    finding = _finding(db, deep)
    if finding is not None:
        finding.partial = partial
    db.commit()


def _execute(
    db: Session,
    handle: JobHandle,
    deep: ThDeepHunt,
    settings: ThSettings,
    sleeper: Callable[[float], None],
    clock: Callable[[], dt.datetime],
) -> None:
    conn = load_connection(db)
    rest = remaining(deep, settings)
    total = deep.slices_done + len(rest)
    deep.status, deep.job_id, deep.error, deep.slices_total = "running", handle.id, None, total
    db.commit()
    handle.stage("running", total=total, message=f"кусок {deep.slices_done} из {total}")
    if not conn.configured:
        _finish(db, deep, "failed", clock, NOT_CONFIGURED)
        raise RunStopped(NOT_CONFIGURED)

    fields: list[str] = json.loads(deep.fields_json)
    labels: list[str] = json.loads(deep.labels_json)
    pdql = build_pdql(deep.query, fields, is_full_pdql=deep.is_full_pdql)
    wait = sliced_wait(sleeper, handle, clock, NO_DEADLINE)
    with make_client(conn, float(settings.request_timeout_s)) as http:
        client = EventsClient(conn.unsealed(), http)
        for index, (start, end) in enumerate(rest):
            if index:
                wait(settings.slice_pause_s)
            if nightly_due(db, clock()):
                # Условно: отмена могла записать `cancelled` после нашего чтения, и «пауза» поверх
                # неё вернула бы хант в очередь диспетчера.
                paused = db.execute(
                    update(ThDeepHunt).where(ThDeepHunt.id == deep.id, ThDeepHunt.status == "running")
                    .values(status="paused").returning(ThDeepHunt.id).execution_options(synchronize_session=False),
                ).scalar()
                db.commit()
                if paused is None:
                    raise RowCancelled()
                log.info("большой хант %s уступил ночному прогону на куске %s из %s", deep.id, deep.slices_done + 1, total)
                return
            handle.tick(deep.slices_done, message=f"кусок {deep.slices_done + 1} из {total}, {_span(start, end)}")
            found = execute_with_retries(client, pdql, start, end, deep.limit, settings, wait)
            _append(db, deep, found, fields, labels)
            deep.slices_done += 1
            deep.next_slice_from = start
            if len(found) >= deep.limit:
                deep.limit_hit_slices += 1
            db.commit()
    _finish(db, deep, "done", clock)


def _append(db: Session, deep: ThDeepHunt, found: list[dict[str, Any]], fields: list[str], labels: list[str]) -> None:
    """События куска — в находку ханта; она заводится на первом куске с событиями и одна на весь период.
    Пустой кусок находки не заводит: как у ночного прогона, хант без событий кончается без находки."""
    if not found:
        return
    from api.modules.siem.hunting.pdql import event_fields
    fields = fields or json.loads(deep.fields_json) or event_fields(found)
    if not json.loads(deep.fields_json):
        deep.fields_json = json.dumps(fields, ensure_ascii=False)
    finding = _finding(db, deep)
    if finding is None:
        hunt = db.get(ThHunt, deep.hunt_id) if deep.hunt_id is not None else None
        finding = persist_finding(
            db, kind="deep", hunt=hunt, query=None, period_from=deep.period_from, period_to=deep.period_to,
            events=[], fields=fields, labels=labels, limit=deep.limit, deep_id=deep.id,
        )
        finding.query_id = deep.query_id or ""
    kept = found[: deep.limit]
    insert_chunked(db, ThEvent, event_rows(finding.id, kept, fields, finding.event_count), len(kept), None, "событий")
    finding.event_count += len(kept)
    finding.limit_hit = finding.limit_hit or len(found) >= deep.limit
    deep.events += len(kept)


def _span(start: dt.datetime, end: dt.datetime) -> str:
    return f"{start:%d.%m.%Y %H:%M}–{end:%d.%m.%Y %H:%M} UTC"
