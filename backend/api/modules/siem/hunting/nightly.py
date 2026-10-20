"""Ночной прогон Threat Hunting: все включённые запросы библиотеки за сутки.

Прогон — строка `th_run` на дату ночи с границами окна как данными: даже
опоздавший старт ищет свои сутки. Очередь не хранится отдельно — это
включённые запросы, у которых в истории прогона ещё нет итога, поэтому
после перезапуска API прогон продолжается с первого незавершённого запроса.
Для этого строка истории пишется до вызова, а находка с событиями и итог
запроса фиксируются сразу, одной транзакцией.

Повторы при 500/таймауте задерживают очередь по графику, как в скрипте
владельца; 401 останавливает ночь: с непринятым токеном остальные запросы
дали бы тот же отказ. Предел длительности ночи не даёт прогону наехать на
следующую ночь. В тексты ошибок прогона идёт только класс причины
(`public_error`) — без адреса, токена и ответа сервера.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import time
from collections.abc import Callable, Iterator, Sequence
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from api.hosts import LOGIN_REJECTED
from api.jobs import JobCancelled, JobHandle, insert_chunked
from api.modules.siem.hunting.events_client import (
    EventsAuthError,
    EventsClient,
    EventsError,
    EventsRetryable,
    make_client,
    public_error,
)
from api.modules.siem.hunting.library import stored_view
from api.modules.siem.hunting.models import ThEvent, ThFinding, ThHunt, ThQuery, ThRun, ThRunQuery
from api.modules.siem.hunting.pdql import build_pdql
from api.modules.siem.hunting.settings import ThSettings, load_th_settings
from api.modules.siem.hunting.windows import nightly_window
from api.modules.siem.services.kb_settings import load_connection
from api.platform.findings.models import FindingState
from api.timeutil import as_aware_utc, utcnow

log = logging.getLogger(__name__)

#: Статусы находок хантов — платформенный механизм: модуль, область и ключ находки.
TH_MODULE = "siem_th"
TH_SCOPE = 1
#: Итоги запроса, после которых он из очереди прогона выбывает; `running` — прерванный, его повторяют.
FINAL = ("ok", "failed", "skipped", "aborted")
NOT_IN_TIME = "не успели за ночь"
NOT_CONFIGURED = "подключение к MaxPatrol не настроено"
#: Ожидание (повтор, пауза) идёт кусками не длиннее этого: между ними видны отмена и предел ночи.
WAIT_SLICE_S = 30


def finding_key(finding_id: int) -> str:
    return f"th:{finding_id}"


class RetriesExhausted(EventsError):
    """Повторы по графику кончились; текст — класс последней причины, без данных ответа."""


class RunStopped(Exception):
    """Прогон закрыт и зафиксирован в базе; исключение лишь переводит задачу в failed с этим текстом."""


class OutOfTime(Exception):
    """Ожидание закончилось бы за пределом ночи: текущий и оставшиеся запросы — `skipped`."""


def sliced_wait(
    sleeper: Callable[[float], None], handle: JobHandle, clock: Callable[[], dt.datetime], deadline: dt.datetime,
) -> Callable[[float], None]:
    """Ожидание кусками по `WAIT_SLICE_S`: график повторов тянется до получаса, и всё это время
    отмена человека и предел ночи должны срабатывать, а не ждать конца паузы."""

    def wait(seconds: float) -> None:
        remaining = float(seconds)
        while True:
            if as_aware_utc(clock()) + dt.timedelta(seconds=remaining) > deadline:
                raise OutOfTime()
            if remaining <= 0:
                return
            step = min(WAIT_SLICE_S, remaining)
            sleeper(step)
            remaining -= step
            if handle.cancelled():
                raise JobCancelled()

    return wait


def _live_run(db: Session, target_date: dt.date) -> ThRun | None:
    return db.scalar(select(ThRun).where(ThRun.target_date == target_date, ThRun.status != "superseded"))


def create_run(db: Session, target_date: dt.date, settings: ThSettings, tz: str) -> ThRun:
    """Прогон на дату ночи в очереди. Одна ночь — один прогон: замена — только через `supersede_and_rerun`."""
    if _live_run(db, target_date) is not None:
        raise ValueError(f"прогон за {target_date:%d.%m.%Y} уже есть")
    period_from, period_to = nightly_window(target_date, settings.window_from, tz)
    run = ThRun(target_date=target_date, period_from=period_from, period_to=period_to, status="queued")
    db.add(run)
    db.flush()
    run.queries_total = len(queue_for(db, run))
    db.commit()
    return run


def supersede_and_rerun(db: Session, target_date: dt.date, login: str, settings: ThSettings, tz: str) -> ThRun:
    """«Повторить за дату»: прежний прогон помечается заменённым, его находки, с которыми ещё
    не работали (нет строки статуса), удаляются вместе с событиями; находки со статусом
    остаются — по ним уже идёт работа. Идущий или ждущий прогон не заменяется: его поток
    продолжал бы писать в заменённый."""
    old = _live_run(db, target_date)
    if old is not None:
        if old.status in ("queued", "running"):
            raise ValueError(f"прогон за {target_date:%d.%m.%Y} ещё не завершён")
        old.status = "superseded"
        keys = {finding_key(fid): fid for fid in db.scalars(select(ThFinding.id).where(ThFinding.run_id == old.id))}
        with_status = set(db.scalars(select(FindingState.key).where(
            FindingState.module == TH_MODULE, FindingState.scope_id == TH_SCOPE, FindingState.key.in_(list(keys)),
        )))
        drop = [fid for key, fid in keys.items() if key not in with_status]
        if drop:
            db.execute(delete(ThFinding).where(ThFinding.id.in_(drop)))
            db.execute(update(ThRunQuery).where(ThRunQuery.finding_id.in_(drop)).values(finding_id=None))
        db.flush()
        log.info("прогон за %s заменён по просьбе %s; удалено находок без статуса: %s", target_date, login, len(drop))
    return create_run(db, target_date, settings, tz)


def queue_for(db: Session, run: ThRun) -> list[ThQuery]:
    """Включённые запросы включённых хантов без итога в этом прогоне; хант и запрос — по `position`
    (порядок хантов задаёт человек в планировщике)."""
    finished = select(ThRunQuery.query_pk).where(ThRunQuery.run_id == run.id, ThRunQuery.status.in_(FINAL))
    return list(db.scalars(
        select(ThQuery)
        .join(ThHunt, ThHunt.id == ThQuery.hunt_id)
        .where(
            ThHunt.enabled.is_(True), ThHunt.deleted_at.is_(None), ThQuery.enabled.is_(True),
            ThQuery.id.not_in(finished),
        )
        .order_by(ThHunt.position, ThHunt.id, ThQuery.position, ThQuery.id)
    ))


def execute_with_retries(
    client: EventsClient,
    pdql: str,
    time_from: dt.datetime,
    time_to: dt.datetime,
    limit: int,
    settings: ThSettings,
    sleeper: Callable[[float], None],
) -> list[dict[str, Any]]:
    """Один вызов за период; при 500/таймауте — ждать `retry_minutes[i]` минут и повторить."""
    attempt = 0
    while True:
        try:
            return client.search(pdql, time_from, time_to, limit)
        except EventsRetryable as exc:
            if attempt >= len(settings.retry_minutes):
                raise RetriesExhausted(f"исчерпаны повторы: {public_error(exc)}", exc.status) from exc
            sleeper(settings.retry_minutes[attempt] * 60)
            attempt += 1


def persist_finding(
    db: Session,
    *,
    kind: str,
    hunt: ThHunt | None,
    query: ThQuery | None,
    period_from: dt.datetime,
    period_to: dt.datetime,
    events: list[dict[str, Any]],
    fields: list[str],
    labels: list[str],
    limit: int,
    run_id: int | None = None,
    deep_id: int | None = None,
    partial: bool = False,
) -> ThFinding:
    """Находка и её события в транзакции `db` (фиксирует вызывающий). Колонки — снимок полей и
    подписей на момент прогона: запрос потом могут поправить. От события берутся только поля
    запроса: остальное, что вернул MaxPatrol, не хранится."""
    kept = events[:limit]
    labels = (list(labels) + fields[len(labels):])[: len(fields)]
    finding = ThFinding(
        kind=kind,
        hunt_id=hunt.id if hunt else None,
        hunt_code=hunt.code if hunt else "",
        query_id=query.query_id if query else "",
        run_id=run_id,
        deep_id=deep_id,
        period_from=period_from,
        period_to=period_to,
        event_count=len(kept),
        limit_hit=len(events) >= limit,
        partial=partial,
        columns_json=json.dumps(
            [{"field": f, "label": label} for f, label in zip(fields, labels, strict=True)], ensure_ascii=False,
        ),
    )
    db.add(finding)
    db.flush()
    insert_chunked(db, ThEvent, event_rows(finding.id, kept, fields), len(kept), None, "событий")
    return finding


def event_rows(
    finding_id: int, events: list[dict[str, Any]], fields: list[str], start: int = 0,
) -> Iterator[dict[str, Any]]:
    """Строки `th_event` с позиции `start`: большой хант дописывает события кусок за куском в ту же находку."""
    for i, event in enumerate(events, start):
        yield {"finding_id": finding_id, "position": i,
               "data_json": json.dumps({f: "" if event.get(f) is None else event[f] for f in fields}, ensure_ascii=False)}


def run_nightly(
    db: Session,
    handle: JobHandle,
    run_id: int,
    *,
    sleeper: Callable[[float], None] = time.sleep,
    clock: Callable[[], dt.datetime] = utcnow,
) -> None:
    """Выполнить (или продолжить) прогон. Итог прогона фиксируется здесь же; исключение наружу —
    только чтобы `run_job` закрыл задачу как cancelled/failed."""
    run = db.get(ThRun, run_id)
    if run is None or run.status not in ("queued", "running"):
        return
    current: list[ThRunQuery] = []
    try:
        _execute(db, handle, run, load_th_settings(db), sleeper, clock, current)
    except (JobCancelled, RunStopped):
        if run.status == "running":  # отмена: прогон ещё открыт
            _finish(db, run, "cancelled", clock)
        raise
    except Exception as exc:
        db.rollback()
        # В задачу уходит только класс; полный текст и трассировка — в журнал сервера для разбора.
        log.exception("сбой ночного прогона")
        error = f"сбой прогона: {type(exc).__name__}"
        for row in current:
            if row.status == "running":
                row.status, row.error = "failed", error
        _finish(db, run, "failed", clock, error)
        # Текст исходного исключения может нести адрес — в задачу уходит только класс.
        raise RunStopped(error) from exc


def _finish(db: Session, run: ThRun, status: str, clock: Callable[[], dt.datetime], error: str | None = None) -> None:
    run.status = status
    run.error = error
    run.finished_at = clock()
    db.commit()


def _close_rest(db: Session, run: ThRun, rest: Sequence[ThQuery], status: str, error: str) -> None:
    """Пометить невыполненные запросы итогом без вызова (aborted/skipped)."""
    existing = {r.query_pk: r for r in db.scalars(select(ThRunQuery).where(ThRunQuery.run_id == run.id))}
    for query in rest:
        row = existing.get(query.id) or _history_row(db, run, query)
        row.status, row.error = status, error


def _history_row(db: Session, run: ThRun, query: ThQuery) -> ThRunQuery:
    hunt = db.get(ThHunt, query.hunt_id)
    assert hunt is not None
    row = ThRunQuery(run_id=run.id, query_pk=query.id, hunt_code=hunt.code, query_id=query.query_id, status="running")
    db.add(row)
    return row


def _execute(
    db: Session,
    handle: JobHandle,
    run: ThRun,
    settings: ThSettings,
    sleeper: Callable[[float], None],
    clock: Callable[[], dt.datetime],
    current: list[ThRunQuery],
) -> None:
    conn = load_connection(db)
    queue = queue_for(db, run)
    finished = db.scalar(
        select(func.count()).select_from(ThRunQuery)
        .where(ThRunQuery.run_id == run.id, ThRunQuery.status.in_(FINAL))
    ) or 0
    total = finished + len(queue)
    run.status = "running"
    run.job_id = handle.id
    run.started_at = run.started_at or clock()
    run.queries_total = total
    db.commit()
    handle.stage("running", total=total, message=f"{finished} из {total}")
    if not conn.configured:
        _close_rest(db, run, queue, "aborted", f"прогон прерван: {NOT_CONFIGURED}")
        _finish(db, run, "aborted", clock, NOT_CONFIGURED)
        raise RunStopped(NOT_CONFIGURED)

    # Предел ночи считается от конца окна расписания, а не от старта: опоздавший прогон
    # не должен отнимать время у следующей ночи.
    deadline = as_aware_utc(run.period_to) + dt.timedelta(hours=settings.nightly_deadline_h)
    wait = sliced_wait(sleeper, handle, clock, deadline)
    index = 0
    with make_client(conn, float(settings.request_timeout_s)) as http:
        client = EventsClient(conn.unsealed(), http)
        try:
            for index, query in enumerate(queue):
                # Пауза — только при смене ханта: запросы одной гипотезы идут подряд, а нагрузку
                # на MaxPatrol разводит перерыв между хантами.
                if index and query.hunt_id != queue[index - 1].hunt_id:
                    wait(settings.hunt_pause_s)
                hunt = db.get(ThHunt, query.hunt_id)
                assert hunt is not None
                handle.tick(finished + index, message=f"{finished + index + 1} из {total}, {hunt.code}")
                if as_aware_utc(clock()) >= deadline:
                    raise OutOfTime()
                if not _run_query(db, client, run, hunt, query, settings, wait, clock, current):
                    _close_rest(db, run, queue[index + 1:], "aborted", f"прогон прерван: {LOGIN_REJECTED}")
                    _finish(db, run, "aborted", clock, LOGIN_REJECTED)
                    raise RunStopped(LOGIN_REJECTED)
        except OutOfTime:
            # Текущий запрос (строка «в работе», если ожидание прервало его повторы) и остальные.
            rest = queue[index:]
            _close_rest(db, run, rest, "skipped", NOT_IN_TIME)
            _finish(db, run, "done", clock, f"{NOT_IN_TIME}: пропущено запросов {len(rest)}")
            return
    _finish(db, run, "done", clock)


def _run_query(
    db: Session,
    client: EventsClient,
    run: ThRun,
    hunt: ThHunt,
    query: ThQuery,
    settings: ThSettings,
    sleeper: Callable[[float], None],
    clock: Callable[[], dt.datetime],
    current: list[ThRunQuery],
) -> bool:
    """Один запрос: строка истории «в работе» фиксируется до вызова, итог с находкой — сразу после.
    False — вход отклонён: итог запроса не зафиксирован, прогон закрывает вызывающий."""
    row = db.scalar(select(ThRunQuery).where(ThRunQuery.run_id == run.id, ThRunQuery.query_pk == query.id))
    if row is None:
        row = _history_row(db, run, query)
    started = clock()
    row.status, row.started_at, row.error, row.events, row.finding_id = "running", started, None, 0, None
    db.commit()
    current[:] = [row]

    text, fields, labels, query_limit = stored_view(query)
    limit = query_limit or settings.default_limit
    try:
        found = execute_with_retries(
            client, build_pdql(text, fields), run.period_from, run.period_to, limit, settings, sleeper,
        )
    except EventsAuthError as exc:
        row.status, row.error = "failed", public_error(exc)
        row.duration_ms = _ms(started, clock())
        run.queries_done += 1
        return False
    except EventsError as exc:
        row.status = "failed"
        row.error = str(exc) if isinstance(exc, RetriesExhausted) else public_error(exc)
        run.queries_done += 1
    else:
        if found:
            finding = persist_finding(
                db, kind="nightly", hunt=hunt, query=query, period_from=run.period_from, period_to=run.period_to,
                events=found, fields=fields, labels=labels, limit=limit, run_id=run.id,
            )
            row.finding_id = finding.id
            run.findings += 1
        row.status = "ok"
        row.events = min(len(found), limit)
        run.queries_done += 1
    row.duration_ms = _ms(started, clock())
    db.commit()
    return True


def _ms(start: dt.datetime, end: dt.datetime) -> int:
    return int((as_aware_utc(end) - as_aware_utc(start)).total_seconds() * 1000)
