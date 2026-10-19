"""Ночные прогоны Threat Hunting: история по датам, построчные итоги запросов, «Повторить за дату».

Пропущенная ночь (строки прогона на дату нет вовсе) видна в списке как пробел: диапазон
ожидаемых ночей отдаёт `GET /runs/expected` — последнюю ночь считает сервер по своему поясу,
а не браузер. Такую ночь запускают по дате (`POST /runs/rerun-date`), строки для `/{id}/rerun` у неё нет.

Повтор не запускает задачу сам: прогон встаёт в очередь в базе, а задачу
заводит диспетчер раздела (`kick`) — он один решает, свободен ли раздел.
Занят — прогон дождётся конца текущей задачи, и `job_id` в ответе пуст.
"""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.jobs import cancel_job
from api.modules.siem.hunting import dispatcher
from api.modules.siem.hunting.models import ThJob, ThRun, ThRunQuery
from api.modules.siem.hunting.nightly import supersede_and_rerun
from api.modules.siem.hunting.settings import load_th_settings
from api.modules.siem.hunting.windows import target_date_for
from api.settings import get_settings
from api.timeutil import utcnow

router = APIRouter(prefix="/runs", tags=["siem"])


class RunRow(BaseModel):
    id: int
    target_date: dt.date
    period_from: dt.datetime
    period_to: dt.datetime
    status: str
    started_at: dt.datetime | None
    finished_at: dt.datetime | None
    queries_total: int
    queries_done: int
    findings: int
    #: Запросов с итогом `failed`.
    errors: int
    error: str | None
    job_id: int | None


class RunQueryView(BaseModel):
    id: int
    query_pk: int
    hunt_code: str
    query_id: str
    status: str
    started_at: dt.datetime | None
    duration_ms: int | None
    events: int
    error: str | None
    finding_id: int | None


class RunDetail(RunRow):
    queries: list[RunQueryView]


class RerunOut(BaseModel):
    run_id: int
    job_id: int | None


class RerunDateIn(BaseModel):
    target_date: dt.date


class ExpectedOut(BaseModel):
    """Ночи, за которые прогон должен быть: от самой старой в истории до последней наступившей."""

    from_: dt.date = Field(alias="from")
    to: dt.date


def _errors(db: Session, run_ids: list[int]) -> dict[int, int]:
    if not run_ids:
        return {}
    return {run_id: n for run_id, n in db.execute(
        select(ThRunQuery.run_id, func.count())
        .where(ThRunQuery.run_id.in_(run_ids), ThRunQuery.status == "failed").group_by(ThRunQuery.run_id),
    )}


def _row(run: ThRun, errors: int) -> RunRow:
    return RunRow(
        id=run.id, target_date=run.target_date, period_from=run.period_from, period_to=run.period_to,
        status=run.status, started_at=run.started_at, finished_at=run.finished_at, queries_total=run.queries_total,
        queries_done=run.queries_done, findings=run.findings, errors=errors, error=run.error, job_id=run.job_id,
    )


@router.get("", response_model=list[RunRow])
def list_runs(
    limit: int = Query(default=60, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> list[RunRow]:
    """Свежие ночи сверху; заменённые прогоны остаются в истории под своей датой."""
    runs = list(db.scalars(
        select(ThRun).order_by(ThRun.target_date.desc(), ThRun.id.desc()).limit(limit).offset(offset),
    ))
    errors = _errors(db, [r.id for r in runs])
    return [_row(r, errors.get(r.id, 0)) for r in runs]


def _last_night(db: Session) -> dt.date:
    return target_date_for(utcnow(), load_th_settings(db).window_from, get_settings().tz)


@router.get("/expected", response_model=ExpectedOut, response_model_by_alias=True)
def expected_nights(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ExpectedOut:
    """Без истории — только последняя ночь: пробелы до установки раздела пропуском не считаются."""
    last = _last_night(db)
    oldest = db.scalar(select(func.min(ThRun.target_date)))
    return ExpectedOut.model_validate({"from": min(oldest, last) if oldest is not None else last, "to": last})


@router.post("/rerun-date", response_model=RerunOut, status_code=status.HTTP_202_ACCEPTED)
def rerun_date(
    body: RerunDateIn, request: Request, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> RerunOut:
    """«Запустить за дату» для ночи без прогона (или с прежним — тогда он заменяется, как в
    `/{id}/rerun`). Ночь, чьё окно ещё не наступило, — 422: искать за неё рано. Идущий или
    ждущий прогон даты — 409."""
    target = body.target_date
    if target > _last_night(db):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"ночь {target:%d.%m.%Y} ещё не наступила")
    try:
        new = supersede_and_rerun(db, target, user.login, load_th_settings(db), get_settings().tz)
    # Как в rerun: отказ приходит до любых изменений, rollback не нужен.
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None
    request.state.audit_summary = f"ночной прогон за {target:%d.%m.%Y} запущен вручную: прогон #{new.id}"
    return RerunOut(run_id=new.id, job_id=dispatcher.kick(db, started_by=user.login))


def _run(db: Session, run_id: int) -> ThRun:
    run = db.get(ThRun, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="прогон не найден")
    return run


@router.get("/{run_id}", response_model=RunDetail)
def get_run(run_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> RunDetail:
    run = _run(db, run_id)
    queries = db.scalars(select(ThRunQuery).where(ThRunQuery.run_id == run.id).order_by(ThRunQuery.id))
    views = [RunQueryView(
        id=q.id, query_pk=q.query_pk, hunt_code=q.hunt_code, query_id=q.query_id, status=q.status,
        started_at=q.started_at, duration_ms=q.duration_ms, events=q.events, error=q.error, finding_id=q.finding_id,
    ) for q in queries]
    return RunDetail(**_row(run, sum(v.status == "failed" for v in views)).model_dump(), queries=views)


@router.post("/{run_id}/rerun", response_model=RerunOut, status_code=status.HTTP_202_ACCEPTED)
def rerun(
    run_id: int, request: Request, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> RerunOut:
    """«Повторить за дату»: новый прогон на дату этого, прежний живой — заменённый. Идущий
    или ждущий прогон даты не заменяется — 409."""
    target = _run(db, run_id).target_date
    try:
        new = supersede_and_rerun(db, target, user.login, load_th_settings(db), get_settings().tz)
    # Отказ приходит до любых изменений: незавершённый прогон даты не трогается. Без rollback —
    # он погасил бы и пользователя запроса, которого журнал действий читает после ответа.
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None
    request.state.audit_summary = f"повтор ночного прогона за {target:%d.%m.%Y}: прогон #{new.id}"
    return RerunOut(run_id=new.id, job_id=dispatcher.kick(db, started_by=user.login))


@router.post("/{run_id}/cancel", response_model=RunRow)
def cancel_run(
    run_id: int, request: Request, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> RunRow:
    """Ждущий прогон — `cancelled` сразу; идущий — ещё и просьба задаче остановиться. Строка
    меняется условно: прогон, который задача успела закрыть, остаётся со своим итогом — 409."""
    run = _run(db, run_id)
    if run.status == "running" and run.job_id is not None:
        try:
            cancel_job(db, ThJob, run.job_id)
        except HTTPException as exc:
            # Задача уже закрыта, а строка осталась «идёт»: снять её всё равно надо,
            # иначе диспетчер продолжит прогон.
            if exc.status_code not in (status.HTTP_404_NOT_FOUND, status.HTTP_409_CONFLICT):
                raise
    matched = db.execute(
        update(ThRun).where(ThRun.id == run_id, ThRun.status.in_(("queued", "running")))
        .values(status="cancelled", finished_at=utcnow()).returning(ThRun.id)
        .execution_options(synchronize_session=False),
    ).scalar()
    db.commit()
    if matched is None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="прогон уже завершён")
    db.refresh(run)
    request.state.audit_summary = f"ночной прогон за {run.target_date:%d.%m.%Y} отменён"
    return _row(run, _errors(db, [run.id]).get(run.id, 0))
