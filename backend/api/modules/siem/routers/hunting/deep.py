"""Большие ханты Threat Hunting: запуск руками, список, карточка, отмена, повтор, сохранение в библиотеку.

Запуск ставит хант в очередь в базе (`queued`) и зовёт диспетчер раздела:
задачу заводит только он, одну на раздел, остальные ждут. Хант хранит свою
копию запроса — из библиотеки (поля из формы поверх) или свой; библиотека
от запуска не меняется.

Отмена действует на строку ханта, а не только на задачу: у ждущего и
уступившего ночи задачи нет вовсе, а задачу идущего могли снять раньше, чем
её взял поток, — без отметки в строке диспетчер запустил бы хант снова.
"""
from __future__ import annotations

import calendar
import datetime as dt
import json

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.jobs import cancel_job
from api.modules.siem.hunting import dispatcher
from api.modules.siem.hunting import library as lib
from api.modules.siem.hunting.deep import create_deep
from api.modules.siem.hunting.library import HuntIn, LibraryError, QueryIn
from api.modules.siem.hunting.models import ThDeepHunt, ThFinding, ThHunt, ThJob, ThQuery
from api.modules.siem.hunting.nightly import TH_MODULE, TH_SCOPE, finding_key
from api.modules.siem.hunting.pdql import align_labels, split_fields
from api.modules.siem.hunting.settings import load_th_settings
from api.modules.siem.routers.hunting.findings import FindingDetail, finding_detail
from api.modules.siem.routers.hunting.library import HuntView, _library_error, _view
from api.platform.findings.service import effective_status, state_map
from api.timeutil import as_aware_utc, utcnow

router = APIRouter(prefix="/deep", tags=["siem"])

#: Как у запроса библиотеки: потолок предела событий одного вызова.
LIMIT_MAX = 100_000
TITLE_WORDS = 60
#: Состояния, в которых хант ещё может что-то сделать.
ACTIVE = ("queued", "running", "paused")


class DeepIn(BaseModel):
    """Либо `hunt_query_id` (копия запроса библиотеки, присланные поля — поверх), либо `query` + `fields`.
    Период — `period_from` и `period_to` вместе либо `months` назад от сейчас (умолчание — из настроек)."""

    title: str | None = Field(default=None, max_length=255)
    hunt_query_id: int | None = None
    query: str | None = None
    fields: str | None = None
    fields_label: str | None = None
    limit: int | None = Field(default=None, ge=1, le=LIMIT_MAX)
    months: int | None = Field(default=None, ge=1, le=36)
    period_from: dt.datetime | None = None
    period_to: dt.datetime | None = None


class SaveIn(BaseModel):
    code: str = Field(max_length=64)
    name: str = Field(max_length=255)


class SourceView(BaseModel):
    hunt_code: str
    query_id: str | None


class DeepView(BaseModel):
    id: int
    title: str
    source: SourceView | None
    period_from: dt.datetime
    period_to: dt.datetime
    status: str
    slices_done: int
    slices_total: int
    events: int
    finding_id: int | None
    #: Статус платформы у находки ханта; находки ещё нет — null.
    status_state: str | None
    job_id: int | None
    created_by: str
    created_at: dt.datetime


class DeepDetail(DeepView):
    query: str
    fields: list[str]
    labels: list[str]
    limit: int
    limit_hit_slices: int
    partial: bool
    error: str | None
    finished_at: dt.datetime | None
    finding: FindingDetail | None


def _unprocessable(detail: str) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=detail)


def _views(db: Session, deeps: list[ThDeepHunt]) -> list[DeepView]:
    """Источник, находка и её статус — тремя запросами на весь список, а не по запросу на хант."""
    hunt_ids = {d.hunt_id for d in deeps if d.hunt_id is not None}
    codes: dict[int, str] = {
        hunt_id: code for hunt_id, code in db.execute(select(ThHunt.id, ThHunt.code).where(ThHunt.id.in_(hunt_ids)))
    }
    found: dict[int, int] = {
        deep_id: fid for deep_id, fid in db.execute(
            select(ThFinding.deep_id, ThFinding.id).where(ThFinding.deep_id.in_([d.id for d in deeps])),
        ) if deep_id is not None
    }
    states = state_map(db, TH_MODULE, TH_SCOPE, [finding_key(f) for f in found.values()])
    views = []
    for d in deeps:
        fid = found.get(d.id)
        code = codes.get(d.hunt_id) if d.hunt_id is not None else None
        views.append(DeepView(
            id=d.id, title=d.title, source=SourceView(hunt_code=code, query_id=d.query_id) if code else None,
            period_from=d.period_from, period_to=d.period_to, status=d.status, slices_done=d.slices_done,
            slices_total=d.slices_total, events=d.events, finding_id=fid,
            status_state=effective_status(states.get(finding_key(fid))) if fid is not None else None,
            job_id=d.job_id, created_by=d.created_by, created_at=d.created_at,
        ))
    return views


def _detail(db: Session, deep: ThDeepHunt) -> DeepDetail:
    (view,) = _views(db, [deep])
    finding = db.scalar(select(ThFinding).where(ThFinding.deep_id == deep.id))
    return DeepDetail(
        **view.model_dump(), query=deep.query, fields=json.loads(deep.fields_json), labels=json.loads(deep.labels_json),
        limit=deep.limit, limit_hit_slices=deep.limit_hit_slices, partial=deep.partial, error=deep.error,
        finished_at=deep.finished_at, finding=finding_detail(db, finding) if finding is not None else None,
    )


def _deep(db: Session, deep_id: int) -> ThDeepHunt:
    deep = db.get(ThDeepHunt, deep_id)
    if deep is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="большой хант не найден")
    return deep


def months_back(moment: dt.datetime, months: int) -> dt.datetime:
    """Тот же день N календарных месяцев назад; дня нет в том месяце (31-е) — последний день месяца."""
    total = moment.year * 12 + moment.month - 1 - months
    year, month0 = divmod(total, 12)
    day = min(moment.day, calendar.monthrange(year, month0 + 1)[1])
    return moment.replace(year=year, month=month0 + 1, day=day)


def _period(db: Session, payload: DeepIn, now: dt.datetime) -> tuple[dt.datetime, dt.datetime]:
    if payload.period_from is not None or payload.period_to is not None:
        if payload.period_from is None or payload.period_to is None:
            raise _unprocessable("период: нужны обе даты — начало и конец")
        return as_aware_utc(payload.period_from), as_aware_utc(payload.period_to)
    months = payload.months or load_th_settings(db).default_depth_months
    return months_back(now, months), now


def _first_words(query: str) -> str:
    return " ".join(query.split())[:TITLE_WORDS]


@router.get("", response_model=list[DeepView])
def list_deep(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[DeepView]:
    return _views(db, list(db.scalars(select(ThDeepHunt).order_by(ThDeepHunt.created_at.desc(), ThDeepHunt.id.desc()))))


@router.post("", response_model=DeepView, status_code=status.HTTP_202_ACCEPTED)
def start_deep(
    payload: DeepIn, request: Request, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> DeepView:
    settings = load_th_settings(db)
    hunt: ThHunt | None = None
    query: ThQuery | None = None
    if payload.hunt_query_id is not None:
        query = db.get(ThQuery, payload.hunt_query_id)
        hunt = db.get(ThHunt, query.hunt_id) if query is not None else None
        if query is None or hunt is None or hunt.deleted_at is not None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="запрос библиотеки не найден")
        text, fields, labels, limit = lib.stored_view(query)
        default_title = f"{hunt.code} {query.query_id}"
    else:
        text, fields, labels, limit = "", [], [], None
        default_title = ""
    if payload.query is not None and payload.query.strip():
        text = payload.query.strip()
    if payload.fields is not None and split_fields(payload.fields):
        fields = split_fields(payload.fields)
        labels = align_labels(fields, payload.fields_label or "")
    elif payload.fields_label is not None:
        labels = align_labels(fields, payload.fields_label)
    if not text or not fields:
        raise _unprocessable("запрос и поля обязательны")
    now = utcnow()
    period_from, period_to = _period(db, payload, now)
    title = (payload.title or "").strip() or default_title or _first_words(text)
    try:
        deep = create_deep(
            db, title=title, hunt=hunt, query=query, query_text=text, fields=fields, labels=labels,
            limit=payload.limit or limit or settings.default_limit, period_from=period_from, period_to=period_to,
            login=user.login, now=now,
        )
    except ValueError as exc:
        raise _unprocessable(str(exc)) from None
    request.state.audit_summary = f"большой хант #{deep.id} «{title}» поставлен в очередь"
    dispatcher.kick(db, started_by=user.login)
    db.refresh(deep)
    return _views(db, [deep])[0]


@router.get("/{deep_id}", response_model=DeepDetail)
def get_deep(deep_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> DeepDetail:
    return _detail(db, _deep(db, deep_id))


@router.post("/{deep_id}/cancel", response_model=DeepView)
def cancel_deep(
    deep_id: int, request: Request, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> DeepView:
    """Ждущий и уступивший ночи — `cancelled` сразу; идущий — ещё и просьба задаче остановиться.
    Собранное до отмены остаётся в находке с пометкой «неполная»."""
    deep = _deep(db, deep_id)
    if deep.status not in ACTIVE:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="большой хант уже завершён")
    if deep.status == "running" and deep.job_id is not None:
        try:
            cancel_job(db, ThJob, deep.job_id)
        except HTTPException as exc:
            # Задача уже закрыта (перезапуск API, сбой потока), а строка осталась «идёт»:
            # её всё равно надо снять, иначе диспетчер продолжит хант.
            if exc.status_code not in (status.HTTP_404_NOT_FOUND, status.HTTP_409_CONFLICT):
                raise
    # Условно: между чтением и записью задача могла закрыть хант (`done`) — итог не затираем.
    slices_done = db.execute(
        update(ThDeepHunt).where(ThDeepHunt.id == deep_id, ThDeepHunt.status.in_(ACTIVE))
        .values(status="cancelled", partial=ThDeepHunt.slices_done > 0, finished_at=utcnow())
        .returning(ThDeepHunt.slices_done).execution_options(synchronize_session=False),
    ).scalar()
    if slices_done is None:
        db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, detail="большой хант уже завершён")
    db.execute(update(ThFinding).where(ThFinding.deep_id == deep_id).values(partial=slices_done > 0))
    db.commit()
    db.refresh(deep)
    request.state.audit_summary = f"большой хант #{deep.id} отменён"
    return _views(db, [deep])[0]


@router.post("/{deep_id}/rerun", response_model=DeepView, status_code=status.HTTP_202_ACCEPTED)
def rerun_deep(
    deep_id: int, request: Request, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> DeepView:
    """Новый хант с тем же запросом, полями, пределом и периодом; прежний остаётся как был."""
    old = _deep(db, deep_id)
    hunt = db.get(ThHunt, old.hunt_id) if old.hunt_id is not None else None
    new = create_deep(
        db, title=old.title, hunt=hunt, query=None, query_text=old.query, fields=json.loads(old.fields_json),
        labels=json.loads(old.labels_json), limit=old.limit, period_from=old.period_from, period_to=old.period_to,
        # Запрос библиотеки мог быть уже удалён — номер запроса берётся из копии, а не из библиотеки.
        login=user.login, query_id=old.query_id,
    )
    request.state.audit_summary = f"большой хант #{old.id} запущен ещё раз: #{new.id}"
    dispatcher.kick(db, started_by=user.login)
    db.refresh(new)
    return _views(db, [new])[0]


@router.post("/{deep_id}/save-to-library", response_model=HuntView, status_code=status.HTTP_201_CREATED)
def save_to_library(
    deep_id: int, payload: SaveIn, request: Request, db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> HuntView:
    """Свой запрос — в библиотеку выключенным хантом с одним запросом: в ночь он пойдёт, только
    когда человек его включит. Запрос, взятый из библиотеки, там уже есть — 409."""
    deep = _deep(db, deep_id)
    if deep.hunt_id is not None or deep.query_id is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="запрос взят из библиотеки — он уже там")
    data = HuntIn(code=payload.code, name=payload.name, enabled=False, queries=[QueryIn(
        query_id="Q1", query=deep.query, fields=", ".join(json.loads(deep.fields_json)),
        fields_label=", ".join(json.loads(deep.labels_json)), limit=deep.limit,
    )])
    try:
        hunt = lib.create_hunt(db, data, user.login)
    except LibraryError as exc:
        raise _library_error(exc) from exc
    request.state.audit_summary = f"запрос большого ханта #{deep.id} сохранён в библиотеку: {hunt.code}"
    return _view(db, hunt)
