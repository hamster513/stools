"""Библиотека хантов Threat Hunting: CRUD, выключатели, проверка запроса, импорт и выгрузка YAML.

Правила сохранения (код, запросы, «интерфейс главнее») живут в `hunting.library`
и `hunting.yaml_io`; здесь только HTTP: поиск ханта, коды ответов и вид для экрана.
Находки и прогоны читаются из чужих таблиц и только для показа: «новые» находки
считаются по платформенному статусу (`state_map`) одним запросом на ответ.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import InstrumentedAttribute

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.hosts import take_slot
from api.limits import TH_YAML_UPLOAD, check_upload_size
from api.modules.siem.hunting import library as lib
from api.modules.siem.hunting import yaml_io
from api.modules.siem.hunting.events_client import EventsClient, make_client, public_error
from api.modules.siem.hunting.library import HuntIn, LibraryError
from api.modules.siem.hunting.models import ThFinding, ThHunt, ThQuery, ThRunQuery
from api.modules.siem.hunting.pdql import build_pdql, split_fields
from api.modules.siem.services.kb_settings import load_connection
from api.platform.findings.service import effective_status, state_map

router = APIRouter(tags=["siem"])

MODULE = "siem_th"
SCOPE_ID = 1
NOT_CONFIGURED = "подключение не настроено: нужны адрес и API-токен"
RUNS_SHOWN = 30
FINDINGS_SHOWN = 50
#: Проверка запроса смотрит только последний час и просит одно событие: цель — принял ли MaxPatrol запрос.
CHECK_WINDOW = dt.timedelta(hours=1)


class EnabledIn(BaseModel):
    enabled: bool


class CheckIn(BaseModel):
    query: str
    fields: str


class CheckOut(BaseModel):
    ok: bool
    message: str


def _library_error(exc: LibraryError) -> HTTPException:
    """Занятый код — конфликт с существующим хантом, остальное — ошибка в присланных данных."""
    code = status.HTTP_409_CONFLICT if str(exc).startswith("код занят") else status.HTTP_422_UNPROCESSABLE_CONTENT
    return HTTPException(code, detail=str(exc))


def _hunt(db: Session, hunt_id: int) -> ThHunt:
    hunt = db.get(ThHunt, hunt_id)
    if hunt is None or hunt.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="хант не найден")
    return hunt


def _latest_runs(db: Session, column: InstrumentedAttribute[Any], values: list[Any]) -> dict[Any, ThRunQuery]:
    """Последняя запись истории на каждое значение колонки — одним запросом, а не по запросу на хант."""
    if not values:
        return {}
    newest = select(func.max(ThRunQuery.id)).where(column.in_(values)).group_by(column)
    rows = db.scalars(select(ThRunQuery).where(ThRunQuery.id.in_(newest)))
    return {getattr(row, column.key): row for row in rows}


def _statuses(db: Session, finding_ids: list[int]) -> dict[int, str]:
    states = state_map(db, MODULE, SCOPE_ID, [f"th:{i}" for i in finding_ids])
    return {i: effective_status(states.get(f"th:{i}")) for i in finding_ids}


def _last_run(row: ThRunQuery | None) -> dict[str, Any] | None:
    return None if row is None else {"at": row.started_at, "status": row.status}


class HuntRow(BaseModel):
    id: int
    code: str
    name: str
    technique_id: str | None
    enabled: bool
    queries: int
    last_run: dict[str, Any] | None
    new_findings: int
    updated_at: dt.datetime


@router.get("/hunts", response_model=list[HuntRow])
def list_hunts(
    enabled: bool | None = None, technique: str | None = None, q: str | None = None,
    db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> list[HuntRow]:
    needle = (q or "").strip().casefold()
    hunts = [
        h for h in lib.list_hunts(db)
        if (enabled is None or h.enabled == enabled)
        and (not technique or h.technique_id == technique)
        and (not needle or needle in h.code.casefold() or needle in h.name.casefold())
    ]
    ids = [h.id for h in hunts]
    counts = {
        hunt_id: n for hunt_id, n in db.execute(
            select(ThQuery.hunt_id, func.count()).where(ThQuery.hunt_id.in_(ids)).group_by(ThQuery.hunt_id),
        )
    }
    last = _latest_runs(db, ThRunQuery.hunt_code, [h.code for h in hunts])
    findings = [(fid, hunt_id) for fid, hunt_id in db.execute(select(ThFinding.id, ThFinding.hunt_id).where(ThFinding.hunt_id.in_(ids)))]
    state = _statuses(db, [fid for fid, _ in findings])
    fresh: dict[int, int] = {}
    for fid, hunt_id in findings:
        if state[fid] == "new":
            fresh[hunt_id] = fresh.get(hunt_id, 0) + 1
    return [
        HuntRow(
            id=h.id, code=h.code, name=h.name, technique_id=h.technique_id, enabled=h.enabled,
            queries=counts.get(h.id, 0), last_run=_last_run(last.get(h.code)),
            new_findings=fresh.get(h.id, 0), updated_at=h.updated_at,
        )
        for h in hunts
    ]


class QueryView(BaseModel):
    id: int
    query_id: str
    position: int
    query: str
    fields: str
    fields_label: str
    limit: int | None
    enabled: bool
    last: dict[str, Any] | None
    new_findings: int


class RunView(BaseModel):
    id: int
    query_id: str
    status: str
    started_at: dt.datetime | None
    duration_ms: int | None
    events: int
    error: str | None
    finding_id: int | None


class FindingRow(BaseModel):
    id: int
    kind: str
    query_id: str
    period_from: dt.datetime
    period_to: dt.datetime
    event_count: int
    created_at: dt.datetime
    status: str


class HuntView(BaseModel):
    id: int
    code: str
    name: str
    description: str
    technique_id: str | None
    enabled: bool
    updated_at: dt.datetime
    updated_by: str
    queries: list[QueryView]
    runs: list[RunView]
    findings: list[FindingRow]


def _view(db: Session, hunt: ThHunt) -> HuntView:
    queries = lib.hunt_queries(db, hunt)
    last = _latest_runs(db, ThRunQuery.query_pk, [q.id for q in queries])
    pairs = [(fid, query_id) for fid, query_id in db.execute(select(ThFinding.id, ThFinding.query_id).where(ThFinding.hunt_id == hunt.id))]
    recent = list(db.scalars(
        select(ThFinding).where(ThFinding.hunt_id == hunt.id).order_by(ThFinding.id.desc()).limit(FINDINGS_SHOWN),
    ))
    state = _statuses(db, [fid for fid, _ in pairs])
    fresh: dict[str, int] = {}
    for fid, query_id in pairs:
        if state[fid] == "new":
            fresh[query_id] = fresh.get(query_id, 0) + 1
    runs = db.scalars(
        select(ThRunQuery).where(ThRunQuery.hunt_code == hunt.code).order_by(ThRunQuery.id.desc()).limit(RUNS_SHOWN),
    )
    views = []
    for q in queries:
        _, fields, labels, _ = lib.stored_view(q)
        row = last.get(q.id)
        views.append(QueryView(
            id=q.id, query_id=q.query_id, position=q.position, query=q.query,
            fields=", ".join(fields), fields_label=", ".join(labels), limit=q.limit, enabled=q.enabled,
            last=None if row is None else {"at": row.started_at, "events": row.events, "status": row.status},
            new_findings=fresh.get(q.query_id, 0),
        ))
    return HuntView(
        id=hunt.id, code=hunt.code, name=hunt.name, description=hunt.description, technique_id=hunt.technique_id,
        enabled=hunt.enabled, updated_at=hunt.updated_at, updated_by=hunt.updated_by, queries=views,
        runs=[RunView(
            id=r.id, query_id=r.query_id, status=r.status, started_at=r.started_at, duration_ms=r.duration_ms,
            events=r.events, error=r.error, finding_id=r.finding_id,
        ) for r in runs],
        findings=[FindingRow(
            id=f.id, kind=f.kind, query_id=f.query_id, period_from=f.period_from, period_to=f.period_to,
            event_count=f.event_count, created_at=f.created_at, status=state[f.id],
        ) for f in recent],
    )


@router.post("/hunts", response_model=HuntView, status_code=status.HTTP_201_CREATED)
def create_hunt(
    payload: HuntIn, request: Request, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> HuntView:
    try:
        hunt = lib.create_hunt(db, payload, user.login)
    except LibraryError as exc:
        raise _library_error(exc) from exc
    request.state.audit_summary = f"создан хант {hunt.code}"
    return _view(db, hunt)


@router.get("/hunts/{hunt_id}", response_model=HuntView)
def get_hunt(hunt_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> HuntView:
    return _view(db, _hunt(db, hunt_id))


@router.put("/hunts/{hunt_id}", response_model=HuntView)
def put_hunt(
    hunt_id: int, payload: HuntIn, request: Request, db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> HuntView:
    hunt = _hunt(db, hunt_id)
    try:
        # Код ханта не меняется: на него ссылаются находки и история прогонов.
        lib.update_hunt(db, hunt, payload.model_copy(update={"code": hunt.code}), user.login)
    except LibraryError as exc:
        raise _library_error(exc) from exc
    request.state.audit_summary = f"изменён хант {hunt.code}"
    return _view(db, hunt)


@router.delete("/hunts/{hunt_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_hunt(
    hunt_id: int, request: Request, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> Response:
    hunt = _hunt(db, hunt_id)
    lib.delete_hunt(db, hunt, user.login)
    request.state.audit_summary = f"удалён хант {hunt.code}"
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/hunts/{hunt_id}/enabled", response_model=HuntView)
def set_hunt_enabled(
    hunt_id: int, payload: EnabledIn, request: Request, db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> HuntView:
    hunt = _hunt(db, hunt_id)
    lib.set_enabled(db, hunt, payload.enabled, user.login)
    request.state.audit_summary = f"хант {hunt.code}: {'включён' if payload.enabled else 'выключен'}"
    return _view(db, hunt)


@router.post("/queries/check", response_model=CheckOut)
def check_query(
    payload: CheckIn, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> CheckOut:
    """Принимает ли MaxPatrol запрос: один вызов событий за последний час. Результат не сохраняется."""
    fields = split_fields(payload.fields)
    if not payload.query.strip() or not fields:
        return CheckOut(ok=False, message="запрос и поля обязательны")
    conn = load_connection(db)
    if not conn.configured:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=NOT_CONFIGURED)
    now = dt.datetime.now(dt.UTC)
    slot = take_slot("siem", user.id)
    try:
        with make_client(conn, 30.0) as http:
            found = EventsClient(conn.unsealed(), http).search(
                build_pdql(payload.query.strip(), fields), now - CHECK_WINDOW, now, 1,
            )
    # Любая причина отказа доходит до человека классом, без адреса, токена и текста ответа.
    except Exception as exc:  # noqa: BLE001
        return CheckOut(ok=False, message=public_error(exc))
    finally:
        slot.release()
    return CheckOut(ok=True, message="запрос принят" + (", за последний час есть события" if found else ", за последний час событий нет"))


def _read_yaml(file: UploadFile) -> list[HuntIn]:
    data = file.file.read(TH_YAML_UPLOAD + 1)
    check_upload_size(len(data), TH_YAML_UPLOAD)
    try:
        return yaml_io.parse_library_yaml(data)
    except LibraryError as exc:
        raise _library_error(exc) from exc


class PreviewOut(BaseModel):
    rows: list[yaml_io.ImportRow]
    hunts: int


@router.post("/library/import/preview", response_model=PreviewOut)
def import_preview(
    file: UploadFile = File(...), db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> PreviewOut:
    hunts = _read_yaml(file)
    return PreviewOut(rows=yaml_io.preview_import(db, hunts), hunts=len(hunts))


@router.post("/library/import")
def import_library(
    request: Request, file: UploadFile = File(...), replace: str = Form(""), db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> dict[str, int]:
    hunts = _read_yaml(file)
    codes = {c.strip() for c in replace.split(",") if c.strip()}
    try:
        result = yaml_io.apply_import(db, hunts, codes, user.login)
    except LibraryError as exc:
        raise _library_error(exc) from exc
    request.state.audit_summary = (
        f"импорт: создано {result['created']}, заменено {result['replaced']}, пропущено {result['skipped']}"
    )
    return result


@router.get("/library/export")
def export_library(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> Response:
    name = f"th-library-{dt.datetime.now(dt.UTC):%Y-%m-%d}.yaml"
    return Response(
        yaml_io.export_library_yaml(db), media_type="text/yaml",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@router.post("/queries/{query_pk}/enabled", response_model=HuntView)
def set_query_enabled(
    query_pk: int, payload: EnabledIn, request: Request, db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> HuntView:
    query = db.get(ThQuery, query_pk)
    hunt = None if query is None else _hunt(db, query.hunt_id)
    if query is None or hunt is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="запрос не найден")
    lib.set_query_enabled(db, query, payload.enabled, user.login)
    request.state.audit_summary = f"{hunt.code}/{query.query_id}: {'включён' if payload.enabled else 'выключен'}"
    return _view(db, hunt)
