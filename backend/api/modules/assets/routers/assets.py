"""Реестр активов: список с фасетами, карточка, ручные поля, объединение, отвязка,
закрепление полей, синхронизация с модулями и её расписание, массовая смена статуса
расхождений (статусы находок платформы)."""
from __future__ import annotations

import datetime as dt
import uuid
from itertools import batched
from typing import Any, Literal

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.jobs import active_job, run_job, start_job
from api.modules.assets.core.discrepancies import CODES
from api.modules.assets.findings_adapter import MODULE, SCOPE
from api.modules.assets.findings_adapter import reconcile as reconcile_findings
from api.modules.assets.models import AssetJob
from api.modules.assets.services.assets import (
    ANY_CODE,
    CRITICALITY,
    SOURCES,
    AssetConflict,
    AssetNotFound,
    asset_detail,
    bulk_update,
    delete_assets,
    detach_observation,
    discrepancy_keys,
    list_assets,
    lookup_asset,
    matching_ids,
    merge_assets,
    pin_field,
    update_manual,
)
from api.modules.assets.services.sync import (
    SCHEDULE_TARGET_ID,
    sync_job,
    sync_status,
    try_lock_in_transaction,
)
from api.platform.export import Column, export_response
from api.platform.filters import QueryInts, QueryList, multi, multi_int
from api.platform.findings import service as finding_svc
from api.platform.findings.core import STATUSES, RoleRequired, TransitionError
from api.platform.findings.router import ChangeBody
from api.platform.schedule_views import ScheduleIn, ScheduleView, schedule_view
from api.platform.scheduler import PlatformSchedule, delete_schedule, upsert_schedule

router = APIRouter(tags=["assets"])

MAX_LIMIT = 500
#: Столько активов можно выбрать «всеми по фильтру» и изменить одним запросом.
MAX_BULK = 50_000
#: Ключей расхождений за один вызов `bulk_change` — как у ручки массовой смены платформы.
DISC_BULK_CHUNK = 5000
TASK_WRITING = "идёт запись результатов задачи — повторите позже"


class JobStarted(BaseModel):
    job_id: int


class AssetPatch(BaseModel):
    """Только ручные поля; не переданное поле не меняется."""

    criticality: Literal["Critical", "High", "Medium", "Low", ""] | None = None
    tags: list[str] | None = Field(default=None, max_length=50)
    note: str | None = Field(default=None, max_length=4000)
    network_id: int | None = None
    network_manual: bool | None = None


class BulkIn(BaseModel):
    """Массовое изменение: теги добавляются и снимаются, не переданная критичность не меняется."""

    ids: list[int] = Field(min_length=1, max_length=MAX_BULK)
    criticality: Literal["Critical", "High", "Medium", "Low", ""] | None = None
    tags_add: list[str] = Field(default_factory=list, max_length=50)
    tags_remove: list[str] = Field(default_factory=list, max_length=50)


class DiscrepancyBulkIn(BaseModel):
    """Смена статуса расхождения кода `code` у отмеченных активов; `change` — как у `/api/findings/bulk`."""

    ids: list[int] = Field(min_length=1, max_length=MAX_BULK)
    code: str = Field(max_length=32)
    change: ChangeBody


class IdsIn(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=MAX_BULK)


class PinIn(BaseModel):
    field: Literal["name", "fqdn", "domain", "ip", "os"]
    pinned: bool


class MergeIn(BaseModel):
    other_id: int


def _errors(fn: Any, *args: Any) -> Any:
    try:
        return fn(*args)
    except AssetNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from None
    except AssetConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from None


def _check(value: str | frozenset[str] | None, allowed: tuple[str, ...]) -> None:
    for v in sorted({value} if isinstance(value, str) else value or ()):
        if v not in allowed:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"неизвестное значение фильтра «{v}»")


def _filters(
    q: str | None = None,
    source_has: QueryList = None,
    source_missing: QueryList = None,
    code: QueryList = None,
    network_id: QueryInts = None,
    zone: QueryList = None,
    port: int | None = Query(default=None, ge=1, le=65535),
    tag: str | None = None,
    criticality: QueryList = None,
    disc_status: QueryList = None,
    assignee: QueryList = None,
    overdue: bool | None = None,
) -> dict[str, Any]:
    """Фильтры списка — одни и те же у страницы списка и у выбора «всех по фильтру». `disc_status`
    (коды статусов повтором ключа или через запятую, или `all`), `assignee` (`me`, `none`, логины) и
    `overdue` — про расхождения: актив подходит, если у него есть расхождение под ними (и под `code`,
    если он задан). Фасеты `code, source_has, source_missing, criticality, zone, assignee, network_id` —
    повтором ключа, внутри фасета «или»."""
    picked = {"source_has": multi(source_has), "source_missing": multi(source_missing), "code": multi(code),
              "zone": multi(zone), "criticality": multi(criticality)}
    _check(picked["source_has"], SOURCES)
    _check(picked["source_missing"], SOURCES)
    _check(picked["code"], (*CODES, ANY_CODE))
    _check(picked["criticality"], (*CRITICALITY, "none", ""))
    _check(multi(disc_status, commas=True), STATUSES)
    return {
        "q": q, **picked, "network_id": multi_int(network_id), "port": port, "tag": tag,
        "disc_status": disc_status, "assignee": assignee, "overdue": overdue,
    }


@router.get("/assets")
def get_assets(
    filters: dict[str, Any] = Depends(_filters),
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    items, total, facets = list_assets(db, **filters, limit=limit, offset=offset, login=user.login)
    return {"total": total, "items": items, "facets": facets if offset == 0 else None}


@router.get("/assets/ids")
def get_asset_ids(
    filters: dict[str, Any] = Depends(_filters), db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Id всех активов под фильтрами (не больше `MAX_BULK`) — для выбора «всех по фильтру»."""
    ids = matching_ids(db, **filters, login=user.login)
    return {"total": len(ids), "ids": ids[:MAX_BULK]}


#: Подписи источников — как на экране (SOURCE_LABELS фронтенда).
SOURCE_TITLES = {"vm": "VM", "ksc": "KSC", "ad": "AD", "scan": "Скан", "dns": "DNS", "rt": "RT"}
#: Выгрузке нужен весь отбор: страница списка ограничена `MAX_LIMIT`, здесь — нет.
EXPORT_ALL = 10**9

EXPORT_COLUMNS = [
    Column("name", "Имя"), Column("ip", "IP"), Column("network", "Сеть"), Column("zone", "Зона"), Column("os", "ОС"),
    Column("sources", "Источники"), Column("last_seen", "Виден"), Column("discrepancies", "Расхождения"),
]


@router.get("/assets/export")
def export_assets(
    filters: dict[str, Any] = Depends(_filters),
    fmt: str = Query(default="csv", alias="format"),
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """Активы под фильтрами списка, в его порядке — тот же отбор (`list_assets`) без страницы."""
    items, _total, _facets = list_assets(db, **filters, limit=EXPORT_ALL, offset=0, login=user.login)
    rows = [
        {"name": a["name"], "ip": a["ip"], "network": a["network"]["cidr"] if a["network"] else None,
         "zone": a["network"]["zone"] if a["network"] else None, "os": a["os"],
         "sources": ", ".join(SOURCE_TITLES.get(src["source"], src["source"]) for src in a["sources"]),
         "last_seen": dt.datetime.fromisoformat(a["last_seen"]) if a["last_seen"] else None, "discrepancies": a["discrepancy_count"]}
        for a in items
    ]
    return export_response(fmt, EXPORT_COLUMNS, rows, module="assets", name="assets")


@router.post("/assets/bulk")
def bulk(payload: BulkIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, int]:
    if payload.criticality is None and not payload.tags_add and not payload.tags_remove:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="не задано, что менять: критичность или теги")
    updated = bulk_update(db, payload.ids, criticality=payload.criticality, tags_add=payload.tags_add, tags_remove=payload.tags_remove)
    db.commit()
    return {"updated": updated}


@router.post("/assets/discrepancies/bulk")
def bulk_discrepancies(
    payload: DiscrepancyBulkIn, request: Request, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> dict[str, int]:
    """Статус, исполнитель, срок расхождения `code` у отмеченных активов — одним массовым действием
    (`bulk_id`). Ключи — расхождения, которые у этих активов есть сейчас; права — как у
    `/api/findings/bulk` (принять риск — по `risk_accept_role`, 403)."""
    _check(payload.code, CODES)
    change = payload.change.to_change()
    what = payload.change.describe()
    try:
        # До первого куска: отказ по правилам не должен оставить смену сделанной наполовину.
        finding_svc.check_change(db, change, actor=user)
    except TransitionError as exc:
        code = status.HTTP_403_FORBIDDEN if isinstance(exc, RoleRequired) else status.HTTP_422_UNPROCESSABLE_CONTENT
        raise HTTPException(code, detail=str(exc)) from None
    keys = discrepancy_keys(db, payload.ids, payload.code)
    bulk_id = uuid.uuid4().hex
    request.state.audit_summary = f"{MODULE}: находок {len(keys)}; {what}; bulk_id {bulk_id}"
    changed = 0
    try:
        for chunk in batched(keys, DISC_BULK_CHUNK):
            changed += finding_svc.bulk_change(db, module=MODULE, scope_id=SCOPE, keys=list(chunk), change=change,
                                               actor=user, bulk_id=bulk_id)
    except TransitionError as exc:
        db.rollback()
        code = status.HTTP_403_FORBIDDEN if isinstance(exc, RoleRequired) else status.HTTP_422_UNPROCESSABLE_CONTENT
        raise HTTPException(code, detail=f"изменено {changed} из {len(keys)}, дальше отказ: {exc}") from None
    request.state.audit_summary = f"{MODULE}: изменено находок {changed} из {len(keys)}; {what}; bulk_id {bulk_id}"
    return {"changed": changed}


@router.get("/assets/{asset_id}")
def get_asset(asset_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    return dict(_errors(asset_detail, db, asset_id))


@router.patch("/assets/{asset_id}")
def patch_asset(asset_id: int, payload: AssetPatch, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    _errors(update_manual, db, asset_id, payload.model_dump(include=payload.model_fields_set))
    db.commit()
    if payload.model_fields_set & {"network_id", "network_manual"}:
        reconcile_findings(db, f"сеть актива #{asset_id} изменена вручную")
    return dict(asset_detail(db, asset_id))


@router.post("/assets/bulk-delete")
def bulk_delete(payload: IdsIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, int]:
    """Удаление вручную: актив с наблюдениями исчезает; если источник его ещё видит — вернётся при синхронизации."""
    _no_running_sync(db)
    deleted = delete_assets(db, payload.ids)
    db.commit()
    return {"deleted": deleted}


@router.delete("/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(asset_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> Response:
    _no_running_sync(db)
    if delete_assets(db, [asset_id]) == 0:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="актив не найден")
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/assets/{asset_id}/pin")
def pin(asset_id: int, payload: PinIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    _errors(pin_field, db, asset_id, payload.field, payload.pinned)
    db.commit()
    reconcile_findings(db, f"поле актива #{asset_id} закреплено вручную")
    return dict(asset_detail(db, asset_id))


def _no_running_sync(db: Session) -> None:
    """Синхронизация держит индекс активов в памяти и вернула бы наблюдения туда, где их видела.
    Запись результатов скана или DNS идёт под той же блокировкой: она берётся до конца запроса."""
    running = active_job(db, AssetJob, ("sync",))
    if running is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"идёт синхронизация #{running.id}, дождитесь её")
    if not try_lock_in_transaction(db):
        raise HTTPException(status.HTTP_409_CONFLICT, detail=TASK_WRITING)


@router.post("/assets/{asset_id}/merge")
def merge(asset_id: int, payload: MergeIn, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    _no_running_sync(db)
    _errors(merge_assets, db, asset_id, payload.other_id, user.login)
    db.commit()
    reconcile_findings(db, f"актив #{payload.other_id} объединён с #{asset_id}")
    return dict(asset_detail(db, asset_id))


@router.post("/observations/{observation_id}/detach")
def detach(observation_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    _no_running_sync(db)
    fresh = _errors(detach_observation, db, observation_id)
    db.commit()
    reconcile_findings(db, f"наблюдение #{observation_id} отвязано в актив #{fresh.id}")
    return dict(asset_detail(db, fresh.id))


@router.post("/sync", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
def start_sync(background_tasks: BackgroundTasks, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> JobStarted:
    running = active_job(db, AssetJob, ("sync",))
    if running is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"идёт синхронизация #{running.id}, дождитесь её")
    job_id = start_job(db, AssetJob, "sync", user.login, message="вручную")
    background_tasks.add_task(run_job, AssetJob, job_id, lambda s, h: sync_job(s, h, "вручную"))
    return JobStarted(job_id=job_id)


def _sync_schedule(db: Session) -> PlatformSchedule | None:
    return db.execute(
        select(PlatformSchedule).where(
            PlatformSchedule.module == "assets", PlatformSchedule.kind == "sync", PlatformSchedule.target_id == SCHEDULE_TARGET_ID,
        )
    ).scalar_one_or_none()


@router.get("/sync/schedule", response_model=ScheduleView | None)
def get_sync_schedule(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ScheduleView | None:
    sched = _sync_schedule(db)
    return schedule_view(sched) if sched is not None else None


@router.put("/sync/schedule", response_model=ScheduleView)
def put_sync_schedule(payload: ScheduleIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ScheduleView:
    try:
        sched = upsert_schedule(
            db, module="assets", kind="sync", target_id=SCHEDULE_TARGET_ID, interval_hours=payload.interval_hours,
            window_from=payload.window_from or None, window_to=payload.window_to or None, enabled=payload.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from None
    db.commit()
    return schedule_view(sched)


@router.delete("/sync/schedule", status_code=status.HTTP_204_NO_CONTENT)
def remove_sync_schedule(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> Response:
    sched = _sync_schedule(db)
    if sched is not None:
        delete_schedule(db, sched.id)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/sync/status")
def get_sync_status(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    return sync_status(db)


@router.get("/lookup")
def lookup(
    source: str,
    key: str = Query(min_length=1, max_length=512),
    server_id: int | None = None,
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, int]:
    """Актив хоста модуля по ключу наблюдения: KSC — `server_id:host_id` (или `host_id` и
    `server_id` отдельно), VM — `hostname|ip`, AD — SID компьютера; 404 — не сопоставлен."""
    _check(source, SOURCES)
    if source == "ksc" and server_id is not None:
        key = f"{server_id}:{key}"
    return {"asset_id": _errors(lookup_asset, db, source, key)}
