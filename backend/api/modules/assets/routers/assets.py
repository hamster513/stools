"""Реестр активов: список с фасетами, карточка, ручные поля, объединение, отвязка,
закрепление полей, синхронизация с модулями и её расписание, массовая смена статуса
расхождений (статусы находок платформы)."""
from __future__ import annotations

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
from api.modules.assets.routers.scan import ScheduleIn, ScheduleView, schedule_view
from api.modules.assets.services.assets import (
    ANY_CODE,
    CRITICALITY,
    SOURCES,
    AssetConflict,
    AssetNotFound,
    asset_detail,
    bulk_update,
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
from api.platform.findings import service as finding_svc
from api.platform.findings.core import STATUSES, RoleRequired, TransitionError
from api.platform.findings.router import ChangeBody
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


def _check(value: str | None, allowed: tuple[str, ...]) -> None:
    if value is not None and value not in allowed:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"неизвестное значение фильтра «{value}»")


def _filters(
    q: str | None = None,
    source_has: str | None = None,
    source_missing: str | None = None,
    code: str | None = None,
    network_id: int | None = None,
    zone: str | None = None,
    port: int | None = Query(default=None, ge=1, le=65535),
    tag: str | None = None,
    criticality: str | None = None,
    disc_status: str | None = None,
    assignee: str | None = Query(default=None, max_length=255),
    overdue: bool | None = None,
) -> dict[str, Any]:
    """Фильтры списка — одни и те же у страницы списка и у выбора «всех по фильтру». `disc_status`
    (коды статусов через запятую или `all`), `assignee` (`me`, `none`, логин) и `overdue` — про
    расхождения: актив подходит, если у него есть расхождение под ними (и под `code`, если он задан)."""
    _check(source_has, SOURCES)
    _check(source_missing, SOURCES)
    _check(code, (*CODES, ANY_CODE))
    _check(criticality, (*CRITICALITY, "none"))
    if disc_status and disc_status != "all":
        for s in disc_status.split(","):
            _check(s, STATUSES)
    return {
        "q": q, "source_has": source_has, "source_missing": source_missing, "code": code, "network_id": network_id,
        "zone": zone, "port": port, "tag": tag, "criticality": criticality,
        "disc_status": disc_status or None, "assignee": assignee or None, "overdue": overdue,
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
