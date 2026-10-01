"""Реестр активов: список с фасетами, карточка, ручные поля, объединение, отвязка,
закрепление полей, синхронизация с модулями."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.jobs import active_job, run_job, start_job
from api.modules.assets.core.discrepancies import CODES
from api.modules.assets.models import AssetJob
from api.modules.assets.services.assets import (
    CRITICALITY,
    SOURCES,
    AssetConflict,
    AssetNotFound,
    asset_detail,
    detach_observation,
    list_assets,
    merge_assets,
    pin_field,
    update_manual,
)
from api.modules.assets.services.sync import sync_job, sync_status

router = APIRouter(tags=["assets"])

MAX_LIMIT = 500


class JobStarted(BaseModel):
    job_id: int


class AssetPatch(BaseModel):
    """Только ручные поля; не переданное поле не меняется."""

    criticality: Literal["Critical", "High", "Medium", "Low", ""] | None = None
    tags: list[str] | None = Field(default=None, max_length=50)
    note: str | None = Field(default=None, max_length=4000)
    network_id: int | None = None
    network_manual: bool | None = None


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


@router.get("/assets")
def get_assets(
    q: str | None = None,
    source_has: str | None = None,
    source_missing: str | None = None,
    code: str | None = None,
    network_id: int | None = None,
    zone: str | None = None,
    port: int | None = Query(default=None, ge=1, le=65535),
    tag: str | None = None,
    criticality: str | None = None,
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    _check(source_has, SOURCES)
    _check(source_missing, SOURCES)
    _check(code, CODES)
    _check(criticality, (*CRITICALITY, "none"))
    items, total, facets = list_assets(
        db, q=q, source_has=source_has, source_missing=source_missing, code=code, network_id=network_id, zone=zone,
        port=port, tag=tag, criticality=criticality, limit=limit, offset=offset,
    )
    return {"total": total, "items": items, "facets": facets if offset == 0 else None}


@router.get("/assets/{asset_id}")
def get_asset(asset_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    return dict(_errors(asset_detail, db, asset_id))


@router.patch("/assets/{asset_id}")
def patch_asset(asset_id: int, payload: AssetPatch, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    _errors(update_manual, db, asset_id, payload.model_dump(include=payload.model_fields_set))
    db.commit()
    return dict(asset_detail(db, asset_id))


@router.post("/assets/{asset_id}/pin")
def pin(asset_id: int, payload: PinIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    _errors(pin_field, db, asset_id, payload.field, payload.pinned)
    db.commit()
    return dict(asset_detail(db, asset_id))


def _no_running_sync(db: Session) -> None:
    """Синхронизация держит индекс активов в памяти и вернула бы наблюдения туда, где их видела."""
    running = active_job(db, AssetJob, ("sync",))
    if running is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"идёт синхронизация #{running.id}, дождитесь её")


@router.post("/assets/{asset_id}/merge")
def merge(asset_id: int, payload: MergeIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    _no_running_sync(db)
    _errors(merge_assets, db, asset_id, payload.other_id)
    db.commit()
    return dict(asset_detail(db, asset_id))


@router.post("/observations/{observation_id}/detach")
def detach(observation_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    _no_running_sync(db)
    fresh = _errors(detach_observation, db, observation_id)
    db.commit()
    return dict(asset_detail(db, fresh.id))


@router.post("/sync", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
def start_sync(background_tasks: BackgroundTasks, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> JobStarted:
    running = active_job(db, AssetJob, ("sync",))
    if running is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"идёт синхронизация #{running.id}, дождитесь её")
    job_id = start_job(db, AssetJob, "sync", user.login, message="вручную")
    background_tasks.add_task(run_job, AssetJob, job_id, lambda s, h: sync_job(s, h, "вручную"))
    return JobStarted(job_id=job_id)


@router.get("/sync/status")
def get_sync_status(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    return sync_status(db)
