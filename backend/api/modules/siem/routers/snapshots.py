"""Загрузка и просмотр снапшотов."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser, Snapshot
from api.deps import get_current_user
from api.modules.siem.services.ingest import (
    UploadResult,
    process_upload,
    reparse,
    start_reparse,
    start_upload,
)
from api.modules.siem.services.summary import build_list_item, build_summary
from api.settings import Settings, get_settings

router = APIRouter(prefix="/snapshots", tags=["snapshots"])


@router.post("", response_model=UploadResult)
async def upload_snapshot(
    background_tasks: BackgroundTasks,
    file: UploadFile,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> UploadResult:
    data = await file.read()
    if not data:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="пустой файл")
    result = start_upload(db, settings, data, file.filename or "kb.zip")
    if not result.duplicate:
        background_tasks.add_task(process_upload, result.job_id, result.snapshot_id)
    return result


@router.post("/{snapshot_id}/reparse", status_code=status.HTTP_202_ACCEPTED)
def reparse_snapshot(
    snapshot_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, int]:
    """Разобрать архив заново тем разбором, что есть сейчас.

    После обновления сервиса разбор умеет больше, но старый снапшот об
    этом не знает: его кэш записан прежним кодом. Архив хранится целиком
    именно для этого.
    """
    snapshot = db.get(Snapshot, snapshot_id)
    if snapshot is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    if not Path(snapshot.archive_path).is_file():
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="архив снапшота недоступен — переразобрать нечего",
        )
    job_id = start_reparse(db, snapshot)
    background_tasks.add_task(reparse, job_id, snapshot_id)
    return {"job_id": job_id}


@router.get("")
def list_snapshots(
    db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)
) -> list[dict[str, Any]]:
    rows = db.query(Snapshot).order_by(Snapshot.id.desc()).all()
    return [build_list_item(s) for s in rows]


@router.get("/{snapshot_id}")
def get_snapshot(
    snapshot_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)
) -> dict[str, Any]:
    snapshot = db.get(Snapshot, snapshot_id)
    if snapshot is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    return build_summary(db, snapshot)
