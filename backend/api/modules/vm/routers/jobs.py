"""Список и отмена фоновых задач модуля VM."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.jobs import cancel_job as _cancel_job
from api.modules.vm.models import VmJob

router = APIRouter(prefix="/jobs", tags=["vm"])


class JobView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    kind: str
    stage: str
    status: str
    progress: int
    processed: int
    total: int | None = None
    message: str
    error: str | None = None
    cancel_requested: bool
    started_at: dt.datetime
    finished_at: dt.datetime | None = None
    started_by: str


@router.get("", response_model=list[JobView])
def list_jobs(
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> list[VmJob]:
    # Идущие — сверху, дальше по свежести: экран задач открывают, чтобы
    # увидеть, что происходит сейчас, а не листать историю.
    running = db.execute(
        select(VmJob).where(VmJob.status == "running").order_by(VmJob.id.desc())
    ).scalars().all()
    finished = db.execute(
        select(VmJob).where(VmJob.status != "running").order_by(VmJob.id.desc()).limit(limit)
    ).scalars().all()
    return list(running) + list(finished)


@router.get("/{job_id}", response_model=JobView)
def get_job(job_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> VmJob:
    job = db.get(VmJob, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="задача не найдена")
    return job


@router.post("/{job_id}/cancel", status_code=status.HTTP_204_NO_CONTENT)
def cancel_job(job_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> None:
    _cancel_job(db, VmJob, job_id)
