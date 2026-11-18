"""Список и отмена фоновых задач модуля VM."""
from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.jobs import cancel_job as _cancel_job
from api.modules.vm.models import VmJob
from api.modules.vm.services.jobs import IMPORT_KINDS, import_sql_name

router = APIRouter(prefix="/jobs", tags=["vm"])


SqlState = Literal["active", "lock", "io", "wait"]
_WAIT_STATES: dict[str | None, SqlState] = {None: "active", "Lock": "lock", "IO": "io"}


class SqlActivity(BaseModel):
    pid: int
    state: SqlState
    seconds: int


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
    sql_activity: SqlActivity | None = None


def job_views(db: Session, jobs: Sequence[VmJob]) -> list[JobView]:
    views = [JobView.model_validate(job) for job in jobs]
    imports = {import_sql_name(j.id): j for j in views if j.kind in IMPORT_KINDS and j.status == "running"}
    if not imports or db.get_bind().dialect.name != "postgresql":
        return views
    try:
        with db.begin_nested():
            rows = db.execute(text("""
                SELECT application_name, pid, wait_event_type,
                       GREATEST(0, floor(extract(epoch FROM clock_timestamp() - query_start))) AS seconds
                FROM pg_catalog.pg_stat_activity
                WHERE datname = current_database() AND usename = current_user
                  AND backend_type = 'client backend' AND state = 'active'
                  AND application_name = ANY(:names) AND pid <> pg_backend_pid()
                LIMIT :limit
            """), {"names": list(imports), "limit": len(imports)}).all()
    except SQLAlchemyError:
        # The job log is also available to installations with restricted statistics access.
        return views
    for name, pid, wait_type, seconds in rows:
        imports[name].sql_activity = SqlActivity(pid=pid, state=_WAIT_STATES.get(wait_type, "wait"), seconds=int(seconds))
    return views


@router.get("", response_model=list[JobView])
def list_jobs(
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> list[JobView]:
    # Идущие — сверху, дальше по свежести: экран задач открывают, чтобы
    # увидеть, что происходит сейчас, а не листать историю.
    running = db.execute(
        select(VmJob).where(VmJob.status == "running").order_by(VmJob.id.desc())
    ).scalars().all()
    finished = db.execute(
        select(VmJob).where(VmJob.status != "running").order_by(VmJob.id.desc()).limit(limit)
    ).scalars().all()
    return job_views(db, [*running, *finished])


@router.get("/{job_id}", response_model=JobView)
def get_job(job_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> JobView:
    job = db.get(VmJob, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="задача не найдена")
    return job_views(db, [job])[0]


@router.post("/{job_id}/cancel", status_code=status.HTTP_204_NO_CONTENT)
def cancel_job(job_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> None:
    _cancel_job(db, VmJob, job_id)
