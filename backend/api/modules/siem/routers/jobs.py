"""Опрос состояния фонового задания."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser, Job
from api.deps import get_current_user

router = APIRouter(prefix="/jobs", tags=["jobs"])


class JobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    stage: str
    status: str
    progress: int
    error: str | None = None
    snapshot_id: int | None = None


@router.get("/{job_id}", response_model=JobResponse)
def get_job(
    job_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)
) -> Job:
    job = db.get(Job, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="задание не найдено")
    return job
