"""Запуск импорта из MaxPatrol VM или из файла."""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.vm.models import VmImport
from api.modules.vm.routers.jobs import JobView
from api.modules.vm.services.importer import run_import
from api.modules.vm.services.jobs import JobHandle, active_job, run_job, start_job
from api.modules.vm.services.settings import load_settings
from api.settings import Settings, get_settings

router = APIRouter(prefix="/import", tags=["vm"])

IMPORT_KINDS = ("import_vm", "import_file")


class JobStarted(BaseModel):
    job_id: int


class ImportView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finished_at: dt.datetime
    source: str
    filename: str
    hosts: int
    pairs: int
    cves: int
    new_zones: int


class ImportState(BaseModel):
    last: ImportView | None
    active: JobView | None


def _reject_if_running(db: Session) -> None:
    running = active_job(db, IMPORT_KINDS)
    if running is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"импорт уже идёт (задача #{running.id}, стадия {running.stage})",
        )


@router.post("/vm", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
def import_from_vm(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: AppUser = Depends(get_current_user),
) -> JobStarted:
    vm = load_settings(db)
    if not vm.connection.configured:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="подключение к MaxPatrol VM не настроено")
    _reject_if_running(db)
    job_id = start_job(db, "import_vm", user.login, message=vm.connection.host)
    data_dir = settings.data_dir

    def work(session: Session, handle: JobHandle) -> None:
        run_import(session, handle, "vm", None, load_settings(session), data_dir)

    background_tasks.add_task(run_job, job_id, work)
    return JobStarted(job_id=job_id)


@router.post("/file", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
async def import_from_file(
    background_tasks: BackgroundTasks,
    file: UploadFile,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: AppUser = Depends(get_current_user),
) -> JobStarted:
    _reject_if_running(db)
    name = file.filename or "export.csv"
    suffix = ".json" if name.lower().endswith(".json") else ".csv"
    job_id = start_job(db, "import_file", user.login, message=name)
    target = settings.data_dir / "vm" / f"upload-{job_id}{suffix}"
    target.parent.mkdir(parents=True, exist_ok=True)
    # Файл на гигабайт в память не читается: пишем кусками на диск.
    size = 0
    with target.open("wb") as out:
        while chunk := await file.read(1 << 20):
            out.write(chunk)
            size += len(chunk)
    if size == 0:
        target.unlink(missing_ok=True)
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="пустой файл")
    data_dir = settings.data_dir

    def work(session: Session, handle: JobHandle) -> None:
        run_import(session, handle, "file", Path(target), load_settings(session), data_dir, filename=name)

    background_tasks.add_task(run_job, job_id, work)
    return JobStarted(job_id=job_id)


@router.get("", response_model=ImportState)
def import_state(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ImportState:
    last = db.execute(select(VmImport).order_by(VmImport.id.desc())).scalars().first()
    running = active_job(db, IMPORT_KINDS)
    return ImportState(
        last=ImportView.model_validate(last) if last else None,
        active=JobView.model_validate(running) if running else None,
    )
