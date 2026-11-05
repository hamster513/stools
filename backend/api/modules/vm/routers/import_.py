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
from api.jobs import UPLOAD_INTERRUPTED
from api.limits import VM_UPLOAD, check_upload_size
from api.modules.vm.models import VmImport
from api.modules.vm.routers.jobs import JobView
from api.modules.vm.services.harbor_sync import SYNC_KIND
from api.modules.vm.services.importer import run_import
from api.modules.vm.services.jobs import (
    REF_KINDS,
    JobHandle,
    active_job,
    fail_job,
    lock_job_start,
    run_job,
    start_job,
)
from api.modules.vm.services.settings import load_settings
from api.platform.sync_jobs import Submit
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
    last: ImportView | None = None
    active: JobView | None = None


def _reject_if_running(db: Session) -> None:
    """Под блокировкой запуска задач VM (её отпустит commit `start_job`): массовая смена
    статусов выбирает пары кусками, и замена пар посреди неё смешала бы два импорта."""
    lock_job_start(db)
    running = active_job(db, IMPORT_KINDS)
    if running is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"импорт уже идёт (задача #{running.id}, стадия {running.stage})",
        )
    if active_job(db, ["bulk_status"]) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="идёт массовая смена статусов")
    # Архив справочников в конце пересчитывает риск всех пар — замена пар посреди него смешала бы данные.
    bundle = active_job(db, ["ref_bundle", *REF_KINDS])
    if bundle is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"идёт загрузка справочников (задача #{bundle.id})")
    # Синхронизация образов пополняет ту же витрину CVE, которую импорт чистит от сирот.
    harbor = active_job(db, [SYNC_KIND])
    if harbor is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"идёт синхронизация образов из Harbor (задача #{harbor.id})")


@router.post("/vm", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
def import_from_vm(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: AppUser = Depends(get_current_user),
) -> JobStarted:
    return JobStarted(job_id=start_vm_import(db, user.login, background_tasks.add_task, settings))


def start_vm_import(db: Session, login: str, submit: Submit, settings: Settings | None = None) -> int:
    vm = load_settings(db)
    if not vm.connection.configured:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="подключение к MaxPatrol VM не настроено")
    _reject_if_running(db)
    job_id = start_job(db, "import_vm", login, message=vm.connection.host)
    data_dir = (settings or get_settings()).data_dir

    def work(session: Session, handle: JobHandle) -> None:
        run_import(session, handle, "vm", None, load_settings(session), data_dir)

    submit(lambda: run_job(job_id, work))
    return job_id


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
    try:
        with target.open("wb") as out:
            while chunk := await file.read(1 << 20):
                out.write(chunk)
                size += len(chunk)
                check_upload_size(size, VM_UPLOAD)
    # Отказ по размеру, обрыв клиента, ошибка диска: задача не остаётся «в работе», файл не лежит.
    except Exception as exc:
        target.unlink(missing_ok=True)
        fail_job(db, job_id, str(exc.detail) if isinstance(exc, HTTPException) else UPLOAD_INTERRUPTED)
        raise
    if size == 0:
        target.unlink(missing_ok=True)
        fail_job(db, job_id, "пустой файл")
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="пустой файл")
    data_dir = settings.data_dir

    def work(session: Session, handle: JobHandle) -> None:
        run_import(session, handle, "file", Path(target), load_settings(session), data_dir, filename=name)

    def guarded() -> None:
        # Задачу могли снять до старта потока: `work` тогда не вызывается, а файл остаётся.
        try:
            run_job(job_id, work)
        finally:
            target.unlink(missing_ok=True)

    background_tasks.add_task(guarded)
    return JobStarted(job_id=job_id)


@router.get("", response_model=ImportState)
def import_state(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ImportState:
    last = db.execute(select(VmImport).order_by(VmImport.id.desc())).scalars().first()
    running = active_job(db, IMPORT_KINDS)
    return ImportState(
        last=ImportView.model_validate(last) if last else None,
        active=JobView.model_validate(running) if running else None,
    )
