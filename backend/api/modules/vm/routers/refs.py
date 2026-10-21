"""Справочники: состояние, скачивание из сети, загрузка из файлов."""
from __future__ import annotations

import datetime as dt
import uuid
import zipfile
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.jobs import UPLOAD_INTERRUPTED
from api.limits import VM_UPLOAD, check_upload_size
from api.modules.vm.core.refs import REF_NAMES
from api.modules.vm.models import VmRefState
from api.modules.vm.routers.import_ import JobStarted
from api.modules.vm.services.bundle import classify, run_bundle
from api.modules.vm.services.jobs import (
    DATA_KINDS,
    JobHandle,
    active_job,
    fail_job,
    lock_job_start,
    run_job,
    start_job,
)
from api.modules.vm.services.refs import URLS, nvd_years_default, run_ref_download, run_ref_file
from api.modules.vm.services.settings import load_settings
from api.settings import Settings, get_settings

router = APIRouter(prefix="/refs", tags=["vm"])

TITLES = {
    "epss": "EPSS",
    "nvd": "NVD CVE",
    "exploitdb": "ExploitDB",
    "msf": "Metasploit",
    "attack": "CVE → ATT&CK (CTID)",
    "kev": "CISA KEV",
}


class RefView(BaseModel):
    name: str
    title: str
    url: str
    loaded_at: dt.datetime | None = None
    source: str | None = None
    records: int
    detail: str
    #: Старше 30 дней — справочник устарел, обзор это подсвечивает.
    stale: bool
    active_job_id: int | None = None


class DownloadRequest(BaseModel):
    years: list[int] | None = None


def _check_name(name: str) -> None:
    if name not in REF_NAMES:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="неизвестный справочник")


def _reject_if_running(db: Session, name: str) -> None:
    # Архив грузит те же таблицы: справочник в одиночку посреди него перемешал бы два набора.
    running = active_job(db, [f"ref_{name}", "ref_bundle"])
    if running is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"загрузка уже идёт (задача #{running.id})")


#: С архивом не идёт ни одна задача данных VM и ни одна загрузка справочника (спека §8):
#: пересборка витрины и пересчёт риска в конце архива задели бы их всех.
BUNDLE_CONFLICTS = (*DATA_KINDS, "bulk_status", *(f"ref_{n}" for n in REF_NAMES))
NO_KNOWN_REFS = "в архиве нет известных справочников"


def _reject_bundle_if_running(db: Session) -> None:
    running = active_job(db, BUNDLE_CONFLICTS)
    if running is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"идёт задача #{running.id}, загрузка архива после неё")


def _has_known_refs(path: Path) -> bool:
    if not zipfile.is_zipfile(path):
        return False
    try:
        with zipfile.ZipFile(path) as zf:
            return any(classify(info.filename) for info in zf.infolist() if not info.is_dir())
    except zipfile.BadZipFile:
        return False


@router.get("", response_model=list[RefView])
def list_refs(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[RefView]:
    states = {s.name: s for s in db.execute(select(VmRefState)).scalars()}
    now = dt.datetime.now(dt.UTC)
    out = []
    for name in REF_NAMES:
        s = states.get(name)
        # Архив грузит все справочники сразу: его задача видна на каждой карточке.
        running = active_job(db, [f"ref_{name}", "ref_bundle"])
        loaded = s.loaded_at if s else None
        if loaded is not None and loaded.tzinfo is None:
            loaded = loaded.replace(tzinfo=dt.UTC)
        out.append(
            RefView(
                name=name,
                title=TITLES[name],
                url=URLS[name].replace("{year}", "<год>"),
                loaded_at=loaded,
                source=s.source if s else None,
                records=s.records if s else 0,
                detail=s.detail if s else "",
                stale=loaded is None or (now - loaded) > dt.timedelta(days=30),
                active_job_id=running.id if running else None,
            )
        )
    return out


@router.post("/bundle/upload", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
async def upload_bundle(
    background_tasks: BackgroundTasks,
    file: UploadFile,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: AppUser = Depends(get_current_user),
) -> JobStarted:
    """Объявлен раньше `/{name}/…`: иначе `bundle` ушёл бы в шаблон и получил 404 справочника."""
    # Сначала без блокировки — чтобы не принимать полгигабайта ради отказа; под
    # блокировкой ещё раз ниже, перед заведением задачи.
    _reject_bundle_if_running(db)
    folder = settings.data_dir / "vm"
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / f"ref-bundle-{uuid.uuid4().hex}.zip"
    try:
        total = 0
        with target.open("wb") as out:
            while chunk := await file.read(1 << 20):
                out.write(chunk)
                total += len(chunk)
                check_upload_size(total, VM_UPLOAD)
        # Задача не заводится, если в архиве нечего грузить: ошибка видна сразу, а не в журнале задач.
        if not _has_known_refs(target):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=NO_KNOWN_REFS)
        lock_job_start(db)
        _reject_bundle_if_running(db)
        job_id = start_job(db, "ref_bundle", user.login, message=file.filename or "архив")
    except BaseException:
        target.unlink(missing_ok=True)
        raise

    def work(session: Session, handle: JobHandle) -> None:
        run_bundle(session, handle, target, load_settings(session).weights)

    def guarded() -> None:
        # Задачу могли снять до старта потока: `work` тогда не вызывается, а архив остаётся.
        try:
            run_job(job_id, work)
        finally:
            target.unlink(missing_ok=True)

    background_tasks.add_task(guarded)
    return JobStarted(job_id=job_id)


@router.post("/{name}/download", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
def download_ref(
    name: str,
    payload: DownloadRequest | None = None,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> JobStarted:
    _check_name(name)
    _reject_if_running(db, name)
    years = (payload.years if payload else None) or (nvd_years_default() if name == "nvd" else None)
    if name == "nvd" and years and any(y < 1999 or y > dt.datetime.now(dt.UTC).year for y in years):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="год вне диапазона фидов NVD")
    job_id = start_job(db, f"ref_{name}", user.login, message="из сети")

    def work(session: Session, handle: JobHandle) -> None:
        run_ref_download(session, handle, name, load_settings(session).weights, years)

    background_tasks.add_task(run_job, job_id, work)
    return JobStarted(job_id=job_id)


@router.post("/{name}/upload", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
async def upload_ref(
    name: str,
    background_tasks: BackgroundTasks,
    files: list[UploadFile],
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: AppUser = Depends(get_current_user),
) -> JobStarted:
    _check_name(name)
    _reject_if_running(db, name)
    if not files:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="файлы не переданы")
    job_id = start_job(db, f"ref_{name}", user.login, message=", ".join(f.filename or "?" for f in files))
    folder = settings.data_dir / "vm"
    folder.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    written: list[Path] = []
    total = 0
    try:
        for i, f in enumerate(files):
            suffix = Path(f.filename or "").suffix or ".dat"
            target = folder / f"ref-{job_id}-{i}{suffix}"
            written.append(target)
            size = 0
            with target.open("wb") as out:
                while chunk := await f.read(1 << 20):
                    out.write(chunk)
                    size += len(chunk)
                    total += len(chunk)
                    check_upload_size(total, VM_UPLOAD)
            if size == 0:
                target.unlink(missing_ok=True)
                continue
            paths.append(target)
    # Отказ по размеру, обрыв клиента, ошибка диска: задача не остаётся «в работе», файлы не лежат.
    except Exception as exc:
        for path in written:
            path.unlink(missing_ok=True)
        fail_job(db, job_id, str(exc.detail) if isinstance(exc, HTTPException) else UPLOAD_INTERRUPTED)
        raise
    if not paths:
        fail_job(db, job_id, "пустой файл")
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="пустые файлы")

    def work(session: Session, handle: JobHandle) -> None:
        run_ref_file(session, handle, name, paths, load_settings(session).weights)

    def guarded() -> None:
        # Задачу могли снять до старта потока: `work` тогда не вызывается, а файлы остаются.
        try:
            run_job(job_id, work)
        finally:
            for path in paths:
                path.unlink(missing_ok=True)

    background_tasks.add_task(guarded)
    return JobStarted(job_id=job_id)
