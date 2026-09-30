"""Справочники: состояние, скачивание из сети, загрузка из файлов."""
from __future__ import annotations

import datetime as dt
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
from api.modules.vm.services.jobs import JobHandle, active_job, fail_job, run_job, start_job
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
    running = active_job(db, [f"ref_{name}"])
    if running is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"загрузка уже идёт (задача #{running.id})")


@router.get("", response_model=list[RefView])
def list_refs(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[RefView]:
    states = {s.name: s for s in db.execute(select(VmRefState)).scalars()}
    now = dt.datetime.now(dt.UTC)
    out = []
    for name in REF_NAMES:
        s = states.get(name)
        running = active_job(db, [f"ref_{name}"])
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
