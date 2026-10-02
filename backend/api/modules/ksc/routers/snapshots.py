"""Серверы и снапшоты: список, загрузка выгрузки, пересчёт, удаление, обзор."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.collector_routes import (
    comparison_summary,
    findings_overview,
    read_upload,
    snapshot_or_404,
    start_import,
    start_reanalyze,
)
from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.jobs import JobHandle
from api.modules.ksc.core.checks import CHECKS
from api.modules.ksc.core.export import ExportFormatError
from api.modules.ksc.core.findings import SEVERITIES
from api.modules.ksc.models import KscFinding, KscJob, KscServer, KscSnapshot
from api.modules.ksc.services.settings import load_config
from api.modules.ksc.services.snapshots import (
    MAX_UPLOAD,
    compare,
    delete_snapshot,
    import_export,
    latest_snapshot,
    reanalyze,
    severity_counts,
    stats,
)
from api.settings import Settings, get_settings

router = APIRouter(tags=["ksc"])


class JobStarted(BaseModel):
    job_id: int


class ServerView(BaseModel):
    id: int
    name: str
    version: str
    snapshots: int
    last_snapshot_id: int | None = None
    last_snapshot_at: dt.datetime | None = None


class SnapshotView(BaseModel):
    id: int
    server_id: int
    collected_at: dt.datetime
    imported_at: dt.datetime
    source: str
    collector: str
    filename: str
    hosts: int
    findings: int
    by_severity: dict[str, int]
    new: int | None = None
    fixed: int | None = None
    previous_id: int | None = None


def _snapshot_view(db: Session, s: KscSnapshot) -> SnapshotView:
    cmp_ = compare(db, s)
    counts = severity_counts(db, s.id)
    return SnapshotView(
        id=s.id,
        server_id=s.server_id,
        collected_at=s.collected_at,
        imported_at=s.imported_at,
        source=s.source,
        collector=s.collector,
        filename=s.filename,
        hosts=s.hosts,
        findings=s.findings,
        by_severity={sev: counts.get(sev, 0) for sev in SEVERITIES},
        new=cmp_.new if cmp_.previous_id else None,
        fixed=len(cmp_.fixed) if cmp_.previous_id else None,
        previous_id=cmp_.previous_id,
    )


@router.get("/servers", response_model=list[ServerView])
def list_servers(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[ServerView]:
    out = []
    for s in db.execute(select(KscServer).order_by(KscServer.name, KscServer.id)).scalars():
        count = int(db.execute(select(func.count()).select_from(KscSnapshot).where(KscSnapshot.server_id == s.id)).scalar() or 0)
        last = latest_snapshot(db, s.id)
        out.append(
            ServerView(
                id=s.id, name=s.name, version=s.version, snapshots=count,
                last_snapshot_id=last.id if last else None, last_snapshot_at=last.collected_at if last else None,
            )
        )
    return out


@router.get("/servers/{server_id}/overview")
def server_overview(server_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    server = db.get(KscServer, server_id)
    if server is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="сервер не найден")
    snap = latest_snapshot(db, server_id)
    if snap is None:
        return {"server": {"id": server.id, "name": server.name, "version": server.version}, "snapshot": None, "coverage": None, "checks": []}
    cmp_ = compare(db, snap)
    rows = db.execute(select(KscFinding.check, KscFinding.severity, KscFinding.key).where(KscFinding.snapshot_id == snap.id)).all()
    counts = severity_counts(db, snap.id)
    return {
        "server": {"id": server.id, "name": server.name, "version": server.version},
        "snapshot": {
            "id": snap.id, "collected_at": snap.collected_at.isoformat(), "source": snap.source, "collector": snap.collector,
            "hosts": snap.hosts, "findings": snap.findings, "by_severity": {sev: counts.get(sev, 0) for sev in SEVERITIES},
        },
        "compared_to": comparison_summary(cmp_),
        "coverage": stats(snap).get("coverage"),
        **findings_overview(db, "ksc", server_id, rows, CHECKS, SEVERITIES, cmp_),
    }


@router.get("/snapshots", response_model=list[SnapshotView])
def list_snapshots(server_id: int | None = None, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[SnapshotView]:
    stmt = select(KscSnapshot).order_by(KscSnapshot.collected_at.desc(), KscSnapshot.id.desc())
    if server_id is not None:
        stmt = stmt.where(KscSnapshot.server_id == server_id)
    return [_snapshot_view(db, s) for s in db.execute(stmt).scalars()]


@router.get("/snapshots/{snapshot_id}", response_model=SnapshotView)
def get_snapshot(snapshot_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> SnapshotView:
    return _snapshot_view(db, snapshot_or_404(db, KscSnapshot, snapshot_id))


@router.post("/snapshots/file", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
async def upload_snapshot(
    background_tasks: BackgroundTasks,
    file: UploadFile,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: AppUser = Depends(get_current_user),
) -> JobStarted:
    data = await read_upload(db, KscJob, file)
    if len(data) > MAX_UPLOAD:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="файл больше 200 МБ")
    data_dir = settings.data_dir

    def load(session: Session, handle: JobHandle, upload: Path, name: str) -> str:
        try:
            snap = import_export(session, handle, upload, "file", name, load_config(session), data_dir)
        except ExportFormatError as exc:
            raise ValueError(str(exc)) from exc
        return f"снапшот #{snap.id}: хостов {snap.hosts}, находок {snap.findings}"

    job_id = start_import(
        background_tasks, db, user, data, file.filename, upload_dir=settings.data_dir / "ksc", job_model=KscJob, load=load,
    )
    return JobStarted(job_id=job_id)


@router.post("/snapshots/{snapshot_id}/reanalyze", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
def reanalyze_snapshot(
    snapshot_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: AppUser = Depends(get_current_user),
) -> JobStarted:
    data_dir = settings.data_dir
    job_id = start_reanalyze(
        background_tasks, db, user, snapshot_id, job_model=KscJob, snapshot_model=KscSnapshot,
        reanalyze=lambda session, handle, s: reanalyze(session, handle, s, load_config(session), data_dir),
    )
    return JobStarted(job_id=job_id)


@router.delete("/snapshots/{snapshot_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_snapshot(
    snapshot_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> None:
    delete_snapshot(db, snapshot_or_404(db, KscSnapshot, snapshot_id), Path(settings.data_dir))
