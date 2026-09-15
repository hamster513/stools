"""Домены и снапшоты: список, загрузка выгрузки, пересчёт, удаление, обзор."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.jobs import JobHandle
from api.modules.ad.core.checks import CHECK_BY_CODE, CHECKS
from api.modules.ad.core.export import ExportFormatError
from api.modules.ad.core.findings import SEVERITIES
from api.modules.ad.models import AdDomain, AdFinding, AdSnapshot
from api.modules.ad.services.jobs import active_job, run_job, start_job
from api.modules.ad.services.settings import load_config
from api.modules.ad.services.snapshots import (
    accepted_keys,
    compare,
    delete_snapshot,
    import_export,
    latest_snapshot,
    reanalyze,
    severity_counts,
)
from api.settings import Settings, get_settings

router = APIRouter(tags=["ad"])


class JobStarted(BaseModel):
    job_id: int


class DomainView(BaseModel):
    id: int
    sid: str
    dns_root: str
    netbios: str
    dn: str
    snapshots: int
    last_snapshot_id: int | None
    last_snapshot_at: dt.datetime | None


class SnapshotView(BaseModel):
    id: int
    domain_id: int
    collected_at: dt.datetime
    imported_at: dt.datetime
    source: str
    collector: str
    filename: str
    objects: int
    findings: int
    by_severity: dict[str, int]
    new: int | None
    fixed: int | None
    previous_id: int | None


def _snapshot_view(db: Session, s: AdSnapshot) -> SnapshotView:
    cmp_ = compare(db, s)
    counts = severity_counts(db, s.id)
    return SnapshotView(
        id=s.id,
        domain_id=s.domain_id,
        collected_at=s.collected_at,
        imported_at=s.imported_at,
        source=s.source,
        collector=s.collector,
        filename=s.filename,
        objects=s.objects,
        findings=s.findings,
        by_severity={sev: counts.get(sev, 0) for sev in SEVERITIES},
        new=cmp_.new if cmp_.previous_id else None,
        fixed=len(cmp_.fixed) if cmp_.previous_id else None,
        previous_id=cmp_.previous_id,
    )


@router.get("/domains", response_model=list[DomainView])
def list_domains(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[DomainView]:
    out = []
    for d in db.execute(select(AdDomain).order_by(AdDomain.dns_root, AdDomain.id)).scalars():
        count = int(db.execute(select(func.count()).select_from(AdSnapshot).where(AdSnapshot.domain_id == d.id)).scalar() or 0)
        last = latest_snapshot(db, d.id)
        out.append(
            DomainView(
                id=d.id, sid=d.sid, dns_root=d.dns_root, netbios=d.netbios, dn=d.dn, snapshots=count,
                last_snapshot_id=last.id if last else None, last_snapshot_at=last.collected_at if last else None,
            )
        )
    return out


@router.get("/domains/{domain_id}/overview")
def domain_overview(domain_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    domain = db.get(AdDomain, domain_id)
    if domain is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="домен не найден")
    snap = latest_snapshot(db, domain_id)
    if snap is None:
        return {"domain": {"id": domain.id, "dns_root": domain.dns_root, "netbios": domain.netbios}, "snapshot": None, "checks": []}
    cmp_ = compare(db, snap)
    accepted = accepted_keys(db, domain_id)
    rows = db.execute(select(AdFinding.check, AdFinding.severity, AdFinding.key).where(AdFinding.snapshot_id == snap.id)).all()
    per_check: dict[str, dict[str, Any]] = {
        c.code: {"code": c.code, "title": c.title, "description": c.description, "total": 0, "by_severity": dict.fromkeys(SEVERITIES, 0), "new": 0, "accepted": 0}
        for c in CHECKS
    }
    for check, severity, key in rows:
        entry = per_check.get(check)
        if entry is None:
            continue
        entry["total"] += 1
        entry["by_severity"][severity] = entry["by_severity"].get(severity, 0) + 1
        if key in cmp_.new_keys:
            entry["new"] += 1
        if key in accepted:
            entry["accepted"] += 1
    fixed_by_check: dict[str, int] = {}
    for f in cmp_.fixed:
        fixed_by_check[f.check] = fixed_by_check.get(f.check, 0) + 1
    for code, entry in per_check.items():
        entry["fixed"] = fixed_by_check.get(code, 0)
    counts = severity_counts(db, snap.id)
    return {
        "domain": {"id": domain.id, "dns_root": domain.dns_root, "netbios": domain.netbios, "dn": domain.dn, "sid": domain.sid},
        "snapshot": {
            "id": snap.id, "collected_at": snap.collected_at.isoformat(), "source": snap.source, "collector": snap.collector,
            "objects": snap.objects, "findings": snap.findings, "by_severity": {sev: counts.get(sev, 0) for sev in SEVERITIES},
        },
        "compared_to": {
            "previous_id": cmp_.previous_id,
            "collected_at": cmp_.previous_collected_at.isoformat() if cmp_.previous_collected_at else None,
            "new": cmp_.new, "fixed": len(cmp_.fixed),
        },
        "accepted_total": len(accepted & {key for _, _, key in rows}),
        "checks": list(per_check.values()),
    }


@router.get("/snapshots", response_model=list[SnapshotView])
def list_snapshots(domain_id: int | None = None, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[SnapshotView]:
    stmt = select(AdSnapshot).order_by(AdSnapshot.collected_at.desc(), AdSnapshot.id.desc())
    if domain_id is not None:
        stmt = stmt.where(AdSnapshot.domain_id == domain_id)
    return [_snapshot_view(db, s) for s in db.execute(stmt).scalars()]


@router.get("/snapshots/{snapshot_id}", response_model=SnapshotView)
def get_snapshot(snapshot_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> SnapshotView:
    s = db.get(AdSnapshot, snapshot_id)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    return _snapshot_view(db, s)


def _reject_if_running(db: Session) -> None:
    running = active_job(db, ["import_file", "collect", "reanalyze"])
    if running is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"идёт задача #{running.id} ({running.kind}), дождитесь её")


@router.post("/snapshots/file", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
async def upload_snapshot(
    background_tasks: BackgroundTasks,
    file: UploadFile,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: AppUser = Depends(get_current_user),
) -> JobStarted:
    _reject_if_running(db)
    data = await file.read()
    if not data:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="пустой файл")
    name = file.filename or "export.json"
    job_id = start_job(db, "import_file", user.login, message=name)
    upload = settings.data_dir / "ad" / f"upload-{job_id}.bin"
    upload.parent.mkdir(parents=True, exist_ok=True)
    upload.write_bytes(data)
    data_dir = settings.data_dir

    def work(session: Session, handle: JobHandle) -> None:
        try:
            raw = upload.read_bytes()
            try:
                snap = import_export(session, handle, raw, "file", name, load_config(session), data_dir)
            except ExportFormatError as exc:
                raise ValueError(str(exc)) from exc
            handle.stage("done", message=f"снапшот #{snap.id}: находок {snap.findings}")
        finally:
            upload.unlink(missing_ok=True)

    background_tasks.add_task(run_job, job_id, work)
    return JobStarted(job_id=job_id)


@router.post("/snapshots/{snapshot_id}/reanalyze", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
def reanalyze_snapshot(
    snapshot_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: AppUser = Depends(get_current_user),
) -> JobStarted:
    snap = db.get(AdSnapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    _reject_if_running(db)
    job_id = start_job(db, "reanalyze", user.login, message=f"снапшот #{snapshot_id}")
    data_dir = settings.data_dir

    def work(session: Session, handle: JobHandle) -> None:
        s = session.get(AdSnapshot, snapshot_id)
        if s is None:
            raise ValueError("снапшот удалён")
        reanalyze(session, handle, s, load_config(session), data_dir)

    background_tasks.add_task(run_job, job_id, work)
    return JobStarted(job_id=job_id)


@router.delete("/snapshots/{snapshot_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_snapshot(
    snapshot_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> None:
    snap = db.get(AdSnapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    delete_snapshot(db, snap, Path(settings.data_dir))


def check_titles() -> dict[str, str]:
    return {code: spec.title for code, spec in CHECK_BY_CODE.items()}


def stats_of(snapshot: AdSnapshot) -> dict[str, dict[str, int]]:
    try:
        return dict(json.loads(snapshot.stats_json or "{}"))
    except ValueError:
        return {}
