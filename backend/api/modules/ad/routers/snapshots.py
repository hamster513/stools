"""Домены и снапшоты: список, загрузка выгрузки, пересчёт, удаление, обзор."""
from __future__ import annotations

import datetime as dt
import json
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import Row, func, select
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
from api.export_files import file_sha256
from api.jobs import JobCancelled, JobHandle
from api.modules.ad.core.account_groups import account_groups
from api.modules.ad.core.ca_data import load_ca_data_path, sniff_format
from api.modules.ad.core.checks import ANALYZER_VERSION, CHECK_BY_CODE, CHECKS
from api.modules.ad.core.checks.common import CATEGORIES
from api.modules.ad.core.export import ExportFormatError, ExportIndex, load_export_path
from api.modules.ad.core.findings import SEVERITIES
from api.modules.ad.core.gpo_rights import gpo_rights
from api.modules.ad.models import AdDomain, AdFinding, AdJob, AdSnapshot
from api.modules.ad.services.ca_data import store_ca_data
from api.modules.ad.services.dc_links import dc_links
from api.modules.ad.services.settings import load_config
from api.modules.ad.services.snapshots import (
    compare,
    delete_snapshot,
    domain_score,
    import_export,
    latest_snapshot,
    reanalyze,
    score_history,
    severity_counts,
    snapshot_path,
)
from api.modules.ad.services.summary_cells import CellNotFound, CellUnavailable, cell_info
from api.platform.findings import service as finding_svc
from api.settings import Settings, get_settings

router = APIRouter(tags=["ad"])
log = logging.getLogger("stools.ad")


class JobStarted(BaseModel):
    job_id: int


class DomainView(BaseModel):
    id: int
    sid: str
    dns_root: str
    netbios: str
    dn: str
    snapshots: int
    last_snapshot_id: int | None = None
    last_snapshot_at: dt.datetime | None = None


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
    new: int | None = None
    fixed: int | None = None
    previous_id: int | None = None


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
    found = db.execute(
        select(AdFinding.check, AdFinding.severity, AdFinding.key, AdFinding.allowlisted).where(AdFinding.snapshot_id == snap.id)
    ).all()
    rows = [(check, severity, key) for check, severity, key, _ in found]
    counts = severity_counts(db, snap.id)
    unchecked: dict[str, str] = json.loads(snap.unchecked_json or "{}")
    stale = snap.analyzer_version != ANALYZER_VERSION
    if stale:
        # Данные части проверок появились в новой версии: у старого снапшота такая проверка
        # пуста не потому, что чисто. Сохранённые причины точнее — их не заменяем.
        with_findings = {check for check, _, _ in rows}
        reason = f"снапшот посчитан прежней версией анализатора ({snap.analyzer_version or '—'}) — пересчитайте"
        for spec in CHECKS:
            if spec.code not in with_findings:
                unchecked.setdefault(spec.code, reason)
    return {
        "domain": {"id": domain.id, "dns_root": domain.dns_root, "netbios": domain.netbios, "dn": domain.dn, "sid": domain.sid},
        "snapshot": {
            "id": snap.id, "collected_at": snap.collected_at.isoformat(), "source": snap.source, "collector": snap.collector,
            "objects": snap.objects, "findings": snap.findings, "by_severity": {sev: counts.get(sev, 0) for sev in SEVERITIES},
            "analyzer_version": snap.analyzer_version, "stale_analysis": stale,
        },
        "compared_to": comparison_summary(cmp_),
        **findings_overview(db, "ad", domain_id, rows, CHECKS, SEVERITIES, cmp_, unchecked, CATEGORIES),
        "score": _live_score(db, domain_id, found),
        "score_history": score_history(db, domain_id),
    }


@router.get("/domains/{domain_id}/dc-links")
def domain_dc_links(domain_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[dict[str, Any]]:
    """Контроллеры сводки последнего снапшота со связками Assets, VM и KSC (спека §7)."""
    if db.get(AdDomain, domain_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="домен не найден")
    return dc_links(db, domain_id)


def _live_score(db: Session, domain_id: int, found: Sequence[Row[tuple[str, str, str, bool]]]) -> dict[str, Any]:
    """Живая оценка: находки вне allowlist в статусах, которые учитываются в подсчётах.
    Категории — в порядке CATEGORIES и с названием для заголовков групп."""
    states = finding_svc.state_map(db, "ad", domain_id)
    counted = finding_svc.counted_statuses(db)
    live = domain_score(
        (check, severity) for check, severity, key, allowlisted in found
        if not allowlisted and finding_svc.effective_status(states.get(key)) in counted
    )
    cats = live["categories"]
    live["categories"] = {code: {**cats[code], "title": title} for code, title in CATEGORIES.items() if code in cats}
    return live


@router.get("/snapshots", response_model=list[SnapshotView])
def list_snapshots(domain_id: int | None = None, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[SnapshotView]:
    stmt = select(AdSnapshot).order_by(AdSnapshot.collected_at.desc(), AdSnapshot.id.desc())
    if domain_id is not None:
        stmt = stmt.where(AdSnapshot.domain_id == domain_id)
    return [_snapshot_view(db, s) for s in db.execute(stmt).scalars()]


@router.get("/snapshots/{snapshot_id}", response_model=SnapshotView)
def get_snapshot(snapshot_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> SnapshotView:
    return _snapshot_view(db, snapshot_or_404(db, AdSnapshot, snapshot_id))


@router.get("/snapshots/{snapshot_id}/summary")
def get_summary(snapshot_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    snap = snapshot_or_404(db, AdSnapshot, snapshot_id)
    if not snap.summary_json:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="сводка не посчитана: пересчитайте снапшот")
    summary: dict[str, Any] = json.loads(snap.summary_json)
    return summary


def _export_index(data_dir: Path, snapshot_id: int) -> ExportIndex:
    try:
        return ExportIndex(load_export_path(snapshot_path(data_dir, snapshot_id)))
    except (OSError, ExportFormatError, ValueError) as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="файл выгрузки снапшота недоступен") from exc


@router.get("/snapshots/{snapshot_id}/account-groups/{sid}")
def get_account_groups(
    snapshot_id: int,
    sid: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Группы учётки по выгрузке снапшота: прямые, вложенные, первичная (контракт — docs/ad/api.md)."""
    snap = snapshot_or_404(db, AdSnapshot, snapshot_id)
    idx = _export_index(settings.data_dir, snap.id)
    found = account_groups(idx)
    groups = found.groups.get(sid)
    if groups is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="учётки с таким SID в снапшоте нет")
    return {"snapshot_id": snap.id, "collected_at": snap.collected_at, "sid": sid, "name": idx.principal_name(sid),
            "groups": groups, "notes": found.notes}


@router.get("/snapshots/{snapshot_id}/summary-cell")
def get_summary_cell(
    snapshot_id: int,
    cell: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Подпись и размеры ячейки сводки, без самих SID (контракт — docs/ad/api.md, «Ячейки сводки»)."""
    snap = snapshot_or_404(db, AdSnapshot, snapshot_id)
    try:
        info = cell_info(db, settings.data_dir, snap.id, cell)
    except CellNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except CellUnavailable as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return {"snapshot_id": info.snapshot_id, "collected_at": info.collected_at, "domain": info.domain,
            "cell": info.cell_id, "label": info.label, "users": len(info.users), "computers": len(info.computers),
            "summary_n": info.summary_n, "params_saved": info.params_saved}


@router.get("/snapshots/{snapshot_id}/gpo-rights")
def get_gpo_rights(
    snapshot_id: int,
    group_sid: str = "",
    local_group: str = "",
    host: str = "",
    hosts_limit: int = Query(1000, ge=0, le=10000),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Кто входит в какие локальные группы на каких компьютерах по GPO (контракт — docs/ad/api.md).
    Фильтры без учёта регистра; host — по полному списку хостов записи, до обрезки до hosts_limit."""
    snap = snapshot_or_404(db, AdSnapshot, snapshot_id)
    found = gpo_rights(_export_index(settings.data_dir, snap.id))
    sid_key, group_key, host_key = group_sid.lower(), local_group.lower(), host.lower()
    # Списки hosts и scope общие для записей одной GPO: запись собирается заново, hosts — срезом.
    rights = [
        {**r, "hosts": r["hosts"][:hosts_limit]}
        for r in found["rights"]
        if (not sid_key or r["group_sid"].lower() == sid_key)
        and (not group_key or r["local_group"].lower() == group_key)
        and (not host_key or any(h.lower() == host_key for h in r["hosts"]))
    ]
    return {"snapshot_id": snap.id, "collected_at": snap.collected_at, **found, "rights": rights}


@router.post("/snapshots/file", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
async def upload_snapshot(
    background_tasks: BackgroundTasks,
    file: UploadFile,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: AppUser = Depends(get_current_user),
) -> JobStarted:
    data = await read_upload(db, AdJob, file)
    data_dir = settings.data_dir
    login = user.login

    def load(session: Session, handle: JobHandle, upload: Path, name: str) -> str:
        # Любая версия stools-ad-ca/* — к разбору данных ЦС: он объяснит, что версия не та.
        if (sniff_format(upload) or "").startswith("stools-ad-ca/"):
            return _load_ca_data(session, handle, upload, name, login, data_dir)
        try:
            snap = import_export(session, handle, upload, "file", name, load_config(session), data_dir)
        except ExportFormatError as exc:
            raise ValueError(str(exc)) from exc
        return f"снапшот #{snap.id}: находок {snap.findings}"

    job_id = start_import(
        background_tasks, db, user, data, file.filename, upload_dir=settings.data_dir / "ad", job_model=AdJob, load=load,
    )
    return JobStarted(job_id=job_id)


def _load_ca_data(session: Session, handle: JobHandle, upload: Path, name: str, login: str, data_dir: Path) -> str:
    """Данные ЦС — не снапшот: сохраняются у домена, последний снапшот пересчитывается с ними.
    Ошибки формата и неизвестный домен — ValueError, задача падает с их текстом.
    Пересчёт не удался — данные уже сохранены, и текст ошибки говорит об этом."""
    handle.stage("parsing", message=name)
    ca = load_ca_data_path(upload)
    row = store_ca_data(session, ca, filename=name, sha256=file_sha256(upload), uploaded_by=login)
    session.commit()
    summary = f"данные ЦС: центров {len(ca.cas)}, контроллеров {len(ca.dcs)}"
    snap = latest_snapshot(session, row.domain_id)
    if snap is None:
        return f"{summary}; снапшотов домена пока нет"
    try:
        reanalyze(session, handle, snap, load_config(session), data_dir)
    except JobCancelled:
        raise
    except Exception as exc:
        # Свой текст — только у ошибок данных; у прочих в тексте бывают внутренности (пути, SQL).
        if isinstance(exc, (ValueError, FileNotFoundError)):
            cause = str(exc)
        else:
            log.exception("данные ЦС: пересчёт снапшота #%s не удался", snap.id)
            cause = exc.__class__.__name__
        raise ValueError(f"данные ЦС сохранены, но снапшот #{snap.id} не пересчитан: {cause}") from exc
    return f"{summary}; снапшот #{snap.id} пересчитан"


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
        background_tasks, db, user, snapshot_id, job_model=AdJob, snapshot_model=AdSnapshot,
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
    delete_snapshot(db, snapshot_or_404(db, AdSnapshot, snapshot_id), Path(settings.data_dir))


def check_titles() -> dict[str, str]:
    return {code: spec.title for code, spec in CHECK_BY_CODE.items()}


def stats_of(snapshot: AdSnapshot) -> dict[str, dict[str, int]]:
    try:
        return dict(json.loads(snapshot.stats_json or "{}"))
    except ValueError:
        return {}
