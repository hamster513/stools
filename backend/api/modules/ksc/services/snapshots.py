"""Снапшоты KSC: импорт выгрузки, анализ со сверкой AD, инвентарь хостов, сравнение, удаление.

Выгрузка хранится файлом `STOOLS_DATA_DIR/ksc/<id>.json.gz`: находки и
сверку можно пересчитать без повторного сбора.
"""
from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from api.jobs import JobHandle
from api.modules.ksc.core.checks import ANALYZER_VERSION, run_all
from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.export import ExportIndex, KscExport, load_export
from api.modules.ksc.core.findings import SEVERITY_RANK, Finding
from api.modules.ksc.models import KscFinding, KscHost, KscServer, KscSnapshot, KscVerdict
from api.modules.ksc.services.coverage import ad_computers_for

MAX_UPLOAD = 200 * 1024 * 1024


def snapshot_path(data_dir: Path, snapshot_id: int) -> Path:
    return data_dir / "ksc" / f"{snapshot_id}.json.gz"


def _server_for(db: Session, export: KscExport) -> KscServer:
    server = db.execute(select(KscServer).where(KscServer.name == export.server.name)).scalars().first()
    if server is None:
        server = KscServer(name=export.server.name)
        db.add(server)
    server.version = export.server.version or server.version
    db.flush()
    return server


def analyze(db: Session, export: KscExport, cfg: KscConfig, data_dir: Path) -> tuple[ExportIndex, list[Finding]]:
    idx = ExportIndex(export)
    idx.ad_computers = ad_computers_for(db, export, data_dir)
    findings = run_all(idx, cfg)
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.check, f.host.lower(), f.target.lower()))
    return idx, findings


def _coverage_stats(idx: ExportIndex, cfg: KscConfig) -> dict[str, Any]:
    cov = idx.coverage
    fresh = dt.timedelta(days=cfg.bases_old_days)
    return {
        "ad_total": cov.ad_total if cov else None,
        "ksc_total": len(idx.hosts),
        "both": len(cov.both) if cov else None,
        "ad_only": len(cov.ad_only) if cov else None,
        "ksc_only": len(cov.ksc_only) if cov else None,
        "with_agent": sum(1 for h in idx.hosts if h.agent_installed),
        "with_protection": sum(1 for h in idx.hosts if h.protection_installed),
        "protection_on": sum(1 for h in idx.hosts if h.protection == "on"),
        "bases_fresh": sum(1 for h in idx.hosts if h.bases_at and idx.now - h.bases_at <= fresh),
    }


def _store(db: Session, snapshot: KscSnapshot, idx: ExportIndex, findings: list[Finding], cfg: KscConfig) -> None:
    db.execute(delete(KscFinding).where(KscFinding.snapshot_id == snapshot.id))
    db.execute(delete(KscHost).where(KscHost.snapshot_id == snapshot.id))
    cov = idx.coverage
    host_rows = [
        {
            "snapshot_id": snapshot.id, "host_id": h.host_id[:64], "name": h.name[:255], "fqdn": h.fqdn[:255], "domain": h.domain[:255],
            "group_path": h.group_path[:1024], "os": h.os[:255], "ip": h.ip[:64], "agent_installed": h.agent_installed, "agent_alive": h.agent_alive,
            "last_seen_at": h.last_seen_at, "agent_version": h.agent_version[:64], "product": h.product[:255], "product_version": h.product_version[:64],
            "protection": h.protection, "rtp_state": h.rtp_state, "bases_at": h.bases_at, "last_fullscan_at": h.last_fullscan_at,
            "status": h.status, "threats": h.threats, "unassigned": h.unassigned,
            "in_ad": None if cov is None else ("both" if h.host_id in cov.both else "ksc_only"),
            "components_json": json.dumps(h.components, ensure_ascii=False),
        }
        for h in idx.hosts
    ]
    if host_rows:
        db.execute(KscHost.__table__.insert(), host_rows)  # type: ignore[attr-defined]
    rows = [
        {
            "snapshot_id": snapshot.id, "key": f.key, "check": f.check, "severity": f.severity, "severity_original": f.severity_original,
            "host": f.host[:255], "host_key": f.host_key[:255], "target": f.target[:1024], "allowlisted": f.allowlisted,
            "details_json": json.dumps(f.details, ensure_ascii=False, default=str),
        }
        for f in findings
    ]
    if rows:
        db.execute(KscFinding.__table__.insert(), rows)  # type: ignore[attr-defined]
    checks: dict[str, dict[str, int]] = {}
    for f in findings:
        checks.setdefault(f.check, {})
        checks[f.check][f.severity] = checks[f.check].get(f.severity, 0) + 1
    snapshot.hosts = len(idx.hosts)
    snapshot.findings = len(findings)
    snapshot.stats_json = json.dumps({"checks": checks, "coverage": _coverage_stats(idx, cfg)}, ensure_ascii=False)
    snapshot.analyzer_version = ANALYZER_VERSION


def import_export(db: Session, handle: JobHandle | None, data: bytes, source: str, filename: str, cfg: KscConfig, data_dir: Path) -> KscSnapshot:
    if handle:
        handle.stage("parsing", message=filename)
    export = load_export(data)
    if handle:
        handle.stage("analyzing", message=f"хостов {len(export.hosts)}")
    idx, findings = analyze(db, export, cfg, data_dir)
    if handle:
        handle.stage("persisting", message=f"находок {len(findings)}")
    server = _server_for(db, export)
    snapshot = KscSnapshot(
        server_id=server.id, collected_at=export.server.collected_at, source=source,
        collector=f"{export.server.collector} {export.server.collector_version}".strip(), filename=filename[:255],
        sha256=hashlib.sha256(data).hexdigest(),
    )
    db.add(snapshot)
    db.flush()
    _store(db, snapshot, idx, findings, cfg)
    path = snapshot_path(data_dir, snapshot.id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if data[:2] == b"\x1f\x8b" else gzip.compress(data))
    db.commit()
    return snapshot


def reanalyze(db: Session, handle: JobHandle | None, snapshot: KscSnapshot, cfg: KscConfig, data_dir: Path) -> KscSnapshot:
    path = snapshot_path(data_dir, snapshot.id)
    if not path.exists():
        raise FileNotFoundError(f"файл выгрузки снапшота #{snapshot.id} не найден — пересчитать нельзя")
    if handle:
        handle.stage("analyzing", message=f"снапшот #{snapshot.id}")
    export = load_export(path.read_bytes())
    idx, findings = analyze(db, export, cfg, data_dir)
    _store(db, snapshot, idx, findings, cfg)
    db.commit()
    return snapshot


def delete_snapshot(db: Session, snapshot: KscSnapshot, data_dir: Path) -> None:
    path = snapshot_path(data_dir, snapshot.id)
    db.delete(snapshot)
    db.commit()
    if path.exists():
        path.unlink()


def previous_snapshot(db: Session, snapshot: KscSnapshot) -> KscSnapshot | None:
    return db.execute(
        select(KscSnapshot).where(KscSnapshot.server_id == snapshot.server_id, KscSnapshot.collected_at < snapshot.collected_at)
        .order_by(KscSnapshot.collected_at.desc(), KscSnapshot.id.desc())
    ).scalars().first()


def latest_snapshot(db: Session, server_id: int) -> KscSnapshot | None:
    return db.execute(
        select(KscSnapshot).where(KscSnapshot.server_id == server_id).order_by(KscSnapshot.collected_at.desc(), KscSnapshot.id.desc())
    ).scalars().first()


def finding_keys(db: Session, snapshot_id: int) -> set[str]:
    return set(db.execute(select(KscFinding.key).where(KscFinding.snapshot_id == snapshot_id)).scalars())


@dataclass
class Comparison:
    previous_id: int | None
    previous_collected_at: dt.datetime | None
    new_keys: set[str]
    fixed: list[KscFinding]

    @property
    def new(self) -> int:
        return len(self.new_keys)


def compare(db: Session, snapshot: KscSnapshot) -> Comparison:
    prev = previous_snapshot(db, snapshot)
    current = finding_keys(db, snapshot.id)
    if prev is None:
        return Comparison(None, None, set(), [])
    before = finding_keys(db, prev.id)
    fixed_keys = before - current
    fixed = list(db.execute(select(KscFinding).where(KscFinding.snapshot_id == prev.id, KscFinding.key.in_(list(fixed_keys)))).scalars()) if fixed_keys else []
    return Comparison(prev.id, prev.collected_at, current - before, fixed)


def accepted_keys(db: Session, server_id: int) -> set[str]:
    return set(db.execute(select(KscVerdict.key).where(KscVerdict.server_id == server_id, KscVerdict.status == "accepted")).scalars())


def severity_counts(db: Session, snapshot_id: int) -> Counter[str]:
    rows = db.execute(select(KscFinding.severity, func.count()).where(KscFinding.snapshot_id == snapshot_id).group_by(KscFinding.severity)).all()
    return Counter({str(s): int(n) for s, n in rows})


def stats(snapshot: KscSnapshot) -> dict[str, Any]:
    try:
        return dict(json.loads(snapshot.stats_json or "{}"))
    except ValueError:
        return {}
