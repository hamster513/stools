"""Снапшоты: импорт выгрузки, анализ, сравнение с предыдущим, удаление.

Выгрузка хранится файлом рядом с данными (`STOOLS_DATA_DIR/ad/<id>.json.gz`):
находки можно пересчитать новыми правилами без повторного сбора.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from api.export_files import file_sha256, store_gz
from api.jobs import JobHandle, insert_chunked
from api.modules.ad.core.ca_data import CaData
from api.modules.ad.core.checks import ANALYZER_VERSION, run_all
from api.modules.ad.core.checks.coverage import coverage_gaps
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import AdExport, ExportIndex, load_export_path
from api.modules.ad.core.findings import SEVERITY_RANK, Finding
from api.modules.ad.models import AdDomain, AdFinding, AdSnapshot, AdVerdict
from api.modules.ad.services.ca_data import effective_ca_data

log = logging.getLogger(__name__)


def snapshot_path(data_dir: Path, snapshot_id: int) -> Path:
    return data_dir / "ad" / f"{snapshot_id}.json.gz"


def _domain_for(db: Session, export: AdExport) -> AdDomain:
    domain = db.execute(select(AdDomain).where(AdDomain.sid == export.domain.sid)).scalars().first()
    if domain is None:
        domain = AdDomain(sid=export.domain.sid)
        db.add(domain)
    # Имена обновляются каждым снапшотом: домен могли переименовать.
    domain.dns_root = export.domain.dns_root or domain.dns_root
    domain.dn = export.domain.dn or domain.dn
    domain.netbios = export.domain.netbios or domain.netbios
    db.flush()
    return domain


def _store_findings(db: Session, snapshot: AdSnapshot, findings: list[Finding], gaps: dict[str, str], handle: JobHandle | None = None) -> None:
    db.execute(delete(AdFinding).where(AdFinding.snapshot_id == snapshot.id))
    rows = (
        {
            "snapshot_id": snapshot.id,
            "key": f.key,
            "check": f.check,
            "severity": f.severity,
            "severity_original": f.severity_original,
            "identity": f.identity[:512],
            "identity_sid": f.identity_sid[:64],
            "target": f.target[:1024],
            "right": f.right[:255],
            "allowlisted": f.allowlisted,
            "details_json": json.dumps(f.details, ensure_ascii=False, default=str),
        }
        for f in findings
    )
    insert_chunked(db, AdFinding, rows, len(findings), handle, "находок")
    stats: dict[str, dict[str, int]] = {}
    for f in findings:
        stats.setdefault(f.check, {})
        stats[f.check][f.severity] = stats[f.check].get(f.severity, 0) + 1
    snapshot.findings = len(findings)
    snapshot.stats_json = json.dumps(stats, ensure_ascii=False)
    snapshot.analyzer_version = ANALYZER_VERSION
    snapshot.unchecked_json = json.dumps(gaps, ensure_ascii=False)


def analyze(export: AdExport, cfg: AdConfig, ca: CaData | None = None) -> list[Finding]:
    findings = run_all(ExportIndex(export, ca), cfg)
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.check, f.identity, f.target))
    return findings


def import_export(
    db: Session,
    handle: JobHandle | None,
    path: Path,
    source: str,
    filename: str,
    cfg: AdConfig,
    data_dir: Path,
    sha256: str | None = None,
) -> AdSnapshot:
    """`path` — файл выгрузки (JSON или gzip) в каталоге данных: разбирается с диска
    и становится файлом снапшота (gzip — переносом, JSON — сжатием потоком).
    `sha256` — отпечаток исходного текста; не задан — по байтам файла, как у загрузки."""
    if handle:
        handle.stage("parsing", message=filename)
    export = load_export_path(path)
    if handle:
        handle.stage("analyzing", message=f"объектов {len(export.objects)}")
    # Домен здесь только читается: `stage` фиксирует транзакцию, и созданный до
    # неё домен пережил бы отказ задачи.
    known = db.execute(select(AdDomain.id).where(AdDomain.sid == export.domain.sid)).scalar()
    ca, ca_data_id = effective_ca_data(db, known) if known is not None else (None, None)
    findings = analyze(export, cfg, ca)
    gaps = coverage_gaps(export, ca)
    if handle:
        handle.stage("persisting", total=len(findings), message=f"находок {len(findings)}")
    domain = _domain_for(db, export)
    snapshot = AdSnapshot(
        domain_id=domain.id,
        collected_at=export.collected_at,
        source=source,
        collector=f"{export.collector.kind} {export.collector.version}".strip(),
        filename=filename,
        sha256=sha256 or file_sha256(path),
        objects=len(export.objects),
        ca_data_id=ca_data_id,
    )
    db.add(snapshot)
    db.flush()
    # Разобранная выгрузка больше не нужна: находки пишутся без неё рядом.
    del export
    _store_findings(db, snapshot, findings, gaps, handle)
    store_gz(path, snapshot_path(data_dir, snapshot.id))
    db.commit()
    _notify_assets(db)
    return snapshot


def _notify_assets(db: Session) -> None:
    """Assets пересоберёт реестр хостов из записанного импорта. Его сбой не должен ронять импорт:
    данные модуля уже зафиксированы. Импорт внутри функции — Assets сам читает таблицы модуля."""
    try:
        from api.modules.assets.services.sync import request_sync

        request_sync(db, "ad")
    except Exception:
        db.rollback()
        log.exception("синхронизация Assets после импорта AD не запущена")


def reanalyze(db: Session, handle: JobHandle | None, snapshot: AdSnapshot, cfg: AdConfig, data_dir: Path) -> AdSnapshot:
    path = snapshot_path(data_dir, snapshot.id)
    if not path.exists():
        raise FileNotFoundError(f"файл выгрузки снапшота #{snapshot.id} не найден — пересчитать нельзя")
    if handle:
        handle.stage("analyzing", message=f"снапшот #{snapshot.id}")
    export = load_export_path(path)
    ca, ca_data_id = effective_ca_data(db, snapshot.domain_id)
    findings = analyze(export, cfg, ca)
    gaps = coverage_gaps(export, ca)
    del export
    if handle:
        handle.stage("persisting", total=len(findings), message=f"находок {len(findings)}")
    snapshot.ca_data_id = ca_data_id
    _store_findings(db, snapshot, findings, gaps, handle)
    db.commit()
    return snapshot


def delete_snapshot(db: Session, snapshot: AdSnapshot, data_dir: Path) -> None:
    path = snapshot_path(data_dir, snapshot.id)
    db.delete(snapshot)
    db.commit()
    if path.exists():
        path.unlink()


def previous_snapshot(db: Session, snapshot: AdSnapshot) -> AdSnapshot | None:
    return db.execute(
        select(AdSnapshot)
        .where(AdSnapshot.domain_id == snapshot.domain_id, AdSnapshot.collected_at < snapshot.collected_at)
        .order_by(AdSnapshot.collected_at.desc(), AdSnapshot.id.desc())
    ).scalars().first()


def latest_snapshot(db: Session, domain_id: int) -> AdSnapshot | None:
    return db.execute(
        select(AdSnapshot).where(AdSnapshot.domain_id == domain_id).order_by(AdSnapshot.collected_at.desc(), AdSnapshot.id.desc())
    ).scalars().first()


def finding_keys(db: Session, snapshot_id: int) -> set[str]:
    return set(db.execute(select(AdFinding.key).where(AdFinding.snapshot_id == snapshot_id)).scalars())


@dataclass
class Comparison:
    previous_id: int | None
    previous_collected_at: dt.datetime | None
    new_keys: set[str]
    fixed: list[AdFinding]

    @property
    def new(self) -> int:
        return len(self.new_keys)


def compare(db: Session, snapshot: AdSnapshot) -> Comparison:
    prev = previous_snapshot(db, snapshot)
    current = finding_keys(db, snapshot.id)
    if prev is None:
        return Comparison(None, None, set(), [])
    before = finding_keys(db, prev.id)
    fixed_keys = before - current
    fixed = (
        list(db.execute(select(AdFinding).where(AdFinding.snapshot_id == prev.id, AdFinding.key.in_(list(fixed_keys)))).scalars())
        if fixed_keys
        else []
    )
    return Comparison(prev.id, prev.collected_at, current - before, fixed)


def accepted_keys(db: Session, domain_id: int) -> set[str]:
    return set(db.execute(select(AdVerdict.key).where(AdVerdict.domain_id == domain_id, AdVerdict.status == "accepted")).scalars())


def severity_counts(db: Session, snapshot_id: int) -> Counter[str]:
    rows = db.execute(
        select(AdFinding.severity, func.count()).where(AdFinding.snapshot_id == snapshot_id).group_by(AdFinding.severity)
    ).all()
    return Counter({str(s): int(n) for s, n in rows})
