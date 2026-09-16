"""Поиск снапшота AD для сверки: по DNS-корню или NetBIOS доменов из выгрузки KSC."""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.ad.core.export import ExportFormatError, load_export_path
from api.modules.ad.models import AdDomain
from api.modules.ad.services.snapshots import latest_snapshot, snapshot_path
from api.modules.ksc.core.coverage import AdComputer, ad_computers_from_export
from api.modules.ksc.core.export import KscExport, unwrap


def _domains_of(export: KscExport) -> tuple[set[str], set[str]]:
    dns = {str(unwrap(h.get("KLHST_WKS_DNSDOMAIN")) or "").lower() for h in export.hosts}
    netbios = {str(unwrap(h.get("KLHST_WKS_WINDOMAIN")) or "").upper() for h in export.hosts}
    for d in export.domains:
        dns.add(str(unwrap(d.get("KLHST_WKS_DNSDOMAIN")) or "").lower())
        netbios.add(str(unwrap(d.get("KLHST_WKS_WINDOMAIN")) or "").upper())
    return dns - {""}, netbios - {"", "WORKGROUP"}


def ad_computers_for(db: Session, export: KscExport, data_dir: Path) -> list[AdComputer] | None:
    dns, netbios = _domains_of(export)
    computers: list[AdComputer] = []
    found = False
    for domain in db.execute(select(AdDomain)).scalars():
        if domain.dns_root.lower() not in dns and domain.netbios.upper() not in netbios:
            continue
        snap = latest_snapshot(db, domain.id)
        if snap is None:
            continue
        path = snapshot_path(data_dir, snap.id)
        if not path.exists():
            continue
        try:
            computers.extend(ad_computers_from_export(load_export_path(path)))
        except (ExportFormatError, OSError, ValueError):
            continue  # снапшот AD битый — сверяемся без этого домена, импорт KSC не роняем
        found = True
    return computers if found else None
