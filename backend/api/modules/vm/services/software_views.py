"""Paginated read models joining current KSC observations to canonical assets."""
from __future__ import annotations

import json

from sqlalchemy import String, and_, cast, func, or_, select
from sqlalchemy.orm import Session

from api.modules.assets.models import AssetObservation
from api.modules.ksc.models import KscHost, KscSnapshot
from api.modules.ksc.software_models import KscSoftware, KscSoftwareInventory
from api.modules.vm.models import VmRefEpss, VmRefKev, VmRefNvd
from api.modules.vm.services.software import latest_snapshot_ids, nvd_ready
from api.modules.vm.software_models import VmKscCve


def _search(q: str, columns):
    escaped = q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return or_(*(c.ilike(f"%{escaped}%", escape="\\") for c in columns))


def asset_software(db: Session, asset_id: int, q: str, limit: int, offset: int) -> dict:
    inventories = []
    inv_ids = []
    observations = db.scalars(select(AssetObservation).where(AssetObservation.asset_id == asset_id,
        AssetObservation.source == "ksc", AssetObservation.gone_at.is_(None)).order_by(AssetObservation.id))
    for observation in observations:
        server, sep, host_id = observation.source_key.partition(":")
        if not sep or not server.isdecimal():
            continue
        snap = db.scalar(select(KscSnapshot).where(KscSnapshot.server_id == int(server), KscSnapshot.id.in_(latest_snapshot_ids())))
        if snap is None:
            continue
        inv = db.scalar(select(KscSoftwareInventory).where(KscSoftwareInventory.snapshot_id == snap.id, KscSoftwareInventory.host_id == host_id))
        if inv is None and db.scalar(select(KscHost.id).where(KscHost.snapshot_id == snap.id, KscHost.host_id == host_id).limit(1)) is None:
            continue  # Host is no longer present in latest snapshot.
        inventories.append({"server_id": snap.server_id, "snapshot_id": snap.id, "host_id": host_id,
            "host_name": inv.host_name if inv else observation.name, "collected_at": snap.collected_at,
            "status": inv.status if inv else "not_collected", "error": inv.error if inv else None})
        if inv:
            inv_ids.append(inv.id)
    query = select(KscSoftware, KscSoftwareInventory, KscSnapshot).join(KscSoftwareInventory,
        KscSoftware.inventory_id == KscSoftwareInventory.id).join(KscSnapshot,
        KscSoftwareInventory.snapshot_id == KscSnapshot.id).where(KscSoftware.inventory_id.in_(inv_ids))
    if q.strip():
        query = query.where(_search(q, (KscSoftware.name, KscSoftware.publisher, KscSoftware.version)))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    page = list(db.execute(query.order_by(KscSoftware.name, KscSoftware.id).limit(limit).offset(offset)))
    counts = dict(db.execute(select(VmKscCve.software_id, func.count()).where(
        VmKscCve.software_id.in_([s.id for s, _, _ in page])).group_by(VmKscCve.software_id)).all())
    items = [{"id": s.id, "server_id": snap.server_id, "snapshot_id": snap.id, "host_id": inv.host_id,
        "host_name": inv.host_name, "name": s.name, "version": s.version, "publisher": s.publisher,
        "product_id": s.product_id, "installed_on": s.installed_on, "install_dir": s.install_dir,
        "collected_at": snap.collected_at, "assessment": s.assessment, "cve_count": counts.get(s.id, 0)} for s, inv, snap in page]
    return {"items": items, "total": total, "inventories": inventories, "nvd_ready": nvd_ready(db)}


def ksc_vulns(db: Session, q: str, state: str | None, asset_id: int | None, limit: int, offset: int) -> dict:
    query = select(VmKscCve, KscSoftware, KscSoftwareInventory, KscSnapshot, AssetObservation.asset_id,
        func.coalesce(VmRefNvd.cvss_v3, VmRefNvd.cvss_v2), VmRefEpss.epss, VmRefKev.cve_id).join(
        KscSoftware, VmKscCve.software_id == KscSoftware.id).join(KscSoftwareInventory,
        KscSoftware.inventory_id == KscSoftwareInventory.id).join(KscSnapshot,
        KscSoftwareInventory.snapshot_id == KscSnapshot.id).join(VmRefNvd, VmRefNvd.cve_id == VmKscCve.cve_id).outerjoin(
        VmRefEpss, VmRefEpss.cve_id == VmKscCve.cve_id).outerjoin(VmRefKev, VmRefKev.cve_id == VmKscCve.cve_id).outerjoin(
        AssetObservation, and_(AssetObservation.source == "ksc", AssetObservation.gone_at.is_(None),
            AssetObservation.source_key == cast(KscSnapshot.server_id, String) + ":" + KscSoftwareInventory.host_id)).where(
        KscSnapshot.id.in_(latest_snapshot_ids()))
    if asset_id is not None:
        query = query.where(AssetObservation.asset_id == asset_id)
    if state:
        query = query.where(VmKscCve.state == state)
    if q.strip():
        query = query.where(_search(q, (KscSoftware.name, KscSoftware.version, KscSoftware.publisher,
                                       KscSoftwareInventory.host_name, VmKscCve.cve_id)))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    page = db.execute(query.order_by(func.coalesce(VmRefNvd.cvss_v3, VmRefNvd.cvss_v2).desc().nulls_last(),
                                    VmKscCve.id).limit(limit).offset(offset))
    items = [{"id": finding.id, "software_id": s.id, "asset_id": aid, "source": "ksc",
        "server_id": snap.server_id, "snapshot_id": snap.id, "host_id": inv.host_id, "host_name": inv.host_name,
        "name": s.name, "version": s.version, "publisher": s.publisher, "cve_id": finding.cve_id,
        "cvss": cvss, "epss": epss, "kev": kev is not None, "state": finding.state, "reason": finding.reason,
        "evidence": json.loads(finding.evidence_json), "collected_at": snap.collected_at,
        "checked_at": finding.checked_at} for finding, s, inv, snap, aid, cvss, epss, kev in page]
    return {"items": items, "total": total, "nvd_ready": nvd_ready(db)}
