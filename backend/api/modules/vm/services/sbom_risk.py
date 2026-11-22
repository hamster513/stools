"""Publish only the manufacturer-confirmed CVEs from a currently claimed host scan."""

from collections.abc import Iterable

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from api.modules.assets.models import Asset, AssetObservation
from api.modules.vm.core.sources import CVE_RE
from api.modules.vm.sbom_models import VmSbomConfirmedCve
from api.modules.vm.services.scoring import (
    ensure_cves,
    lock_cve_membership,
    rebuild_cves,
    rescore_sbom_pairs,
)
from api.modules.vm.services.settings import load_settings


def lock_inventory_links(db: Session, asset_id: int) -> None:
    """Keep a source unlink or asset deletion from crossing the final target check."""
    db.scalar(select(Asset.id).where(Asset.id == asset_id).with_for_update(read=True, key_share=True))
    db.execute(select(AssetObservation.id).where(
        AssetObservation.asset_id == asset_id, AssetObservation.source.in_(("vm", "ksc")),
        AssetObservation.gone_at.is_(None)).order_by(AssetObservation.id).with_for_update(read=True)).all()


def publish_confirmed(db: Session, asset_id: int, findings: Iterable[dict]) -> None:
    """Replace one asset's risk evidence in the caller's scan-result transaction."""
    wanted = set()
    for row in findings:
        bulletin = row.get("bulletin")
        if row.get("assessment") != "vendor_confirmed" or not isinstance(bulletin, str) or not bulletin.strip():
            continue
        cve = str(row.get("vuln_id") or "").strip().upper()
        if cve.isascii() and len(cve) <= 32 and CVE_RE.fullmatch(cve):
            wanted.add(cve)
    pairs = VmSbomConfirmedCve.__table__
    existing = set(db.scalars(select(pairs.c.cve_id).where(pairs.c.asset_id == asset_id)))
    if existing != wanted:
        lock_cve_membership(db)
    removed = existing - wanted
    if removed:
        db.execute(delete(pairs).where(pairs.c.asset_id == asset_id, pairs.c.cve_id.in_(removed)))
    added = sorted(wanted - existing)
    if added:
        fresh = ensure_cves(db, added, commit=False)
        if fresh:
            rebuild_cves(db, load_settings(db).weights, fresh, commit=False)
        db.execute(pairs.insert(), [{"asset_id": asset_id, "cve_id": cve} for cve in added])
    if wanted:
        rescore_sbom_pairs(db, asset_id)
