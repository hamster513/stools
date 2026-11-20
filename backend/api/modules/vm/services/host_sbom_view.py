"""Read-only comparison of Trivy's last success and the current MaxPatrol findings on the same asset."""

from collections import defaultdict
from pathlib import Path

from sqlalchemy import func, literal_column, select
from sqlalchemy.orm import Session

from api.modules.assets.models import Asset, AssetObservation
from api.modules.vm.models import VmHost, VmHostCve, VmImport
from api.modules.vm.sbom_models import HostSbomScan, VmHostCoverage
from api.modules.vm.services import host_sbom, trivy_scan
from api.modules.vm.services.ghsa_mapping import canonical_finding_ids


def comparison(
    db: Session, asset: Asset, data_dir: Path, group: str, limit: int, offset: int
) -> dict:
    scan = db.get(HostSbomScan, asset.id)
    revision = trivy_scan.database_revision(data_dir)
    target = host_sbom.current_target(db, asset.id, revision)
    if scan and scan.prepared_target == target and scan.sources and scan.components is not None:
        components, sources = scan.components, scan.sources
    else:
        bom, sources = host_sbom.inventory(db, asset)
        components = len(bom["components"])
    last_success = scan is not None and scan.scan_at is not None
    status = scan.status if scan else "pending"
    error = scan.error if scan else None
    if not components:
        status = "empty" if "available" in sources.values() else "no_inventory"
    elif not revision:
        status, error = "blocked", "Для проверки нужна локальная база Trivy и доступный сканер."
    elif scan is not None and scan.status in {"ready", "partial"}:
        if target != scan.target:
            status = "stale"
        elif any(v in {"stale", "error", "partial"} for v in sources.values()):
            status = "partial"

    keys = select(AssetObservation.source_key).where(
        AssetObservation.asset_id == asset.id,
        AssetObservation.source == "vm",
        AssetObservation.gone_at.is_(None),
    )
    host_ids = db.scalars(
        select(VmHost.id).where((VmHost.hostname + literal_column("'|'") + VmHost.ip).in_(keys))
    ).all()
    vm_ids = (
        set(db.scalars(select(VmHostCve.cve_id).where(VmHostCve.host_id.in_(host_ids))))
        if host_ids
        else set()
    )
    vm_at = db.scalar(
        select(func.max(VmHostCoverage.observed_at)).where(VmHostCoverage.source_key.in_(keys))
    )
    vm_available = bool(host_ids) or vm_at is not None
    if vm_at is None and host_ids:
        vm_at = db.scalar(select(func.max(VmImport.finished_at)))
    findings = (scan.findings or []) if last_success else []
    canonical = (
        canonical_finding_ids(db, vm_ids | {row["vuln_id"] for row in findings}) if findings else {}
    )
    vm_ids = {canonical.get(vid, vid) for vid in vm_ids}
    packages = defaultdict(dict)
    for row in findings:
        vid = row["vuln_id"]
        key = (
            row["package"],
            row["installed_version"],
            row["fixed_version"],
            row.get("purl") or "",
        )
        packages[canonical[vid]][key] = {
            k: row.get(k)
            for k in ("package", "installed_version", "fixed_version", "purl", "severity")
        }
    trivy_ids = set(packages)
    comparable = bool(
        vm_available
        and last_success
        and scan.checked
        and status in {"ready", "partial"}
        and not any(s in {"stale", "error", "partial"} for s in sources.values())
    )
    counts = None
    sections = {"trivy_uncompared": trivy_ids, "vm_uncompared": vm_ids}
    if comparable:
        sections = {
            "both": trivy_ids & vm_ids,
            "trivy_only": trivy_ids - vm_ids,
            "vm_only": vm_ids - trivy_ids,
        }
        counts = {name: len(values) for name, values in sections.items()}
    rows = [
        (name, vid)
        for name, ids in sections.items()
        if group == "all" or group == name
        for vid in sorted(ids)
    ]
    return {
        "status": status,
        "inventory": sources,
        "components": components,
        "checked": scan.checked if last_success else None,
        "scanned_components": scan.scanned_components if last_success else None,
        "scan_at": scan.scan_at if last_success else None,
        "db_version": scan.db_version if last_success else None,
        "scanner_version": scan.scanner_version if last_success else None,
        "error": error,
        "vm_available": vm_available,
        "vm_at": vm_at,
        "counts": counts,
        "total": len(rows),
        "items": [
            {"id": vid, "group": name, "packages": list(packages[vid].values())}
            for name, vid in rows[offset : offset + limit]
        ],
    }
