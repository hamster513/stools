"""Read-only comparison of Trivy's last success and the current MaxPatrol findings on the same asset."""

import json
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

from sqlalchemy import func, literal_column, select
from sqlalchemy.orm import Session

from api.modules.assets.models import Asset, AssetObservation
from api.modules.vm.core.software_identity import windows_product
from api.modules.vm.core.software_match import cpe_identity, evaluate, inventory_index
from api.modules.vm.models import VmHost, VmHostCve, VmImport, VmRefNvd, VmRefState
from api.modules.vm.sbom_models import HostSbomScan, VmHostCoverage
from api.modules.vm.services import host_sbom, trivy_scan
from api.modules.vm.services.ghsa_mapping import canonical_finding_ids
from api.modules.vm.services.host_packages import package_warnings
from api.modules.vm.services.software import candidate_records, nvd_ready


def component_nvd(db: Session, document: dict, ref: str, limit: int, offset: int) -> dict | None:
    components = document["components"]
    component = next((c for c in components if c["bom-ref"] == ref), None)
    if component is None:
        return None
    result = {"ready": nvd_ready(db), "examined": 0, "affected": 0, "unknown": 0, "items": []}
    identity = cpe_identity(component.get("cpe"))
    if not identity or not component.get("version"):
        return result
    os_name = next(p["value"] for p in document["metadata"]["properties"] if p["name"] == "stools:os-name")
    product = windows_product(component, os_name, {identity[1:]})
    keys = product.keys if product else (identity[1:],)
    environment = inventory_index(components, os_name)
    records = candidate_records(keys).order_by(VmRefNvd.cve_id.desc()).execution_options(yield_per=100)
    for cve_id, raw in db.execute(records):
        result["examined"] += 1
        match = evaluate(component, json.loads(raw), (), os_name, target_keys=keys, environment=environment)
        state = match["state"]
        if state == "not_affected":
            continue
        position = result["affected"] + result["unknown"]
        result[state] += 1
        if offset <= position < offset + limit:
            result["items"].append({"cve_id": cve_id, **match})
    return result


def comparison(
    db: Session, asset: Asset, data_dir: Path, group: str, limit: int, offset: int
) -> dict:
    scan = db.get(HostSbomScan, asset.id)
    revision = trivy_scan.database_revision(data_dir)
    target = host_sbom.current_target(db, asset.id, revision)
    if scan and scan.prepared_target == target and scan.sources and scan.components is not None:
        components, sources = scan.components, scan.sources
    else:
        bom, sources = host_sbom.inventory(db, asset, data_dir)
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
    vm_at = db.scalar(
        select(func.max(VmHostCoverage.observed_at)).where(VmHostCoverage.source_key.in_(keys))
    )
    vm_available = bool(host_ids) or vm_at is not None
    if vm_at is None and host_ids:
        vm_at = db.scalar(select(func.max(VmImport.finished_at)))
    findings = (scan.findings or []) if last_success else []
    comparable = bool(
        vm_available
        and last_success
        and scan.checked
        and status in {"ready", "partial"}
        and not any(s in {"stale", "error", "partial"} for s in sources.values())
    )
    return {
        "status": status,
        "inventory": sources,
        "inventory_warnings": (
            package_warnings(db, windows="windows" in (asset.os or "").lower())
            if sources["maxpatrol"] in {"error", "stale"} else []
        ),
        "components": components,
        "inventory_revision": target,
        "nvd_updated_at": db.scalar(select(VmRefState.loaded_at).where(VmRefState.name == "nvd")),
        "checked": scan.checked if last_success else None,
        "scanned_components": scan.scanned_components if last_success else None,
        "scan_at": scan.scan_at if last_success else None,
        "db_version": scan.db_version if last_success else None,
        "scanner_version": scan.scanner_version if last_success else None,
        "error": error,
        "vm_available": vm_available,
        "vm_at": vm_at,
        **_finding_page(db, host_ids, findings, comparable, group, limit, offset),
    }


def _finding_page(
    db: Session, host_ids: Sequence[int], findings: list[dict], comparable: bool,
    group: str, limit: int, offset: int,
) -> dict:
    vm_query = select(VmHostCve.cve_id).where(VmHostCve.host_id.in_(host_ids)).distinct()
    if not findings:
        # While Trivy is queued, the card only needs a count of the host's MaxPatrol findings.
        total = db.scalar(select(func.count()).select_from(vm_query.subquery())) if host_ids else 0
        kind = "vm_only" if comparable else "vm_uncompared"
        include = group in {"all", "unlinked", kind}
        ids = db.scalars(vm_query.order_by(VmHostCve.cve_id).offset(offset).limit(limit)) if include and total else ()
        return {
            "counts": {"both": 0, "trivy_only": 0, "vm_only": total} if comparable else None,
            "unlinked_total": total,
            "total": total if include else 0,
            "items": [{"id": vid, "group": kind, "packages": []} for vid in ids],
        }

    vm_ids = set(db.scalars(vm_query)) if host_ids else set()
    canonical = canonical_finding_ids(db, vm_ids | {row["vuln_id"] for row in findings})
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
    counts = None
    sections = {"trivy_uncompared": trivy_ids, "vm_uncompared": vm_ids}
    if comparable:
        sections = {
            "both": trivy_ids & vm_ids,
            "trivy_only": trivy_ids - vm_ids,
            "vm_only": vm_ids - trivy_ids,
        }
        counts = {name: len(values) for name, values in sections.items()}
    unlinked = "vm_only" if comparable else "vm_uncompared"
    unlinked_total = len(sections[unlinked])
    if group == "packages":
        visible = {key: ids for key, ids in sections.items() if key != unlinked}
    elif group == "unlinked":
        visible = {unlinked: sections[unlinked]}
    elif group == "all":
        visible = sections
    else:
        visible = {group: sections.get(group, set())}
    total = sum(len(ids) for ids in visible.values())
    items = []
    for kind, ids in visible.items():
        if offset >= len(ids):
            offset -= len(ids)
            continue
        page = sorted(ids)[offset:offset + limit - len(items)]
        items.extend(
            {"id": vid, "group": kind, "packages": [] if kind == unlinked else list(packages[vid].values())}
            for vid in page
        )
        if len(items) == limit:
            break
        offset = 0
    return {"counts": counts, "unlinked_total": unlinked_total, "total": total, "items": items}
