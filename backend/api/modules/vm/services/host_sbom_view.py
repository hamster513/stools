"""Read-only comparison of Trivy's last success and the current MaxPatrol findings on the same asset."""

import json
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

from sqlalchemy import func, literal_column, select
from sqlalchemy.orm import Session

from api.modules.assets.models import Asset, AssetObservation
from api.modules.vm.core.host_sbom import UNASSESSED
from api.modules.vm.core.software_identity import os_family, windows_product
from api.modules.vm.core.software_match import cpe_identity, evaluate, inventory_index
from api.modules.vm.core.vendor_profiles import upstream_profile
from api.modules.vm.models import VmHost, VmHostCve, VmImport, VmRefNvd, VmRefState
from api.modules.vm.sbom_models import HostSbomScan, VmHostCoverage
from api.modules.vm.services import host_sbom, trivy_scan
from api.modules.vm.services.ghsa_mapping import canonical_finding_ids
from api.modules.vm.services.host_packages import package_warnings
from api.modules.vm.services.software import candidate_records, nvd_ready

_VERSION_SOURCES = {"stools:ksc-version": "ksc", "stools:maxpatrol-version": "maxpatrol"}


def component_page(document: dict, q: str, limit: int, offset: int, by_name: bool) -> dict:
    rows = document["components"]
    term = q.strip().casefold()
    groups = defaultdict(list)
    for c in rows:
        groups[c["name"].casefold()].append(c)

    def matches(c):
        return (term in c["name"].casefold() or term in c.get("version", "").casefold()
                or any(p["name"] in _VERSION_SOURCES
                       and term in p["value"].casefold() for p in c["properties"]))

    def describe(c):
        props = {p["name"]: p["value"] for p in c["properties"]}
        return {"ref": c["bom-ref"], "name": c["name"], "version": c.get("version"),
                "purl": c.get("purl"), "cpe": c.get("cpe"), "publisher": c.get("publisher"),
                "arch": props.get("stools:arch"), "group": c.get("group"), "package_type": props.get("stools:package-type"),
                "reason": props.get(UNASSESSED), "winget_id": props.get("stools:winget-id"),
                "reported_versions": [{"source": _VERSION_SOURCES[p["name"]], "version": p["value"]}
                                      for p in c["properties"] if p["name"] in _VERSION_SOURCES],
                "sources": [p["value"] for p in c["properties"] if p["name"] == "stools:source"]}

    page = slice(offset, offset + limit)
    if by_name:
        matched = [group for group in groups.values() if not term or any(matches(c) for c in group)]
        items = [{"name": group[0]["name"], "variants": [describe(c) for c in group]} for group in matched[page]]
    else:
        matched = [c for c in rows if not term or matches(c)]
        items = [describe(c) for c in matched[page]]

    metadata = document["metadata"]
    root = metadata["component"]
    observed = next((p["value"] for p in metadata["properties"] if p["name"] == "stools:os-name"), "")
    note = None
    profile = upstream_profile(root["name"], root["version"]) if root["type"] == "operating-system" else None
    if root["type"] == "operating-system" and root["name"] in {"redos", "astra"}:
        label = "РЕД ОС" if root["name"] == "redos" else "Astra Linux"
        note = f"{label} {root['version']}. "
        note += (f"Системные пакеты проверяются по базе {profile.label}. В риск хоста входят CVE, "
                 "подтверждённые бюллетенем производителя.") if profile else "Для этого выпуска профиль поиска кандидатов не определён."
    elif os_family(observed) == "windows":
        note = ("Trivy проверяет пакеты поддерживаемых экосистем. Установленные Windows-программы "
                "с идентификатором CPE можно проверить по NVD.")
    elif any(p["value"] == "missing-or-incompatible-distribution" for c in rows
             for p in c["properties"] if p["name"] == UNASSESSED):
        note = "Для проверки системных пакетов нужны согласованные данные о названии и версии дистрибутива."
    return {"total": len(matched), "total_names": len(groups), "identified": sum(bool(c.get("purl")) for c in rows),
            "nvd_identified": sum(bool(c.get("cpe")) for c in rows), "coverage_note": note,
            "candidate_profile": profile.label if profile else None, "items": items}


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
    target = host_sbom.current_target(db, asset.id, trivy_scan.with_bulletin_revision(revision, data_dir))
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
    trusted = [row for row in findings if row.get("assessment") != "candidate"]
    page = _finding_page(db, host_ids, trusted, comparable, group, limit, offset)
    if group in {"candidates", "vendor_confirmed"}:
        assessment = "candidate" if group == "candidates" else group
        by_id = defaultdict(list)
        for row in findings:
            if row.get("assessment") == assessment:
                by_id[row["vuln_id"]].append(row)
        page.update(total=len(by_id), items=[{"id": vid, "group": assessment, "packages": by_id[vid]}
                    for vid in sorted(by_id)[offset:offset + limit]])
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
        "vendor_summary": scan.vendor_summary if last_success else None,
        "error": error,
        "vm_available": vm_available,
        "vm_at": vm_at,
        **page,
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
            for k in ("package", "installed_version", "fixed_version", "purl", "severity", "assessment",
                      "profile", "bulletin", "bulletin_url", "upstream_fixed_version") if k in row
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
