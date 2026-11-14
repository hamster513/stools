"""Read-only software coverage and CVEs for an exact KSC snapshot and host."""
from __future__ import annotations

import json

from sqlalchemy import case, exists, func, or_, select
from sqlalchemy.orm import Session

from api.modules.ksc.models import KscSnapshot
from api.modules.ksc.software_models import KscSoftware, KscSoftwareInventory
from api.modules.vm.models import VmRefEpss, VmRefKev, VmRefNvd
from api.modules.vm.services.software import nvd_ready
from api.modules.vm.software_models import VmKscCve, VmNvdProduct

COVERAGE = ("checked", "unrecognized", "missing_version", "pending", "uncertain")


def host_software(db: Session, snap: KscSnapshot, host_id: str, *, q: str, coverage: str | None,
                  state: str | None, limit: int, software_offset: int, vuln_offset: int) -> dict:
    inventory = db.scalar(select(KscSoftwareInventory).where(
        KscSoftwareInventory.snapshot_id == snap.id, KscSoftwareInventory.host_id == host_id).limit(1))
    ready = nvd_ready(db)
    scope = KscSoftware.inventory_id == (inventory.id if inventory else -1)
    recognized = exists(select(VmNvdProduct.cve_id).where(
        VmNvdProduct.vendor == KscSoftware.vendor_key, VmNvdProduct.product == KscSoftware.product_key))
    # A successful match/no-match is evidence of a completed comparison. Unknown alone is not.
    category = case(
        (func.btrim(KscSoftware.version, " \t\r\n") == "", "missing_version"),
        (or_(not ready, KscSoftware.assessment == "pending"), "pending"),
        (KscSoftware.assessment.in_(("matched", "no_match")), "checked"),
        (recognized, "uncertain"), else_="unrecognized")
    counts = dict(db.execute(select(category, func.count()).where(scope).group_by(category)).all())
    summary = {key: counts.get(key, 0) for key in COVERAGE}
    summary["total"] = sum(summary.values())
    software = select(KscSoftware, category.label("coverage")).where(scope)
    if coverage:
        software = software.where(category == coverage)
    if q.strip():
        software = software.where(or_(*(column.icontains(q.strip(), autoescape=True)
            for column in (KscSoftware.name, KscSoftware.publisher, KscSoftware.version))))
    software_total = db.scalar(select(func.count()).select_from(software.subquery())) or 0
    software_rows = [{"id": s.id, "name": s.name, "publisher": s.publisher, "version": s.version,
                      "coverage": bucket, "assessment": s.assessment, "product_id": s.product_id,
                      "installed_on": s.installed_on, "install_dir": s.install_dir}
                     for s, bucket in db.execute(software.order_by(KscSoftware.name, KscSoftware.id)
                                                .limit(limit).offset(software_offset))]
    findings = select(VmKscCve, KscSoftware, func.coalesce(VmRefNvd.cvss_v3, VmRefNvd.cvss_v2),
                      VmRefEpss.epss, VmRefKev.cve_id).join(KscSoftware, KscSoftware.id == VmKscCve.software_id).join(
        VmRefNvd, VmRefNvd.cve_id == VmKscCve.cve_id).outerjoin(VmRefEpss, VmRefEpss.cve_id == VmKscCve.cve_id).outerjoin(
        VmRefKev, VmRefKev.cve_id == VmKscCve.cve_id).where(scope)
    finding_counts = dict(db.execute(select(VmKscCve.state, func.count()).join(
        KscSoftware, KscSoftware.id == VmKscCve.software_id).where(scope).group_by(VmKscCve.state)).all())
    if state:
        findings = findings.where(VmKscCve.state == state)
    finding_total = db.scalar(select(func.count()).select_from(findings.subquery())) or 0
    finding_rows = [{"id": f.id, "software_id": s.id, "name": s.name, "version": s.version,
                     "publisher": s.publisher, "cve_id": f.cve_id, "state": f.state, "reason": f.reason,
                     "evidence": json.loads(f.evidence_json), "checked_at": f.checked_at,
                     "cvss": cvss, "epss": epss, "kev": kev is not None}
                    for f, s, cvss, epss, kev in db.execute(findings.order_by(
                        func.coalesce(VmRefNvd.cvss_v3, VmRefNvd.cvss_v2).desc().nulls_last(), VmKscCve.id)
                        .limit(limit).offset(vuln_offset))]
    return {"snapshot_id": snap.id, "collected_at": snap.collected_at,
            "inventory_status": inventory.status if inventory else "not_collected",
            "inventory_error": inventory.error if inventory else None, "nvd_ready": ready,
            "coverage": summary, "finding_counts": {key: finding_counts.get(key, 0) for key in ("affected", "unknown")},
            "software": {"items": software_rows, "total": software_total},
            "vulnerabilities": {"items": finding_rows, "total": finding_total}}
