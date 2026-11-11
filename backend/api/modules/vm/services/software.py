"""Transactional local CVE evaluation for KSC software; no network calls."""
from __future__ import annotations

import json
from collections import defaultdict

from sqlalchemy import delete, func, select, text, tuple_
from sqlalchemy.orm import Session

from api.db.models import _utcnow
from api.modules.ksc.models import KscSnapshot
from api.modules.ksc.software_models import KscSoftware, KscSoftwareInventory
from api.modules.vm.core.software_match import evaluate, iter_products
from api.modules.vm.models import VmRefNvd
from api.modules.vm.services.bulk import bulk_insert
from api.modules.vm.software_models import VmKscCve, VmNvdProduct


def inventory_lock(db: Session) -> None:
    # Same transaction lock for feed replacement and snapshot ingestion: neither publishes stale findings.
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(730112026)"))


def latest_snapshot_ids():
    ranked = select(KscSnapshot.id, func.row_number().over(partition_by=KscSnapshot.server_id,
        order_by=(KscSnapshot.collected_at.desc(), KscSnapshot.id.desc())).label("position")).subquery()
    return select(ranked.c.id).where(ranked.c.position == 1)


def nvd_ready(db: Session) -> bool:
    return (db.scalar(select(VmRefNvd.cve_id).where(VmRefNvd.applicability_loaded.is_(True)).limit(1)) is not None
            and db.scalar(select(VmRefNvd.cve_id).where(VmRefNvd.applicability_loaded.is_(False)).limit(1)) is None)


def index_nvd_rows(db: Session, rows) -> None:
    indexed = ((row[0], vendor, product) for row in rows
               for vendor, product in sorted(iter_products(json.loads(row[-2]))))
    bulk_insert(db, VmNvdProduct.__table__, ("cve_id", "vendor", "product"), indexed)


def rebuild_ksc(db: Session, snapshot_id: int | None = None) -> None:
    inventory_lock(db)
    scope = KscSoftwareInventory.snapshot_id == snapshot_id if snapshot_id is not None else KscSoftwareInventory.snapshot_id.in_(latest_snapshot_ids())
    inventories = select(KscSoftwareInventory).where(scope).order_by(KscSoftwareInventory.id)
    ready = nvd_ready(db)
    cache: dict[tuple[str, str], list] = {}
    now = _utcnow()
    # Bound inventory/software memory. Reuse product candidates across hosts, never scan all CVEs per host.
    last_id = 0
    while True:
        batch = list(db.scalars(inventories.where(KscSoftwareInventory.id > last_id).limit(100)))
        if not batch:
            break
        last_id = batch[-1].id
        ids = [i.id for i in batch]
        softwares = list(db.scalars(select(KscSoftware).where(KscSoftware.inventory_id.in_(ids))))
        by_host: dict[int, list] = defaultdict(list)
        for software in softwares:
            by_host[software.inventory_id].append(software)
        db.execute(delete(VmKscCve).where(VmKscCve.software_id.in_(select(KscSoftware.id).where(KscSoftware.inventory_id.in_(ids)))))
        missing = list({(s.vendor_key, s.product_key) for s in softwares} - cache.keys())
        for start in range(0, len(missing), 250):
            keys = missing[start:start + 250]
            for key in keys:
                cache[key] = []
            query = select(VmNvdProduct.vendor, VmNvdProduct.product, VmRefNvd.cve_id, VmRefNvd.configurations_json).join(
                VmRefNvd, VmRefNvd.cve_id == VmNvdProduct.cve_id).where(tuple_(VmNvdProduct.vendor, VmNvdProduct.product).in_(keys))
            for vendor, product, cve_id, raw in db.execute(query):
                cache[(vendor, product)].append((cve_id, json.loads(raw)))
        for inv in batch:
            host_rows = by_host[inv.id]
            facts = [{"name": s.name, "publisher": s.publisher, "version": s.version} for s in host_rows]
            for software, fact in zip(host_rows, facts, strict=True):
                candidates = cache.get((software.vendor_key, software.product_key), [])
                software.assessment = "pending" if not ready else "unknown" if not candidates else "no_match"
                for cve_id, configs in candidates:
                    result = evaluate(fact, configs, facts, inv.os)
                    if result["state"] == "not_affected":
                        continue
                    if result["state"] == "affected":
                        software.assessment = "matched"
                    elif software.assessment != "matched":
                        software.assessment = "unknown"
                    db.add(VmKscCve(software_id=software.id, cve_id=cve_id, state=result["state"],
                        reason=result["reason"], evidence_json=json.dumps(result["evidence"], ensure_ascii=False), checked_at=now))
        db.flush()
