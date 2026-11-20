"""Transactional local CVE evaluation for KSC software; no network calls."""
from __future__ import annotations

import json
from collections import defaultdict
from functools import lru_cache

from sqlalchemy import String, cast, delete, func, select, text, tuple_
from sqlalchemy.orm import Session

from api.db.models import _utcnow
from api.modules.assets.models import Asset, AssetObservation
from api.modules.ksc.models import KscSnapshot
from api.modules.ksc.software_models import KscSoftware, KscSoftwareInventory
from api.modules.vm.core.software_identity import (
    needs_os_hint,
    observed_os,
    os_family,
    product_key,
    windows_candidates,
    windows_product,
)
from api.modules.vm.core.software_match import evaluate, inventory_index, iter_products
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


def indexed_products(db, keys):
    keys = sorted(set(keys))
    found = set()
    for start in range(0, len(keys), 250):
        found.update(tuple(row) for row in db.execute(select(
            VmNvdProduct.vendor, VmNvdProduct.product).distinct().where(
                tuple_(VmNvdProduct.vendor, VmNvdProduct.product).in_(keys[start:start + 250]))))
    return found


def candidate_records(keys):
    ids = select(VmNvdProduct.cve_id).where(tuple_(VmNvdProduct.vendor, VmNvdProduct.product).in_(keys))
    return select(VmRefNvd.cve_id, VmRefNvd.configurations_json).where(VmRefNvd.cve_id.in_(ids))


def _host_assessor(cache, ready):
    """Reuse scores only when every application prerequisite sees the same installed versions."""
    @lru_cache(maxsize=256)
    def product_rules(keys):
        candidates = {cid: cfg for key in keys for cid, cfg in cache.get(key, ())}
        dependencies = {key for cfg in candidates.values() for key in iter_products(cfg, vulnerable_only=False)}
        return candidates, dependencies

    @lru_cache(maxsize=64)
    def matches(keys, name, version, os_name, signature):
        candidates, _ = product_rules(keys)
        assessment = "pending" if not ready else "unknown" if not candidates else "no_match"
        findings = []
        environment = {k: [{"name": n, "version": v} for n, v in entries] for k, entries in signature}
        for cve_id, configs in candidates.items():
            result = evaluate({"name": name, "version": version}, configs, (), os_name,
                              target_keys=keys, environment=environment)
            state = result["state"]
            if state == "not_affected":
                continue
            if state == "affected":
                assessment = "matched"
            elif assessment != "matched":
                assessment = "unknown"
            findings.append((cve_id, state, result["reason"], json.dumps(result["evidence"], ensure_ascii=False)))
        return assessment, findings

    def assess(keys, fact, os_name, versions):
        _, required = product_rules(keys)
        signature = tuple((k, versions[k]) for k in sorted(versions.keys() & required))
        return matches(keys, fact["name"], fact["version"], os_name, signature)

    return assess


def rebuild_ksc(db: Session, snapshot_id: int | None = None) -> None:
    inventory_lock(db)
    scope = KscSoftwareInventory.snapshot_id == snapshot_id if snapshot_id is not None else KscSoftwareInventory.snapshot_id.in_(latest_snapshot_ids())
    inventories = select(KscSoftwareInventory).where(scope).order_by(KscSoftwareInventory.id)
    ready = nvd_ready(db)
    cache: dict[tuple[str, str], list] = {}
    assess = _host_assessor(cache, ready)
    columns = ("software_id", "cve_id", "state", "reason", "evidence_json", "checked_at")
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
        os_by_id = {inv.id: inv.os for inv in batch}
        missing_os = [inv.id for inv in batch if needs_os_hint(inv.os)]
        if missing_os:
            asset_os = (select(KscSoftwareInventory.id, Asset.os).select_from(KscSoftwareInventory)
                        .join(KscSnapshot).join(AssetObservation, AssetObservation.source_key ==
                            cast(KscSnapshot.server_id, String) + ":" + KscSoftwareInventory.host_id)
                        .join(Asset, Asset.id == AssetObservation.asset_id)
                        .where(KscSoftwareInventory.id.in_(missing_os), AssetObservation.source == "ksc",
                               AssetObservation.gone_at.is_(None), Asset.merged_into.is_(None)))
            for inv_id, hint in db.execute(asset_os):
                os_by_id[inv_id] = observed_os((os_by_id[inv_id], hint))
        facts_by_host = {inv.id: [{"name": s.name, "publisher": s.publisher, "version": s.version,
                                  "product_id": s.product_id}
                                  for s in by_host[inv.id]] for inv in batch}
        keys_by_host = {}
        wanted = set()
        for inv in batch:
            lookups = []
            for fact in facts_by_host[inv.id]:
                if os_family(os_by_id[inv.id]) == 'windows':
                    _, keys = windows_candidates(fact, os_by_id[inv.id])
                else:
                    keys = (product_key(fact["publisher"], fact["name"], fact["version"]),)
                lookups.append(keys)
                wanted.update(keys)
            keys_by_host[inv.id] = lookups
        missing = list(wanted - cache.keys())
        for start in range(0, len(missing), 250):
            keys = missing[start:start + 250]
            for key in keys:
                cache[key] = []
            query = select(VmNvdProduct.vendor, VmNvdProduct.product, VmRefNvd.cve_id, VmRefNvd.configurations_json).join(
                VmRefNvd, VmRefNvd.cve_id == VmNvdProduct.cve_id).where(tuple_(VmNvdProduct.vendor, VmNvdProduct.product).in_(keys))
            for vendor, product, cve_id, raw in db.execute(query):
                cache[(vendor, product)].append((cve_id, json.loads(raw)))
        inserts = []
        for inv in batch:
            host_rows = by_host[inv.id]
            facts = facts_by_host[inv.id]
            os_name = os_by_id[inv.id]
            resolved_keys = []
            for fact, keys in zip(facts, keys_by_host[inv.id], strict=True):
                if os_family(os_name) == 'windows':
                    resolved = windows_product(fact, os_name, {k for k in keys if cache.get(k)})
                    keys = resolved.keys if resolved else ()
                    if resolved:
                        fact["cpe"] = resolved.cpe_for(fact["version"])
                resolved_keys.append(keys)
            environment = inventory_index(facts, os_name)
            versions = {key: tuple(sorted({(item["name"], item["version"]) for item in items}))
                        for key, items in environment.items()}
            for software, fact, keys in zip(host_rows, facts, resolved_keys, strict=True):
                software.assessment, findings = assess(keys, fact, os_name, versions)
                inserts.extend((software.id, *finding, now) for finding in findings)
                if len(inserts) >= 2000:
                    bulk_insert(db, VmKscCve.__table__, columns, inserts)
                    inserts.clear()
        bulk_insert(db, VmKscCve.__table__, columns, inserts)
        db.flush()
