"""Read-only compact VM snapshot. Run inside API: python - < this_file.py.

Only normalized risk factors and aggregate counts are exported, never hostnames,
addresses, secrets, descriptions, package payloads, or raw scanner reports.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import UTC, datetime

from sqlalchemy import cast, false, func, literal, select, union_all
from sqlalchemy.dialects.postgresql import JSONB

from api.db.base import get_engine
from api.db.models import AppSetting
from api.modules.vm.core.weights import Weights
from api.modules.vm.models import VmCve, VmHost, VmHostCve, VmImageCve, VmRefState, VmZone
from api.modules.vm.services.ghsa_mapping import canonical_finding_id
from api.modules.vm.services.settings import VM_KEY


def export_snapshot(engine):
    started = time.monotonic()
    with engine.connect().execution_options(isolation_level="REPEATABLE READ") as conn, conn.begin():
        conn.exec_driver_sql("SET TRANSACTION READ ONLY")
        conn.exec_driver_sql("SET LOCAL statement_timeout = '120s'")
        conn.exec_driver_sql("SET LOCAL lock_timeout = '3s'")
        meta = {"captured_at": datetime.now(UTC).isoformat(),
                "transaction_read_only": conn.exec_driver_sql("SHOW transaction_read_only").scalar_one(),
                "transaction_isolation": conn.exec_driver_sql("SHOW transaction_isolation").scalar_one(),
                "snapshot": conn.exec_driver_sql("SELECT txid_current_snapshot()::text").scalar_one()}
        assert meta["transaction_read_only"] == "on"
        raw_weights = conn.execute(select(cast(func.nullif(AppSetting.value_json, ""), JSONB)["weights"]).where(AppSetting.key == VM_KEY)).scalar_one_or_none()
        old_schema = isinstance(raw_weights, dict) and "levels" not in raw_weights
        meta["weights"] = Weights.model_validate({} if old_schema or not raw_weights else raw_weights).model_dump()
        meta["legacy_weights_fallback"] = old_schema
        references = list(conn.execute(select(VmRefState.name, VmRefState.loaded_at, VmRefState.records)).mappings())
        meta["references"] = [dict(r) for r in references]
        meta["kev_loaded"] = any(r["name"] == "kev" and r["loaded_at"] is not None for r in references)
        meta["host_findings"] = conn.execute(select(func.count()).select_from(VmHostCve)).scalar_one()
        meta["image_findings"] = conn.execute(select(func.count()).select_from(VmImageCve)).scalar_one()
        meta["hosts_with_findings"] = conn.execute(select(func.count(func.distinct(VmHostCve.host_id)))).scalar_one()
        meta["images_with_findings"] = conn.execute(select(func.count(func.distinct(VmImageCve.image_id)))).scalar_one()
        observed = select(VmHostCve.cve_id).union(select(VmImageCve.cve_id)).cte("priority_observed_ids")
        canonical = select(observed.c.cve_id, canonical_finding_id(observed.c.cve_id).label("canonical")).cte("priority_canonical_ids").prefix_with("MATERIALIZED")
        canonical_map = dict(conn.execute(select(canonical)).tuples().all())
        cves = [dict(r) for r in conn.execute(select(
            VmCve.cve_id, VmCve.cvss, VmCve.epss,
            func.coalesce(func.nullif(VmCve.v3_av, ""), VmCve.v2_av).label("av"), VmCve.exploitdb_type,
            VmCve.msf_rank, VmCve.kev, VmCve.kev_added,
        ).join(observed, observed.c.cve_id == VmCve.cve_id)).mappings()]
        internet = func.coalesce(VmZone.internet_access, false())
        confidential = func.coalesce(VmZone.confidential_data, false())
        marked = func.coalesce(VmZone.marked, false())
        host_groups = select(
            VmHostCve.cve_id, literal("host").label("kind"), VmHost.criticality,
            internet.label("internet"), confidential.label("confidential"), marked.label("zone_marked"),
            func.max(VmHostCve.risk).label("stored_score"), func.count().label("findings"),
            func.count(func.distinct(VmHostCve.host_id)).label("asset_count"),
        ).join(VmHost, VmHost.id == VmHostCve.host_id).outerjoin(VmZone, VmZone.name == VmHost.zone).group_by(
            VmHostCve.cve_id, VmHost.criticality, internet, confidential, marked,
        )
        contexts = [dict(r) for r in conn.execute(host_groups).mappings()]
        image_groups = select(VmImageCve.cve_id, func.max(VmImageCve.risk).label("stored_score"),
                              func.count().label("findings"), func.count(func.distinct(VmImageCve.image_id)).label("asset_count")).group_by(VmImageCve.cve_id)
        contexts.extend(dict(r, kind="image", criticality=None, internet=False, confidential=False, zone_marked=False)
                        for r in conn.execute(image_groups).mappings())
        findings = union_all(
            select(literal("host").label("kind"), VmHostCve.host_id.label("asset_id"), VmHostCve.cve_id),
            select(literal("image").label("kind"), VmImageCve.image_id.label("asset_id"), VmImageCve.cve_id),
        ).cte("priority_findings")
        counts = select(canonical.c.canonical,
                        func.count(func.distinct(findings.c.asset_id)).filter(findings.c.kind == "host").label("hosts"),
                        func.count(func.distinct(findings.c.asset_id)).filter(findings.c.kind == "image").label("images"),
                        ).select_from(findings.join(canonical, canonical.c.cve_id == findings.c.cve_id)).group_by(canonical.c.canonical)
        prevalence = {r["canonical"]: {"hosts": r["hosts"], "images": r["images"]} for r in conn.execute(counts).mappings()}
        assert sum(c["findings"] for c in contexts) == meta["host_findings"] + meta["image_findings"]
        assert {canonical_map[c["cve_id"]] for c in contexts} == set(prevalence)
        meta["export_seconds"] = round(time.monotonic() - started, 3)
        return {"meta": meta, "cves": cves, "contexts": contexts, "canonical": canonical_map, "prevalence": prevalence}

if __name__ == "__main__":
    result = export_snapshot(get_engine())
    json.dump(result, sys.stdout, default=lambda value: value.isoformat(), ensure_ascii=False)
    print(file=sys.stdout)
