"""Compare two priority models offline on one compact, canonicalized snapshot."""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, fields
from datetime import date
from typing import Any

from api.modules.vm.core.priority import AssetContext, priority_policy, priority_score
from api.modules.vm.core.risk import CveInputs, explain
from api.modules.vm.core.weights import Weights


def compare_snapshot(snapshot: dict[str, Any], limit: int = 100, *,
                     high_threshold: int | None = None) -> dict[str, Any]:
    policy = priority_policy(high_threshold)
    if limit < 1:
        raise ValueError("limit must be positive")
    weights = Weights.model_validate(snapshot["meta"]["weights"])
    allowed = {field.name for field in fields(CveInputs)}
    inputs = {}
    for record in snapshot["cves"]:
        data = {key: value for key, value in record.items() if key in allowed}
        data["kev_loaded"] = snapshot["meta"]["kev_loaded"]
        if isinstance(data.get("kev_added"), str):
            data["kev_added"] = date.fromisoformat(data["kev_added"])
        inputs[record["cve_id"]] = CveInputs(**data)
    entries: dict[str, dict[str, Any]] = {}
    unscored = set()
    unknown_contexts = Counter()
    for context in snapshot["contexts"]:
        identifier = context["cve_id"]
        canonical = snapshot["canonical"][identifier]
        cve = inputs.get(identifier)
        if cve is None:
            unscored.add(identifier)
            continue
        image = context["kind"] == "image"
        marked = bool(context["zone_marked"]) and not image
        criticality = None if image else context["criticality"]
        internet = False if image else bool(context["internet"])
        confidential = False if image else bool(context["confidential"])
        old = explain(cve, criticality, internet, confidential, marked, weights)
        new = priority_score(cve, AssetContext(criticality,
                             internet if marked else None, confidential if marked else None),
                             high_threshold=policy["levels"]["high"])
        unknown_contexts.update(new.missing)
        context_view = {"identifier": identifier, "kind": context["kind"], "criticality": criticality,
                        "internet": internet if marked else None, "confidential": confidential if marked else None,
                        "zone_marked": marked}
        key = json.dumps(context_view, sort_keys=True)
        old_context = dict(context_view, legacy_internet=internet, legacy_confidential=confidential)
        old_key = json.dumps(old_context, sort_keys=True)
        if canonical not in entries:
            prevalence = snapshot["prevalence"][canonical]
            entries[canonical] = {
                "id": canonical, "identifiers": set(), "old_score": -1, "new_score": -1,
                "stored_score": None, "kev": False, "cvss": None, "epss": None,
                "affected_hosts": prevalence["hosts"], "affected_images": prevalence["images"],
            }
        row = entries[canonical]
        row["identifiers"].add(identifier)
        row["kev"] = row["kev"] or cve.kev
        for metric in ("cvss", "epss"):
            value = getattr(cve, metric)
            if value is not None:
                row[metric] = max(row[metric], value) if row[metric] is not None else value
        stored = context.get("stored_score")
        if stored is not None:
            row["stored_score"] = max(row["stored_score"], stored) if row["stored_score"] is not None else stored
        if old.score > row["old_score"] or (old.score == row["old_score"] and old_key < row["_old_key"]):
            row.update(old_score=old.score, old_level=old.level, old_context=old_context, _old_key=old_key,
                       old_inputs=asdict(cve), old_explanation={"likelihood": old.likelihood.value,
                                        "cvss_normalized": old.severity_parts["cvss"].value,
                                        "reach": old.severity_parts["reach"].value,
                                        "asset_value": old.value.value, "raw": old.raw})
        if new.score > row["new_score"] or (new.score == row["new_score"] and key < row["_new_key"]):
            row.update(new_score=new.score, new_level=new.level, new_context=context_view,
                       new_inputs=asdict(cve), new_explanation=asdict(new), _new_key=key)
    rows = list(entries.values())
    old_order = sorted(rows, key=lambda row: (-row["old_score"], row["id"]))
    new_order = sorted(rows, key=lambda row: (-row["new_score"], row["id"]))
    for rank, row in enumerate(old_order, 1):
        row["old_rank"] = rank
    for rank, row in enumerate(new_order, 1):
        row["new_rank"] = rank
    for row in rows:
        row["rank_gain"] = row["old_rank"] - row["new_rank"]
        row["identifiers"] = sorted(row["identifiers"])
        del row["_old_key"], row["_new_key"]
    old_top, new_top = old_order[:limit], new_order[:limit]
    old_ids, new_ids = {r["id"] for r in old_top}, {r["id"] for r in new_top}

    def top_metrics(top, prefix):
        return {"kev": sum(r["kev"] for r in top),
                "cvss_ge_9": sum(r["cvss"] is not None and r["cvss"] >= 9 for r in top),
                "missing_epss": sum(r["epss"] is None for r in top),
                "critical_assets": sum(r[prefix+"_context"]["criticality"] == "Critical" for r in top),
                "known_external": sum(r[prefix+"_context"]["internet"] is True for r in top),
                "unknown_exposure": sum(r[prefix+"_context"]["internet"] is None for r in top)}

    def boundary(order, prefix):
        if not order:
            return {"score": None, "tie_size": 0, "strictly_above": 0}
        value = order[min(limit, len(order))-1][prefix+"_score"]
        return {"score": value, "tie_size": sum(r[prefix+"_score"] == value for r in order),
                "strictly_above": sum(r[prefix+"_score"] > value for r in order)}

    old_boundary, new_boundary = boundary(old_order, "old"), boundary(new_order, "new")
    return {
        "meta": snapshot["meta"],
        "policy": policy,
        "coverage": {"scored_vulnerabilities": len(rows), "observed_identifiers": len(snapshot["canonical"]),
                     "unscored_identifiers": sorted(unscored), "asset_contexts": len(snapshot["contexts"]),
                     "findings": sum(c["findings"] for c in snapshot["contexts"]),
                     "contexts_missing_fields": dict(sorted(unknown_contexts.items()))},
        "summary": {"top_limit": limit, "top_overlap": len(old_ids & new_ids),
                    "old_top_metrics": top_metrics(old_top, "old"), "new_top_metrics": top_metrics(new_top, "new"),
                    "old_boundary": old_boundary, "new_boundary": new_boundary,
                    "old_zero_scores": sum(r["old_score"] == 0 for r in rows),
                    "new_zero_scores": sum(r["new_score"] == 0 for r in rows),
                    "effective_floor_promotions": dict(sorted(Counter(
                        r["new_explanation"]["floor"] for r in rows
                        if r["new_score"] > r["new_explanation"]["base_score"]
                    ).items())),
                    "new_boundary_tie_size": new_boundary["tie_size"],
                    "stored_legacy_maxima_different": sum(r["stored_score"] is not None and r["stored_score"] != r["old_score"] for r in rows),
                    "old_levels": dict(sorted(Counter(r["old_level"] for r in rows).items())),
                    "new_levels": dict(sorted(Counter(r["new_level"] for r in rows).items())),
                    "old_histogram": dict(sorted(Counter((r["old_score"]//10)*10 for r in rows).items())),
                    "new_histogram": dict(sorted(Counter((r["new_score"]//10)*10 for r in rows).items()))},
        "old_top": old_top, "new_top": new_top,
        "entered": [r for r in new_top if r["id"] not in old_ids],
        "left": [r for r in old_top if r["id"] not in new_ids],
        "rows": sorted(rows, key=lambda row: row["id"]),
    }
