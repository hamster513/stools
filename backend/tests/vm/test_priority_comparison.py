"""Offline ranking must preserve the legacy baseline and canonical identity."""
import copy

from api.modules.vm.core.risk import CveInputs, explain
from api.modules.vm.core.weights import Weights
from api.modules.vm.services.priority_comparison import compare_snapshot


def fixture():
    return {
        "meta": {"kev_loaded": True, "weights": Weights().model_dump(), "transaction_read_only": "on"},
        "cves": [
            {"cve_id": "CVE-2026-0001", "cvss": 9.8, "epss": .01, "av": "NETWORK", "kev": False},
            {"cve_id": "GHSA-aaaa-bbbb-cccc", "cvss": 9.8, "epss": .01, "av": "NETWORK", "kev": False},
            {"cve_id": "CVE-2026-0002", "cvss": 5, "epss": .001, "av": "LOCAL", "kev": True},
        ],
        "canonical": {"CVE-2026-0001": "CVE-2026-0001", "GHSA-aaaa-bbbb-cccc": "CVE-2026-0001", "CVE-2026-0002": "CVE-2026-0002", "UNKNOWN": "UNKNOWN"},
        "contexts": [
            {"cve_id": cve, "kind": "host", "criticality": "High", "internet": False, "confidential": False,
             "zone_marked": True, "stored_score": 0, "findings": 1, "asset_count": 1}
            for cve in ("CVE-2026-0001", "GHSA-aaaa-bbbb-cccc", "CVE-2026-0002", "UNKNOWN")
        ],
        "prevalence": {"CVE-2026-0001": {"hosts": 1, "images": 0}, "CVE-2026-0002": {"hosts": 1, "images": 0}, "UNKNOWN": {"hosts": 1, "images": 0}},
    }


def test_legacy_parity_and_alias_deduplication():
    snapshot = fixture()
    result = compare_snapshot(snapshot, limit=100)
    assert len(result["rows"]) == 2
    row = next(r for r in result["rows"] if r["id"] == "CVE-2026-0001")
    expected = explain(CveInputs(cvss=9.8, epss=.01, av="NETWORK"), "High", False, False, True, Weights())
    assert row["old_score"] == expected.score
    assert row["affected_hosts"] == 1
    assert set(row["identifiers"]) == {"CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"}
    assert result["coverage"]["unscored_identifiers"] == ["UNKNOWN"]
    assert result["summary"]["top_overlap"] == 2


def test_rankings_and_best_context_are_stable_when_input_order_changes():
    snapshot = fixture()
    first = compare_snapshot(snapshot, limit=1)
    snapshot["contexts"].reverse()
    second = compare_snapshot(snapshot, limit=1)
    assert first == second
    assert first["new_top"][0]["id"] == "CVE-2026-0002"
    assert first["new_top"][0]["new_score"] >= 70


def test_images_have_unknown_new_context_and_legacy_default_context():
    snapshot = fixture()
    snapshot["contexts"] = [dict(snapshot["contexts"][0], kind="image", criticality=None, zone_marked=False)]
    snapshot["prevalence"]["CVE-2026-0001"] = {"hosts": 0, "images": 1}
    row = compare_snapshot(snapshot)["rows"][0]
    expected = explain(CveInputs(cvss=9.8, epss=.01, av="NETWORK"), None, False, False, False, Weights())
    assert row["old_score"] == expected.score
    assert "exposure" in row["new_explanation"]["missing"]
    assert row["affected_images"] == 1


def test_unknown_zone_does_not_trigger_external_floor_and_input_is_not_mutated():
    snapshot = fixture()
    snapshot["cves"][0]["kev"] = True
    snapshot["contexts"] = [dict(snapshot["contexts"][0], zone_marked=False, internet=True)]
    before = copy.deepcopy(snapshot)
    result = compare_snapshot(snapshot)
    assert result["rows"][0]["new_explanation"]["floor"] == 80
    assert snapshot == before


def test_empty_snapshot_and_score_boundary_ties():
    snapshot = fixture()
    snapshot["contexts"] = []
    assert compare_snapshot(snapshot)["new_top"] == []
    snapshot = fixture()
    snapshot["cves"][2] = dict(snapshot["cves"][0], cve_id="CVE-2026-0002")
    result = compare_snapshot(snapshot, limit=1)
    assert result["summary"]["new_boundary_tie_size"] == 2
    assert result["new_top"][0]["id"] == "CVE-2026-0001"


def test_old_explanation_ties_include_legacy_flags_on_unmarked_zones():
    snapshot = fixture()
    snapshot["cves"][0].update(cvss=5, epss=.001)
    context = dict(snapshot["contexts"][0], zone_marked=False)
    snapshot["contexts"] = [dict(context, internet=False), dict(context, internet=True)]
    first = compare_snapshot(snapshot)
    snapshot["contexts"].reverse()
    assert compare_snapshot(snapshot) == first
