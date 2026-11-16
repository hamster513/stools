"""High threshold calibration must preserve non-compensable urgency."""
import pytest

from api.modules.vm.core.priority import AssetContext, priority_score
from api.modules.vm.core.risk import CveInputs
from api.modules.vm.services.priority_comparison import compare_snapshot
from tests.vm.test_priority_comparison import fixture


@pytest.mark.parametrize("threshold", [65, 70, 75, 80, 82])
def test_kev_never_drops_below_high(threshold):
    result = priority_score(CveInputs(kev=True, cvss=0, epss=0, av="LOCAL"),
                            AssetContext("Low", False, False), high_threshold=threshold)
    assert result.score == max(70, threshold)
    assert result.level == "high"
    assert result.floor == max(70, threshold)
    assert result.blocks["exploitation"].points == 40


@pytest.mark.parametrize("threshold", [65, 70, 75, 80, 82])
def test_critical_rules_do_not_change(threshold):
    external = priority_score(CveInputs(kev=True, cvss=0, epss=0, av="NETWORK"),
                              AssetContext("Low", True, False), high_threshold=threshold)
    ready = priority_score(CveInputs(msf_rank="good", cvss=9, epss=0, av="LOCAL"),
                           AssetContext("Critical", False, False), high_threshold=threshold)
    assert (external.score, external.level) == (90, "critical")
    assert (ready.score, ready.level) == (85, "critical")


def test_non_kev_score_is_unchanged_while_level_changes():
    cve = CveInputs(epss=.2, cvss=10, av="NETWORK")
    context = AssetContext("Critical", False, False)
    low = priority_score(cve, context, high_threshold=65)
    high = priority_score(cve, context, high_threshold=80)
    assert low.score == high.score == 70
    assert low.blocks == high.blocks
    assert (low.level, high.level) == ("high", "medium")


@pytest.mark.parametrize("threshold", [0, 40, 85, 100, 79.5, True, "80"])
def test_invalid_high_thresholds(threshold):
    with pytest.raises(ValueError):
        priority_score(CveInputs(), AssetContext(), high_threshold=threshold)


def test_comparison_metadata_and_scores_use_the_same_threshold():
    result = compare_snapshot(fixture(), high_threshold=80)
    assert result["policy"]["levels"] == {"medium": 40, "high": 80, "critical": 85}
    assert result["policy"]["floors"]["kev_minimum"] == 80
    kev = next(r for r in result["rows"] if r["kev"])
    assert kev["new_score"] >= 80 and kev["new_level"] in ("high", "critical")
    assert kev["new_explanation"]["version"] == result["policy"]["version"]


def test_calibration_counts_canonical_vulnerabilities_and_keeps_all_kev():
    from scripts.calibrate_vm_priority import calibrate_snapshot

    snapshot = fixture()
    for record in snapshot["cves"]:
        if not record["kev"]:
            record["epss"] = .2
    for context in snapshot["contexts"][:2]:
        context.update(criticality="Critical", internet=True)
    report, selected = calibrate_snapshot(snapshot, selected_high=80)
    variants = {v["threshold"]: v for v in report["variants"]}
    assert report["coverage"]["scored_vulnerabilities"] == 2
    assert variants[65]["urgent"] == variants[80]["urgent"] == 2
    assert variants[82]["urgent"] == 1
    assert variants[82]["demoted"]["count"] == 1
    assert variants[82]["demoted"]["cvss_ge_9"] == 1
    assert all(v["kev_urgent"] == 1 for v in report["variants"])
    assert variants[80]["affected_pairs_for_urgent_vulnerabilities"] == 2
    assert selected["policy"]["levels"]["high"] == 80


def test_calibration_empty_snapshot_and_selected_threshold_validation():
    from scripts.calibrate_vm_priority import calibrate_snapshot

    snapshot = fixture()
    snapshot.update(cves=[], contexts=[], canonical={}, prevalence={})
    report, _ = calibrate_snapshot(snapshot)
    assert all(v["urgent"] == 0 and v["reduction_pct"] == 0 for v in report["variants"])
    with pytest.raises(ValueError):
        calibrate_snapshot(snapshot, selected_high=79)


def test_calibrated_default_is_high_80_with_kev_minimum_80():
    result = priority_score(CveInputs(kev=True, cvss=0, epss=0, av="LOCAL"),
                            AssetContext("Low", False, False))
    assert (result.score, result.floor, result.level) == (80, 80, "high")
    assert result.version == "priority-v2-h80"
