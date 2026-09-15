"""Формула риска: контрольный пример спеки §4 и подстановки при пропусках."""
from __future__ import annotations

import pytest

from api.modules.vm.core.risk import (
    CveInputs,
    best_exploit_type,
    best_msf_rank,
    cve_factor,
    explain,
    host_impact,
    level,
    score,
)
from api.modules.vm.core.weights import DEFAULT_WEIGHTS as W

FULL = CveInputs(
    epss=0.5,
    cvss=8.0,
    v3_av="NETWORK",
    v3_pr="NONE",
    v3_ui="NONE",
    exploitdb_type="remote",
    msf_rank="excellent",
)


def test_control_example_gives_100() -> None:
    impact = host_impact("Critical", internet=True, confidential=True, w=W)
    assert impact == pytest.approx(0.99)
    factor = cve_factor(FULL, W)
    assert factor == pytest.approx(0.5 * 0.8 * 1.656 * 1.3 * 1.3)
    assert score(factor * impact) == 100


def test_missing_epss_substitutes_half_and_flags_it() -> None:
    e = explain(CveInputs(cvss=5.0), "High", False, False, True, W)
    assert e.epss.value == 0.5 and e.epss.substituted
    assert e.cvss.value == 0.5 and not e.cvss.substituted


def test_missing_cvss_is_neutral() -> None:
    e = explain(CveInputs(epss=0.9), "High", False, False, True, W)
    assert e.cvss.value == 1.0 and e.cvss.substituted


def test_v3_beats_v2() -> None:
    both = CveInputs(v3_av="LOCAL", v3_pr="HIGH", v3_ui="REQUIRED", v2_av="NETWORK", v2_ac="LOW", v2_au="NONE")
    e = explain(both, "None", False, False, True, W)
    assert e.cve_param.value == pytest.approx(0.95 * 0.85 * 0.90)
    assert e.cve_param.source.startswith("v3")


def test_v2_used_when_no_v3() -> None:
    e = explain(CveInputs(v2_av="NETWORK", v2_ac="LOW", v2_au="NONE"), "None", False, False, True, W)
    assert e.cve_param.value == pytest.approx(1.20 * 1.10 * 1.15)


def test_no_metrics_no_exploit_no_msf_are_neutral_and_flagged() -> None:
    e = explain(CveInputs(), "Medium", False, False, True, W)
    assert (e.cve_param.value, e.exdb_param.value, e.msf_param.value) == (1.0, 1.0, 1.0)
    assert e.cve_param.substituted and e.exdb_param.substituted and e.msf_param.substituted


def test_unknown_criticality_counts_as_none_and_is_flagged() -> None:
    e = explain(CveInputs(), "", False, False, True, W)
    assert e.impact_parts["criticality"].value == W.impact.criticality["None"]
    assert e.impact_parts["criticality"].substituted


def test_unmarked_zone_flags_impact() -> None:
    e = explain(CveInputs(), "High", False, False, False, W)
    assert e.impact.substituted and e.impact_parts["internet"].substituted


def test_best_exploit_type_and_rank_by_weight() -> None:
    assert best_exploit_type(["dos", "local", "remote"], W) == "remote"
    assert best_exploit_type([], W) is None
    assert best_msf_rank([100, 300, 600], W) == "excellent"
    assert best_msf_rank([999], W) == "unknown"


@pytest.mark.parametrize(
    "value,expected",
    [(0, "low"), (19, "low"), (20, "medium"), (39, "medium"), (40, "high"), (69, "high"), (70, "critical"), (100, "critical")],
)
def test_scale_boundaries(value: int, expected: str) -> None:
    assert level(value) == expected


def test_score_clamps() -> None:
    assert score(1.7) == 100
    assert score(-0.2) == 0
    assert score(0.4567) == 46
