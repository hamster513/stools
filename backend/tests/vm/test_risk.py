"""Формула риска (спека 2026-10-21 §9): таблица случаев, подстановки, пороги уровней.

Ожидаемые баллы — из спеки при весах по умолчанию: неверная таблица весов
сдвинет хотя бы один из них.
"""
from __future__ import annotations

import datetime as dt

import pytest
from pydantic import ValidationError

from api.modules.vm.core.risk import (
    CveInputs,
    av_class,
    best_exploit_type,
    best_msf_rank,
    explain,
    host_value,
    level,
    likelihood,
    reach,
    score,
)
from api.modules.vm.core.weights import DEFAULT_WEIGHTS as W
from api.modules.vm.core.weights import Levels

# (имя, CVE, критичность, интернет, конф., балл, уровень)
CASES = [
    ("типичная", CveInputs(epss=0.0005, cvss=7.5, av="NETWORK"), "Medium", False, False, 0, "low"),
    ("EPSS 0.10 + remote", CveInputs(epss=0.10, cvss=9.0, av="NETWORK", exploitdb_type="remote"), "Medium", False, False, 16, "medium"),
    (
        "EPSS 0.5 + remote + excellent, Critical из интернета с конф.",
        CveInputs(epss=0.5, cvss=9.8, av="NETWORK", exploitdb_type="remote", msf_rank="excellent"),
        "Critical", True, True, 81, "critical",
    ),
    ("нет EPSS", CveInputs(cvss=7.5, av="NETWORK"), "Medium", False, False, 0, "low"),
    ("KEV 0.02 / 7.8 внутренний", CveInputs(epss=0.02, cvss=7.8, av="NETWORK", kev=True), "Medium", False, False, 37, "high"),
    ("KEV 9.8 Critical из интернета с конф.", CveInputs(epss=0.3, cvss=9.8, av="NETWORK", kev=True), "Critical", True, True, 98, "critical"),
    ("KEV 5.5 Low", CveInputs(epss=0.01, cvss=5.5, av="NETWORK", kev=True), "Low", False, False, 18, "medium"),
    ("LOCAL 0.9 / 7.8", CveInputs(epss=0.9, cvss=7.8, av="LOCAL"), "Medium", False, False, 17, "medium"),
]


@pytest.mark.parametrize(("name", "cve", "crit", "internet", "conf", "expected", "lvl"), CASES, ids=[c[0] for c in CASES])
def test_spec_cases(name: str, cve: CveInputs, crit: str, internet: bool, conf: bool, expected: int, lvl: str) -> None:
    e = explain(cve, crit, internet, conf, True, W)
    assert (e.score, e.level) == (expected, lvl)
    # Балл — произведение трёх членов, а члены — из своих частей.
    assert e.raw == pytest.approx(e.likelihood.value * e.severity.value * e.value.value)
    assert e.severity.value == pytest.approx(e.severity_parts["cvss"].value * e.severity_parts["reach"].value)


def test_control_example_by_hand() -> None:
    """EPSS 0.5, remote, excellent: L = 1 − 0.5 × 0.7 × 0.5; S = 0.98 × 1.0; V = min(1, 1.0 + 0.1 + 0.1)."""
    c = CveInputs(epss=0.5, cvss=9.8, av="NETWORK", exploitdb_type="remote", msf_rank="excellent")
    assert likelihood(c, W)[0].value == pytest.approx(0.825)
    assert host_value("Critical", internet=True, confidential=True, w=W) == 1.0
    assert explain(c, "Critical", True, True, True, W).raw == pytest.approx(0.825 * 0.98)


def test_missing_epss_uses_prior_and_flags_it() -> None:
    e = explain(CveInputs(cvss=7.5, av="NETWORK"), "Medium", False, False, True, W)
    assert e.likelihood_parts["epss"].value == W.prior_epss and e.likelihood_parts["epss"].substituted
    assert e.likelihood.substituted


def test_kev_overrides_likelihood_and_keeps_parts() -> None:
    e = explain(CveInputs(epss=0.02, cvss=7.8, av="NETWORK", kev=True, kev_added=dt.date(2021, 12, 10)), "Medium", False, False, True, W)
    assert e.likelihood.value == 1.0 and not e.likelihood.substituted
    kev = e.likelihood_parts["kev"]
    assert (kev.value, kev.substituted) == (1.0, False) and "10.12.2021" in kev.source
    assert e.likelihood_parts["epss"].value == 0.02


def test_not_in_kev_is_a_fact_unless_catalog_missing() -> None:
    known = explain(CveInputs(epss=0.1), "Medium", False, False, True, W).likelihood_parts["kev"]
    assert (known.value, known.substituted, known.source) == (0.0, False, "нет в KEV")
    missing = explain(CveInputs(epss=0.1, kev_loaded=False), "Medium", False, False, True, W).likelihood_parts["kev"]
    assert missing.substituted and missing.source == "справочник KEV не загружен"


def test_missing_cvss_and_vector_are_substituted() -> None:
    e = explain(CveInputs(epss=0.9), "High", False, False, True, W)
    assert e.severity_parts["cvss"].value == W.cvss_missing and e.severity_parts["cvss"].substituted
    assert e.severity_parts["reach"].value == W.reach_unknown and e.severity_parts["reach"].substituted
    assert e.severity.substituted


@pytest.mark.parametrize(
    ("v3", "v2", "cls"),
    [("NETWORK", "LOCAL", "network"), (None, "ADJACENT_NETWORK", "adjacent"), ("PHYSICAL", None, "local"), (None, None, "none")],
)
def test_av_class_v3_beats_v2(v3: str | None, v2: str | None, cls: str) -> None:
    assert av_class(v3, v2) == cls


def test_reach_by_vector_and_internet() -> None:
    assert reach("network", True, W) == 1.0 and reach("network", False, W) == 0.8
    assert (reach("adjacent", True, W), reach("local", True, W), reach("none", False, W)) == (0.6, 0.4, 0.8)


def test_network_reach_flagged_when_zone_unmarked() -> None:
    e = explain(CveInputs(epss=0.1, cvss=5.0, av="NETWORK"), "High", False, False, False, W)
    assert e.severity_parts["reach"].substituted
    assert e.value.substituted and e.value_parts["internet"].substituted


def test_value_is_capped_and_unknown_criticality_flagged() -> None:
    assert host_value("Critical", True, True, W) == 1.0
    assert host_value("Low", True, True, W) == pytest.approx(0.6)
    e = explain(CveInputs(), "", False, False, True, W)
    assert e.value_parts["criticality"].value == W.value.criticality["None"] and e.value_parts["criticality"].substituted


def test_best_exploit_type_and_rank_by_probability() -> None:
    assert best_exploit_type(["dos", "local", "remote"], W) == "remote"
    assert best_exploit_type([], W) is None
    assert best_msf_rank([100, 300, 600], W) == "excellent"
    assert best_msf_rank([999], W) == "unknown"


@pytest.mark.parametrize(
    "value,expected",
    [(0, "low"), (14, "low"), (15, "medium"), (34, "medium"), (35, "high"), (59, "high"), (60, "critical"), (100, "critical")],
)
def test_scale_boundaries(value: int, expected: str) -> None:
    assert level(value, W.levels) == expected


def test_levels_must_be_ordered() -> None:
    with pytest.raises(ValidationError):
        Levels(medium=35, high=35, critical=60)
    with pytest.raises(ValidationError):
        Levels(medium=15, high=35, critical=101)
    assert level(89, Levels(critical=90)) == "high"


def test_score_clamps_and_rounds_halves_up() -> None:
    assert score(1.7) == 100
    assert score(-0.2) == 0
    assert score(0.4567) == 46
    assert score(0.125) == 13  # round() дал бы 12 — до чётного
