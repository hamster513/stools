"""Правило «вектор CVSS → техника» и разбор справочника CTID."""
from __future__ import annotations

from pathlib import Path

import pytest

from api.modules.vm.core.attack_map import parse_ctid_csv, parse_ctid_json, technique_for

FIX = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    ("v3", "internet", "expected"),
    [
        (("NETWORK", "NONE", "NONE"), True, "T1190"),
        (("NETWORK", "NONE", "NONE"), False, "T1210"),
        (("NETWORK", "LOW", "REQUIRED"), False, "T1203"),
        (("NETWORK", "LOW", "NONE"), True, "T1210"),
        (("NETWORK", "HIGH", "NONE"), False, "T1210"),
        (("ADJACENT_NETWORK", "NONE", "NONE"), True, "T1557"),
        (("LOCAL", "LOW", "NONE"), True, "T1068"),
        (("PHYSICAL", "NONE", "NONE"), True, "T1068"),
    ],
)
def test_rule_v3(v3: tuple[str, str, str], internet: bool, expected: str) -> None:
    assert technique_for(*v3, None, None, internet) == expected


def test_rule_falls_back_to_v2_and_none() -> None:
    assert technique_for(None, None, None, "NETWORK", "NONE", True) == "T1190"
    assert technique_for(None, None, None, "NETWORK", "SINGLE", False) == "T1210"
    assert technique_for(None, None, None, "LOCAL", "NONE", False) == "T1068"
    assert technique_for(None, None, None, None, None, True) is None


def test_parse_ctid_json() -> None:
    with (FIX / "ctid-kev.json").open("rb") as fh:
        rows = sorted(parse_ctid_json(fh))
    assert rows == [
        ("CVE-2021-44228", "T1059", "primary_impact"),
        ("CVE-2024-34102", "T1005", "primary_impact"),
        ("CVE-2024-34102", "T1190", "exploitation_technique"),
    ]


def test_parse_ctid_csv() -> None:
    with (FIX / "attack_to_cve.csv").open("rb") as fh:
        rows = sorted(parse_ctid_csv(fh))
    assert ("CVE-2019-15243", "T1078", "exploitation_technique") in rows
    assert ("CVE-2019-15976", "T1059", "secondary_impact") in rows and len(rows) == 6
