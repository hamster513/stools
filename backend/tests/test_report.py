import json
from collections.abc import Callable
from pathlib import Path

from kbaudit.profile import Profile, TableRoles
from kbaudit.report import run_audit

U1 = "000ffb49-bb9e-4ee4-9262-6754b7ee28d2"

META = """
ObjectId: LOC-CR-1
Origin: Local
"""

CO = """
event Start:
    filter { msgid == "4688" and event_src.host == "host31.corp.internal" }
query Q = select("h") from DEMO_Critical_Hosts_by_Rule
"""


def archive(synthetic_zip: Callable[..., Path]) -> Path:
    return synthetic_zip({
        "taxonomy.json": json.dumps({"msgid": {}, "event_src.host": {}}),
        f"correlation-rules/rules/correlation/{U1}/metainfo.yaml": META,
        f"correlation-rules/rules/correlation/{U1}/DEMO_HC_002_029_Impacket.co": CO,
        "correlation_defaults.json": json.dumps(
            {"DEMO_Critical_Hosts_by_Rule": {"rows": [["srv99"]]}}
        ),
    })


def test_report_counts_rules_and_findings(synthetic_zip: Callable[..., Path]) -> None:
    report = run_audit(archive(synthetic_zip))
    assert report.rule_count == 1
    assert report.finding_count == 1
    assert report.findings_by_kind[2] == 1, "внутренний FQDN — класс 2"


def test_scoped_count_comes_from_profile_not_from_hardcoded_name(
    synthetic_zip: Callable[..., Path],
) -> None:
    """Без профиля инструмент не знает, какие списки сужают область действия:
    в теле правила чтение списка и ограничение им выглядят одинаково."""
    path = archive(synthetic_zip)
    assert run_audit(path).scoped_count == 0

    marked = Profile(tables=TableRoles(scoping=["DEMO_Critical_Hosts_by_Rule"]))
    assert run_audit(path, marked).scoped_count == 1


def test_every_split_sums_to_total(synthetic_zip: Callable[..., Path]) -> None:
    report = run_audit(archive(synthetic_zip))
    assert sum(report.findings_by_kind.values()) == report.finding_count
    assert sum(report.findings_by_polarity.values()) == report.finding_count
    assert sum(report.findings_by_object_type.values()) == report.finding_count
