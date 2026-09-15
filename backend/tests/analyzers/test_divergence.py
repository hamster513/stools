from kbaudit.analyzers.divergence import find_divergences
from kbaudit.analyzers.hardcode import analyze_hardcode
from kbaudit.models import KbObject, ObjectType, Rule

BODY = KbObject(
    uuid="u1",
    object_type=ObjectType.CORRELATION,
    name="R1",
    body_text='src.host == "srv01"',
    body_ext=".co",
)


def test_finding_learns_which_table_holds_the_value() -> None:
    findings = analyze_hardcode(
        [BODY],
        {"srv01"},
        values_by_table={"DEMO_Critical_Hosts_by_Rule": {"srv01"}},
    )
    assert findings[0].kind == 1
    assert findings[0].table_name == "DEMO_Critical_Hosts_by_Rule"


def test_table_name_stays_empty_when_mapping_not_given() -> None:
    findings = analyze_hardcode([BODY], {"srv01"})
    assert findings[0].kind == 1
    assert findings[0].table_name is None


def test_value_in_two_lists_reports_both_joined() -> None:
    findings = analyze_hardcode(
        [BODY], {"srv01"}, values_by_table={"A": {"srv01"}, "B": {"srv01"}}
    )
    assert findings[0].table_name == "A, B"


def test_divergence_lists_rules_that_break_if_value_removed() -> None:
    findings = analyze_hardcode(
        [BODY], {"srv01"}, values_by_table={"DEMO_Hosts": {"srv01"}}
    )
    rules = [
        Rule(uuid="u1", name="R1", table_reads=["DEMO_Hosts"]),
        Rule(uuid="u2", name="R2", table_reads=["DEMO_Hosts"]),
        Rule(uuid="u3", name="R3", table_reads=["Other"]),
    ]
    rows = find_divergences(findings, rules)
    assert len(rows) == 1
    assert rows[0].table_name == "DEMO_Hosts"
    assert rows[0].affected_rules == ["R1", "R2"]
    assert rows[0].hardcoded_in == "R1"


def test_only_class_one_produces_divergences() -> None:
    findings = analyze_hardcode(
        [
            KbObject(
                uuid="u1",
                object_type=ObjectType.CORRELATION,
                name="R1",
                body_text='src.ip == "10.0.0.1"',
                body_ext=".co",
            )
        ],
        set(),
    )
    assert findings[0].kind == 2
    assert find_divergences(findings, []) == []
