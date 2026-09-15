from kbaudit.analyzers.scope import critical_table_status, readers_of, scoped_by
from kbaudit.models import Rule, TableList

CRITICAL = "DEMO_Critical_Hosts_by_Rule"
AUTH = "DEMO_User_Authentications"


def rules() -> list[Rule]:
    return [
        Rule(uuid="1", name="Scoped", table_reads=[CRITICAL, AUTH]),
        Rule(uuid="2", name="AuthOnly", table_reads=[AUTH]),
        Rule(uuid="3", name="Wide", table_reads=[]),
    ]


def test_scoped_rules_are_listed() -> None:
    assert scoped_by(rules(), CRITICAL) == ["Scoped"]


def test_readers_are_listed() -> None:
    assert readers_of(rules(), AUTH) == ["AuthOnly", "Scoped"]


def test_status_reports_dependants_and_emptiness() -> None:
    lists = [TableList(name=CRITICAL, value_count=0), TableList(name=AUTH, value_count=5)]
    status = {s.name: s for s in critical_table_status(rules(), lists, [CRITICAL, AUTH])}
    assert status[CRITICAL].dependant_count == 1
    assert status[CRITICAL].is_empty is True
    assert status[AUTH].dependant_count == 2
    assert status[AUTH].is_empty is False


def test_missing_table_is_reported_as_absent() -> None:
    status = {s.name: s for s in critical_table_status(rules(), [], [CRITICAL])}
    assert status[CRITICAL].exists is False
    assert status[CRITICAL].is_empty is True
