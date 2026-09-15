from kbaudit.catalog import build_catalog
from kbaudit.models import Rule
from kbaudit.naming import NameScheme, detect_name_schemes


def rules() -> list[Rule]:
    return [
        Rule(uuid="1", name="ACME_HC_002_029_Impacket", msgids=["4688"], table_reads=["T1"]),
        Rule(uuid="2", name="ACME_HC_002_030_Psexec", msgids=["4697"], table_reads=["T2"]),
        Rule(uuid="3", name="ACME_AC_020_004_Default_Account"),
        Rule(uuid="4", name="ACME_AC_020_006_Local_Admin"),
        Rule(uuid="5", name="inhouse_vpn_detect_leak"),
        Rule(uuid="6", name="inhouse_vpn_detect_reconnect"),
    ]


def scheme() -> NameScheme:
    return detect_name_schemes([r.name for r in rules()])[0]


def test_groups_come_from_detected_scheme_not_from_vendor_pattern() -> None:
    """Схема выводится из данных: имена намеренно не вендорские."""
    groups = {g.label: g for g in build_catalog(rules(), scheme())}
    assert set(groups) == {"ACME/HC/002", "ACME/AC/020", "inhouse/vpn/detect"}


def test_group_aggregates_rules_msgids_and_tables() -> None:
    groups = {g.label: g for g in build_catalog(rules(), scheme())}
    hc = groups["ACME/HC/002"]
    assert hc.rule_count == 2
    assert hc.msgids == ["4688", "4697"]
    assert hc.tables == ["T1", "T2"]


def test_without_scheme_every_rule_is_its_own_group() -> None:
    """Отсутствие структуры в именах — состояние, а не отказ работать."""
    groups = build_catalog(rules(), None)
    assert len(groups) == len(rules())
    assert all(g.unmatched for g in groups)


def test_rule_not_matching_scheme_becomes_its_own_group() -> None:
    """Прежде такие правила сваливались в общее ведро «без кода», где
    у шестнадцати правил разных авторов не было ничего общего."""
    odd = [*rules(), Rule(uuid="7", name="standalone")]
    groups = {g.label: g for g in build_catalog(odd, scheme())}
    assert groups["standalone"].rule_count == 1
    assert groups["standalone"].unmatched is True
