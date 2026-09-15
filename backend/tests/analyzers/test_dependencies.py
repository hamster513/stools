from kbaudit.analyzers.dependencies import build_edges, inherited_msgids, unresolved_refs
from kbaudit.models import Rule


def rules() -> list[Rule]:
    return [
        Rule(uuid="u1", name="Parent", msgids=["4688"]),
        Rule(uuid="u2", name="Child", corr_refs=["Parent"]),
        Rule(uuid="u3", name="Grandchild", corr_refs=["Child"], msgids=["1"]),
        Rule(uuid="u4", name="Orphan", corr_refs=["NoSuchRule"]),
    ]


def test_edges_are_built_from_existing_rules_only() -> None:
    edges = build_edges(rules())
    assert {(e.parent, e.child) for e in edges} == {
        ("Parent", "Child"),
        ("Child", "Grandchild"),
    }


def test_unresolved_references_are_reported_not_dropped_silently() -> None:
    assert unresolved_refs(rules()) == {"Orphan": ["NoSuchRule"]}


def test_msgids_are_inherited_down_the_chain() -> None:
    got = inherited_msgids(rules(), build_edges(rules()))
    assert got["Child"] == {"4688"}
    assert got["Grandchild"] == {"1", "4688"}


def test_rule_without_parents_keeps_its_own() -> None:
    got = inherited_msgids(rules(), build_edges(rules()))
    assert got["Parent"] == {"4688"}


def test_cycle_does_not_hang() -> None:
    cyclic = [
        Rule(uuid="a", name="A", corr_refs=["B"], msgids=["1"]),
        Rule(uuid="b", name="B", corr_refs=["A"], msgids=["2"]),
    ]
    got = inherited_msgids(cyclic, build_edges(cyclic))
    assert got["A"] == {"1", "2"}
    assert got["B"] == {"1", "2"}


def test_lowercased_reference_resolves_to_the_real_rule_name() -> None:
    """lower(correlation_name) в теле правила кладёт в corr_refs литерал в
    нижнем регистре — ребро должно указывать на настоящее имя правила."""
    rules_ = [
        Rule(uuid="p", name="DEMO_MNA_005_004_Subrule_Coerce_Auth"),
        Rule(
            uuid="c",
            name="DEMO_MNA_005_004_Possible_Coerce_Authentication_attack",
            corr_refs=["demo_mna_005_004_subrule_coerce_auth"],
        ),
    ]
    edges = build_edges(rules_)
    assert [(e.parent, e.child) for e in edges] == [
        (
            "DEMO_MNA_005_004_Subrule_Coerce_Auth",
            "DEMO_MNA_005_004_Possible_Coerce_Authentication_attack",
        )
    ]
    assert unresolved_refs(rules_) == {}


def test_unresolvable_lowercased_reference_stays_unresolved() -> None:
    """Ссылка вида "subrule_egress_system" без префикса не совпадает ни с
    одним именем даже без учёта регистра — рёбром не становится и остаётся
    в unresolved_refs как записана в теле."""
    rules_ = [
        Rule(uuid="p", name="DEMO_MNA_005_004_Subrule_Egress_System"),
        Rule(
            uuid="c",
            name="DEMO_HC_002_035_Possible_Themebleed_exploitation",
            corr_refs=["subrule_egress_system"],
        ),
    ]
    assert build_edges(rules_) == []
    assert unresolved_refs(rules_) == {
        "DEMO_HC_002_035_Possible_Themebleed_exploitation": ["subrule_egress_system"]
    }


def test_case_collision_is_not_silently_merged() -> None:
    """Если два правила различаются только регистром, ссылка, не совпадающая
    ни с одним из них посимвольно, неоднозначна — она не должна молча
    прилипнуть к одному из вариантов."""
    rules_ = [
        Rule(uuid="a", name="Foo"),
        Rule(uuid="b", name="FOO"),
        Rule(uuid="c", name="Child", corr_refs=["foo"]),
    ]
    assert build_edges(rules_) == []
    assert unresolved_refs(rules_) == {"Child": ["foo"]}


def test_case_collision_does_not_block_exact_match() -> None:
    """Точное совпадение регистра однозначно даже при коллизии где-то ещё
    в выгрузке."""
    rules_ = [
        Rule(uuid="a", name="Foo"),
        Rule(uuid="b", name="FOO"),
        Rule(uuid="c", name="Child", corr_refs=["FOO"]),
    ]
    edges = build_edges(rules_)
    assert [(e.parent, e.child) for e in edges] == [("FOO", "Child")]
    assert unresolved_refs(rules_) == {}
