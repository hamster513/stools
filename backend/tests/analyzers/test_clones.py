from kbaudit.analyzers.clones import find_clones, signature
from kbaudit.models import Rule


def test_signature_unions_msgids_fields_and_filters() -> None:
    rule = Rule(
        uuid="u1",
        name="R",
        msgids=["4688"],
        taxonomy_fields=["src.ip"],
        filter_refs=["F"],
    )
    assert signature(rule) == frozenset({"msgid:4688", "field:src.ip", "filter:F"})


def test_identical_rules_are_clones() -> None:
    a = Rule(uuid="a", name="A", msgids=["1", "2", "3", "4"])
    b = Rule(uuid="b", name="B", msgids=["1", "2", "3", "4"])
    pairs = find_clones([a, b])
    assert len(pairs) == 1
    assert pairs[0].similarity == 1.0


def test_fork_above_threshold_is_found() -> None:
    a = Rule(uuid="a", name="A", msgids=["1", "2", "3", "4", "5"])
    b = Rule(uuid="b", name="B", msgids=["1", "2", "3", "4", "6"])
    pairs = find_clones([a, b], threshold=0.6)
    assert len(pairs) == 1
    assert 0.66 < pairs[0].similarity < 0.67


def test_different_rules_are_not_clones() -> None:
    a = Rule(uuid="a", name="A", msgids=["1", "2"])
    b = Rule(uuid="b", name="B", msgids=["8", "9"])
    assert find_clones([a, b]) == []


def test_empty_signatures_never_pair() -> None:
    a = Rule(uuid="a", name="A")
    b = Rule(uuid="b", name="B")
    assert find_clones([a, b]) == []


def test_pairs_are_reported_once_and_sorted() -> None:
    rules = [
        Rule(uuid=str(i), name=name, msgids=["1", "2", "3"])
        for i, name in enumerate(["C", "A", "B"])
    ]
    pairs = find_clones(rules)
    assert len(pairs) == 3
    assert [(p.rule_a, p.rule_b) for p in pairs] == [("A", "B"), ("A", "C"), ("B", "C")]


def test_pair_with_shared_rare_token_is_a_clone() -> None:
    """A и B делят широко распространённое поле (как и куча "шумных" правил
    вокруг), но вдобавок редкий msgid, который встречается только у них двоих.
    Документная частота считается по всему списку правил — шум её не портит."""
    noise = [
        Rule(uuid=f"n{i}", name=f"Noise{i}", taxonomy_fields=["src.ip"])
        for i in range(6)
    ]
    a = Rule(uuid="a", name="A", taxonomy_fields=["src.ip"], msgids=["9001"])
    b = Rule(uuid="b", name="B", taxonomy_fields=["src.ip"], msgids=["9001"])
    pairs = find_clones([a, b, *noise], threshold=0.5)
    assert [(p.rule_a, p.rule_b) for p in pairs] == [("A", "B")]


def test_pair_with_only_widely_shared_tokens_is_not_a_clone_at_full_similarity() -> None:
    """Пять правил реагируют на одно и то же событие (общий msgid) — по
    смыслу это разные детекты на общем словаре, а не форки друг друга.
    Похожесть 1.0 у каждой пары, но общий токен не редкий — клоном не считается."""
    widely_shared = [
        Rule(uuid=f"w{i}", name=f"Widely{i}", msgids=["4688"]) for i in range(5)
    ]
    assert find_clones(widely_shared, threshold=1.0) == []


def test_degenerate_single_common_filter_ref_is_filtered_out() -> None:
    """Вырожденный случай из выгрузки: несколько правил ссылаются на один и
    тот же общий фильтр и больше ничего не разделяют — сигнатура из одного
    широко распространённого токена не делает их клонами."""
    rules = [
        Rule(uuid=f"f{i}", name=f"Filtered{i}", filter_refs=["NotFromCorrelator"])
        for i in range(5)
    ]
    assert find_clones(rules) == []
