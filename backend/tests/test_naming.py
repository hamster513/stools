"""Определение схемы именования не должно знать ни одного вендора.

Все имена в этих тестах выдуманы и намеренно не похожи на имена
из эталонной выгрузки: если тест проходит только на них, значит
в коде осталось знание о конкретном авторе правил.
"""
from kbaudit.naming import apply_scheme, detect_name_schemes, group_key_of


def numbered(prefix: str, category: str, group: str, count: int) -> list[str]:
    return [f"{prefix}_{category}_{group}_{i:03d}_Detect_Something" for i in range(count)]


def corpus() -> list[str]:
    names = []
    for category, group, count in (
        ("AA", "001", 8),
        ("AA", "002", 7),
        ("BB", "010", 6),
        ("CC", "020", 5),
    ):
        names += numbered("ACME", category, group, count)
    return names


def test_detects_four_position_scheme() -> None:
    scheme = detect_name_schemes(corpus())[0]
    assert scheme.separator == "_"
    assert scheme.segments == ["author", "category", "group", "rule_id"]
    assert scheme.coverage == scheme.total == 26
    assert scheme.group_count == 4


def test_reports_cardinality_per_position() -> None:
    """Статистика — то, по чему человек проверяет предложение инструмента."""
    scheme = detect_name_schemes(corpus())[0]
    by_position = {s.position: s for s in scheme.stats}
    assert by_position[0].distinct == 1, "один автор"
    assert by_position[1].distinct == 3, "три категории"
    assert by_position[2].distinct == 4, "четыре группы"
    assert by_position[1].role == "category"


def test_shallow_scheme_gets_roles_from_the_right() -> None:
    """Роли назначаются справа налево: последняя позиция — номер правила."""
    names = [f"grp{i % 3}_{i:03d}_Text" for i in range(12)]
    scheme = detect_name_schemes(names)[0]
    assert scheme.segments == ["group", "rule_id"]


def test_no_structure_gives_no_scheme() -> None:
    """Имена без общей структуры — законное состояние, а не ошибка."""
    assert detect_name_schemes(["alpha", "beta", "gamma"]) == []


def test_all_unique_split_is_rejected() -> None:
    """Разбиение, где почти каждое правило — своя группа, каталогом не является."""
    names = [f"unique{i}_x{i}_y{i}_z{i}" for i in range(20)]
    assert detect_name_schemes(names) == []


def test_empty_corpus_is_not_an_error() -> None:
    assert detect_name_schemes([]) == []


def test_group_key_drops_the_rule_number() -> None:
    scheme = detect_name_schemes(corpus())[0]
    assert group_key_of("ACME_AA_001_000_Detect_Something", scheme) == ("ACME", "AA", "001")


def test_name_not_matching_scheme_has_no_group_key() -> None:
    scheme = detect_name_schemes(corpus())[0]
    assert group_key_of("standalone", scheme) is None


def test_apply_scheme_fills_named_positions() -> None:
    scheme = detect_name_schemes(corpus())[0]
    code = apply_scheme("ACME_BB_010_003_Detect_Something", scheme)
    assert code is not None
    assert (code.author, code.category, code.group, code.rule_id) == (
        "ACME",
        "BB",
        "010",
        "003",
    )


def test_apply_scheme_without_scheme_returns_nothing() -> None:
    assert apply_scheme("whatever", None) is None


def test_dash_separated_names_are_supported() -> None:
    """Разделитель тоже выводится из данных, а не предполагается."""
    names = [f"team-{c}-{i:03d}-rule-text" for c in ("x", "y") for i in range(6)]
    scheme = detect_name_schemes(names)[0]
    assert scheme.separator == "-"
