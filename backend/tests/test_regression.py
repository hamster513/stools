"""Регрессия на настоящей выгрузке.

Пропускается, если STOOLS_FIXTURE_ZIP не задана — выгрузка содержит
инвентарь внутренней инфраструктуры и в репозиторий не попадает.

Эталонные числа тоже выведены из этой выгрузки, поэтому лежат не в
репозитории, а рядом с самим архивом: `<путь к архиву>.numbers.json`
(например `knowledgebase.zip.numbers.json`). Без этого файла проверка
чисел пропускается, остальные проверки работают.
"""
from collections import Counter
from pathlib import Path

import pytest

from kbaudit.analyzers.fields import is_builtin_account
from kbaudit.analyzers.scope import readers_of
from kbaudit.profile import load_profile
from kbaudit.report import run_audit

#: Профиль эталонной инсталляции: роли списков, которые подтвердил человек.
#: Схема именования в нём намеренно не задана — проверяем, что инструмент
#: находит её сам, без знания о том, кто писал правила.
REFERENCE_PROFILE = Path(__file__).parent / "fixtures" / "reference_profile.yaml"


@pytest.fixture(scope="module")
def report(reference_zip: Path):  # type: ignore[no-untyped-def]
    return run_audit(reference_zip, load_profile(REFERENCE_PROFILE))


def test_structural_numbers(report, reference_numbers) -> None:  # type: ignore[no-untyped-def]
    actual = {metric: getattr(report, metric) for metric in reference_numbers}
    assert actual == reference_numbers


def test_all_rules_are_local(report) -> None:  # type: ignore[no-untyped-def]
    assert report.origins == {"Local": 187}


def test_findings_by_kind(report) -> None:  # type: ignore[no-untyped-def]
    assert report.findings_by_kind == {1: 488, 2: 371, 3: 33, 4: 20, 5: 181}


def test_findings_by_polarity(report) -> None:  # type: ignore[no-untyped-def]
    assert report.findings_by_polarity == {"negation": 140, "assertion": 953}


def test_findings_by_object_type(report) -> None:  # type: ignore[no-untyped-def]
    assert report.findings_by_object_type == {
        "correlation": 1059,
        "filter": 26,
        "enrichment": 8,
    }


def test_every_split_sums_to_total(report) -> None:  # type: ignore[no-untyped-def]
    total = report.finding_count
    assert sum(report.findings_by_kind.values()) == total
    assert sum(report.findings_by_polarity.values()) == total
    assert sum(report.findings_by_object_type.values()) == total


def test_class_one_matches_in_table_count(report) -> None:  # type: ignore[no-untyped-def]
    """report.findings_by_kind[1] == report.in_table_count тавтологичен:
    classify() возвращает kind=1 ровно и только когда in_table истинно —
    первой веткой, до всех остальных классов (kbaudit/analyzers/hardcode.py).
    Такое равенство гарантировано конструкцией и не может упасть.

    Настоящая защита — обратное утверждение: ни у одной находки класса,
    отличного от 1, не должно быть in_table = true. Оно ломается, если
    порядок классов в classify() когда-нибудь поменяют (например, если
    класс 2 начнёт проверяться раньше in_table)."""
    assert all(f.in_table is False for f in report.findings if f.kind != 1)


def test_every_class_one_finding_resolves_to_a_table(report) -> None:  # type: ignore[no-untyped-def]
    """Находка класса 1 без имени списка бесполезна: непонятно, что править."""
    unresolved = [f.field for f in report.findings if f.kind == 1 and not f.table_name]
    assert unresolved == []
    assert report.divergence_count == 488


def test_values_living_in_several_lists_are_visible(report) -> None:  # type: ignore[no-untyped-def]
    """234 значения лежат больше чем в одном списке — сам по себе плохой знак."""
    multi = [d for d in report.divergences if "," in d.table_name]
    assert len(multi) == 234


def test_user_authentications_is_absent_from_defaults(report) -> None:  # type: ignore[no-untyped-def]
    """72 правила читают список, содержимого которого в выгрузке нет вовсе.
    Инструмент обязан показывать это, а не молчать."""
    status = {s.name: s for s in report.table_status}
    auth = status["DEMO_User_Authentications"]
    assert auth.exists is False
    assert auth.dependant_count == 72


def test_critical_hosts_list_is_tiny(report) -> None:  # type: ignore[no-untyped-def]
    """60 правил ограничены списком из семи значений."""
    status = {s.name: s for s in report.table_status}
    critical = status["DEMO_Critical_Hosts_by_Rule"]
    assert critical.exists is True
    assert critical.value_count == 7
    assert critical.dependant_count == 60


def test_no_findings_on_builtin_accounts(report) -> None:  # type: ignore[no-untyped-def]
    offenders = [f.field for f in report.findings if is_builtin_account(f.value)]
    assert offenders == []


def test_content_authors_are_visible(report) -> None:  # type: ignore[no-untyped-def]
    """Схема, выведенная из данных, показывает то, чего вендорская
    регулярка не показывала вовсе: в базе знаний четыре автора контента,
    а не один. После ухода вендора это первое, что нужно знать."""
    authors = Counter(r.code.author for r in report.rules if r.code)
    assert dict(authors) == {"DEMO": 172, "acme": 9, "SOC": 5, "IOC": 1}


def test_category_breakdown_within_main_author(report) -> None:  # type: ignore[no-untyped-def]
    """Пересортировка правил между категориями не должна проходить молча:
    сумма её не поймает, поэтому проверяется всё распределение."""
    categories = Counter(
        r.code.category for r in report.rules if r.code and r.code.author == "DEMO"
    )
    assert dict(categories) == {
        "HC": 72,
        "AC": 34,
        "NAA": 30,
        "MNA": 12,
        "MI": 9,
        "PV": 7,
        "NSA": 6,
        "Anomaly": 2,
    }
    assert sum(categories.values()) == 172

def test_user_authentications_has_seventy_two_readers(report) -> None:  # type: ignore[no-untyped-def]
    assert len(readers_of(report.rules, "DEMO_User_Authentications")) == 72


def test_every_rule_gets_a_code(report) -> None:  # type: ignore[no-untyped-def]
    """Прежняя вендорская регулярка оставляла 16 правил без кода одним
    ведром. Схема, выведенная из данных, разбирает все 187 — включая
    правила других авторов и те, чьи имена не влезали в шаблон вендора."""
    with_code = sum(1 for r in report.rules if r.code)
    assert with_code == report.rule_count == 187
    assert report.rules_without_code == 0

def test_unresolved_reference_is_visible(report) -> None:  # type: ignore[no-untyped-def]
    """Ровно одна нерезолвящаяся ссылка на correlation_name во всей выгрузке:
    `DEMO_HC_002_035_Possible_Themebleed_exploitation` ссылается на
    `subrule_egress_system`, которого нет среди имён правил выгрузки.

    Это не дефект парсера и не повод «дорезолвить» ссылку — правило-цель
    просто отсутствует в этой выгрузке (опечатка в теле либо неполная
    выгрузка, см. докстроку `unresolved_refs` в
    kbaudit/analyzers/dependencies.py). Инструмент обязан показать
    висящую ссылку как есть, а не подставить ближайшее совпадение и не
    потерять её молча — на этом стоит весь `unresolved` в `AuditReport`."""
    assert report.unresolved == {
        "DEMO_HC_002_035_Possible_Themebleed_exploitation": ["subrule_egress_system"],
    }


def test_default_account_usage_fork_is_detected(report) -> None:  # type: ignore[no-untyped-def]
    names = {(p.rule_a, p.rule_b) for p in report.clones}
    pair = (
        "DEMO_AC_020_004_Default_Account_Usage",
        "DEMO_AC_020_004_Default_Account_Usage_sidorov",
    )
    assert pair in names


def test_fork_findings_counts(report) -> None:  # type: ignore[no-untyped-def]
    """119 и 60, а не 118 и 59.

    Изначальный эталон (118/59) был измерен прототипом до правки, снявшей
    обязательную точку в имени поля и сделавшей достижимыми для сканера
    хардкода поля вида `datafield1`/`datafield2` (без точки, не только
    `namespace.field`) — см. константу `_FIELD` в
    kbaudit/analyzers/hardcode.py (там же докстрок-комментарий над ней
    объясняет, зачем точка необязательна). После этой правки в каждом из двух форков
    добавилось ровно по одной находке класса 1 на поле `datafield2` —
    118 + 1 = 119, 59 + 1 = 60. Остальные регрессионные числа (включая
    общий `finding_count`) уже учитывали эту правку и не менялись — разъехалась
    только эта пара, потому что её эталон не обновили вместе с остальными.
    Если однажды опять получится 118/59 — скорее всего, регресс в разборе
    полей без точки, а не «эталон снова устарел».
    """
    counts = {
        name: sum(1 for f in report.findings if f.object_name == name)
        for name in (
            "DEMO_AC_020_004_Default_Account_Usage",
            "DEMO_AC_020_004_Default_Account_Usage_sidorov",
        )
    }
    assert counts == {
        "DEMO_AC_020_004_Default_Account_Usage": 119,
        "DEMO_AC_020_004_Default_Account_Usage_sidorov": 60,
    }
