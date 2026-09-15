"""Выжимка по группе: что уходит наружу и что не должно уйти никогда.

Значения в этих тестах выдуманы и намеренно не взяты из настоящей выгрузки:
тест, который проверяет сокрытие данных, сам не должен их содержать.
"""
import pytest

from kbaudit.attack.payload import (
    GroupPayload,
    LeakGuardError,
    assert_no_leak,
    build_payload,
    classify_literal,
)
from kbaudit.models import KbObject, ObjectType, Rule

BLOCKLIST = frozenset({"kata", "web_api", "srv-fin-01", "petrov"})


def body(text: str) -> KbObject:
    return KbObject(
        uuid="u1",
        object_type=ObjectType.CORRELATION,
        name="ACME_HC_002_001_Test",
        body_text=text,
        body_ext=".co",
    )


def test_technical_tokens_are_sendable() -> None:
    """Платформенная лексика описывает не инсталляцию, а Windows."""
    for value in ("cmd.exe", "rundll32.dll", "4688", "HKLM\\Software\\Run", "GNRL_EV_ALERT"):
        assert classify_literal(value, BLOCKLIST) == "send", value


@pytest.mark.parametrize(
    "value",
    [
        "10.72.1.15",
        "10.72.0.0/16",
        "dc01.corp.internal",
        "S-1-5-21-1234-5678-9012-500",
        "INC0043211",
    ],
)
def test_environmental_shapes_are_dropped(value: str) -> None:
    assert classify_literal(value, BLOCKLIST) == "drop"


def test_blocklist_catches_what_no_regex_would() -> None:
    """`kata` и `web_api` выглядят обычными словами, но лежат в whitelist'ах
    выгрузки и потому чувствительны. Блоклист строится из самих данных
    именно ради таких случаев."""
    assert classify_literal("kata", BLOCKLIST) == "drop"
    assert classify_literal("web_api", BLOCKLIST) == "drop"


def test_unknown_values_go_to_review_not_out() -> None:
    """Незнакомое не отправляется молча: `svcctl` не подходит ни под один
    шаблон безопасного вида, но именно он несёт сигнал о технике —
    решение принимает человек, один раз."""
    assert classify_literal("svcctl", BLOCKLIST) == "review"
    assert classify_literal("atsvc", BLOCKLIST) == "review"


def test_approved_values_reach_the_payload() -> None:
    rules = [Rule(uuid="u1", name="ACME_HC_002_001_Test")]
    bodies = [body('object.name == "svcctl"')]
    payload, _ = build_payload(
        "ACME/HC/002", rules, bodies, BLOCKLIST, approved=frozenset({"svcctl"})
    )
    assert "svcctl" in payload.literals, "одобренное человеком должно доходить"


def test_unapproved_values_are_listed_for_review() -> None:
    rules = [Rule(uuid="u1", name="ACME_HC_002_001_Test")]
    bodies = [body('object.name == "atsvc"')]
    payload, review = build_payload("ACME/HC/002", rules, bodies, BLOCKLIST)
    assert "atsvc" not in payload.literals
    assert review == ["atsvc"]


def test_title_with_environmental_value_is_dropped() -> None:
    """Имя организации утекает в том числе через заголовки правил,
    поэтому они проходят ту же проверку, что и литералы."""
    rules = [
        Rule(
            uuid="u1",
            name="ACME_HC_002_001_Test",
            title_ru="Подозрительный вход на dc01.corp.internal",
        )
    ]
    payload, _ = build_payload("ACME/HC/002", rules, [], BLOCKLIST)
    assert payload.titles == []


def test_leak_guard_blocks_address() -> None:
    rules = [Rule(uuid="u1", name="ACME_HC_002_001_Test", title_ru="Обычный заголовок")]
    payload, _ = build_payload("ACME/HC/002", rules, [], BLOCKLIST)
    payload.literals.append("10.72.1.15")
    with pytest.raises(LeakGuardError, match="адрес"):
        assert_no_leak(payload, BLOCKLIST)


def test_leak_guard_blocks_blocklisted_value() -> None:
    rules = [Rule(uuid="u1", name="ACME_HC_002_001_Test")]
    payload, _ = build_payload("ACME/HC/002", rules, [], BLOCKLIST)
    payload.literals.append("srv-fin-01")
    with pytest.raises(LeakGuardError, match="табличного списка"):
        assert_no_leak(payload, BLOCKLIST)


def test_leak_guard_passes_clean_payload() -> None:
    rules = [
        Rule(
            uuid="u1",
            name="ACME_HC_002_001_Test",
            title_ru="Запуск системной утилиты из необычного каталога",
            msgids=["4688", "4697"],
            taxonomy_fields=["object.process.name"],
            filter_refs=["NotFromCorrelator"],
        )
    ]
    payload, _ = build_payload("ACME/HC/002", rules, [], BLOCKLIST)
    assert_no_leak(payload, BLOCKLIST)
    assert payload.rule_count == 1
    assert "4688" in payload.event_ids


def test_leak_guard_blocks_rather_than_sanitises() -> None:
    """Найденная утечка останавливает отправку, а не вычищается.

    Если запрещённое дошло до этой проверки, сломан сборщик выжимки, и
    правильная реакция — остановиться, а не замести следы и поехать дальше.
    """
    rules = [Rule(uuid="u1", name="ACME_HC_002_001_Test")]
    payload, _ = build_payload("ACME/HC/002", rules, [], BLOCKLIST)
    payload.literals.append("dc01.corp.internal")
    before = list(payload.literals)
    with pytest.raises(LeakGuardError):
        assert_no_leak(payload, BLOCKLIST)
    assert payload.literals == before, "выжимка не должна молча меняться"


def test_literals_come_from_rule_bodies_not_from_event_ids() -> None:
    """Сигнал о технике несут литералы тела: `svcctl` отличает запуск через
    диспетчер служб от запуска через планировщик, а код события — нет."""
    rules = [Rule(uuid="u1", name="ACME_HC_002_001_Test", msgids=["4688"])]
    bodies = [body('object.name == "svcctl" and object.process.name == "cmd.exe"')]
    payload, _ = build_payload(
        "ACME/HC/002", rules, bodies, BLOCKLIST, approved=frozenset({"svcctl"})
    )
    assert "svcctl" in payload.literals
    assert "cmd.exe" in payload.literals
    assert "4688" not in payload.literals, "коды событий перечислены отдельно"
    assert payload.event_ids == ["4688"]


def test_environmental_literal_in_body_never_reaches_payload() -> None:
    rules = [Rule(uuid="u1", name="ACME_HC_002_001_Test")]
    bodies = [body('event_src.host == "dc01.corp.internal" and src.ip == "10.72.1.15"')]
    payload, review = build_payload("ACME/HC/002", rules, bodies, BLOCKLIST)
    assert payload.literals == []
    assert "dc01.corp.internal" not in review, "средовое не предлагается даже на просмотр"
    assert "10.72.1.15" not in review
    assert_no_leak(payload, BLOCKLIST)


def test_rule_description_reaches_the_model() -> None:
    """Описание из локализации говорит о технике прямее заголовка:
    «перехватил NTLM-хеш в результате принудительной аутентификации»
    против «Обнаружена возможная атака type_id=JC-MNA-005-004»."""
    rule = Rule(
        uuid="u1",
        name="DEMO_MNA_005_004_Coerce",
        title_ru="Обнаружена возможная атака type_id=JC-MNA-005-004",
        descriptions_ru=[
            (
                "Пользователь {subject.account.name} перехватил NTLM-хеш учётной "
                "записи компьютера в результате принудительной аутентификации"
            )
        ],
    )
    payload, _ = build_payload("DEMO/MNA/005", [rule], [], frozenset())
    assert payload.descriptions
    assert "NTLM-хеш" in payload.embedding_text
    assert "принудительной аутентификации" in payload.embedding_text


def test_description_passes_the_same_leak_check_as_the_title() -> None:
    """Свободный текст опасен одинаково, откуда бы он ни взялся: имя
    организации и внутренние адреса утекают и через описание."""
    rule = Rule(
        uuid="u1",
        name="DEMO_HC_001_Rule",
        title_ru="Обычный заголовок",
        descriptions_ru=["Обнаружено обращение к 10.20.30.40 с узла srv-fin-01.corp.local"],
    )
    payload, _ = build_payload("DEMO/HC/001", [rule], [], frozenset())
    assert payload.descriptions == [], "описание с адресом и внутренним именем не отправляется"
    assert "10.20.30.40" not in payload.embedding_text


def test_leak_guard_also_covers_descriptions() -> None:
    """Проверка перед отправкой смотрит весь текст выжимки, а не только
    заголовки: иначе новый источник текста обошёл бы защиту."""
    payload = GroupPayload(
        group="DEMO/HC/001",
        rule_count=1,
        descriptions=["Обращение к узлу srv99.corp.internal"],
    )
    with pytest.raises(LeakGuardError):
        assert_no_leak(payload, frozenset())
