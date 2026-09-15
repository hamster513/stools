"""Перевод техник: проверяется без сети и без весов.

Главное свойство здесь не форма промпта, а то, что молчаливая потеря
техники невозможна. Разметку человек подтверждает, и ошибка в ней
всплывёт; перевод не подтверждает никто — неверный русский текст
выглядит как верный и живёт годами.
"""
import json
from typing import Any

import pytest

from kbaudit.attack.translate import (
    TranslationError,
    TranslationRequest,
    build_prompt,
    response_schema,
    translate_batch,
)


def items() -> list[TranslationRequest]:
    return [
        TranslationRequest(technique_id="T1059", name="Command and Scripting Interpreter",
                           description="Adversaries may abuse command interpreters."),
        TranslationRequest(technique_id="T1047", name="Windows Management Instrumentation"),
    ]


class Fixed:
    def __init__(self, response: str) -> None:
        self.response = response
        self.seen_prompt: str | None = None

    def complete(self, prompt: str, schema: dict[str, Any]) -> str:
        self.seen_prompt = prompt
        return self.response


def answer(pairs: list[tuple[str, str]]) -> str:
    return json.dumps(
        {
            "techniques": [
                {"technique_id": tid, "name_ru": ru, "description_ru": "описание"}
                for tid, ru in pairs
            ]
        },
        ensure_ascii=False,
    )


def test_schema_pins_the_exact_set_of_techniques() -> None:
    """Обе границы длины заданы: иначе модель молча вернёт меньше,
    и часть техник останется без перевода незаметно."""
    schema = response_schema(items())
    array = schema["properties"]["techniques"]
    assert array["minItems"] == 2
    assert array["maxItems"] == 2
    assert array["items"]["properties"]["technique_id"]["enum"] == ["T1059", "T1047"]


def test_glossary_keeps_terminology_consistent() -> None:
    """Без глоссария модель переведёт Defense Evasion как «уклонение
    от защиты» там, где в матрице уже написано «обход защиты», и в одном
    интерфейсе окажутся два названия одного."""
    text = build_prompt(items(), {"Defense Evasion": "обход защиты"})
    assert "Defense Evasion — обход защиты" in text


def test_product_names_are_asked_to_stay_english() -> None:
    text = build_prompt(items(), {})
    assert "PowerShell" in text and "Regsvr32" in text


def test_translation_is_parsed() -> None:
    got = translate_batch(
        items(), Fixed(answer([("T1059", "Интерпретаторы команд"), ("T1047", "WMI")]))
    )
    assert [t.technique_id for t in got] == ["T1059", "T1047"]
    assert got[0].name_ru == "Интерпретаторы команд"


def test_partial_answer_is_rejected_whole() -> None:
    """Частично разобранная пачка тихо оставила бы часть техник без
    перевода, и понять это было бы уже неоткуда."""
    with pytest.raises(TranslationError, match="не перевела 1 техник"):
        translate_batch(items(), Fixed(answer([("T1059", "Интерпретаторы команд")])))


def test_foreign_technique_is_discarded_and_batch_fails() -> None:
    """Схема уже не даёт назвать чужую технику, но другой провайдер может
    её не поддержать — тогда доверие обернётся переводом не того."""
    with pytest.raises(TranslationError):
        translate_batch(
            items(), Fixed(answer([("T1059", "Интерпретаторы"), ("T9999", "Выдумка")]))
        )


def test_empty_name_is_not_a_translation() -> None:
    with pytest.raises(TranslationError):
        translate_batch(items(), Fixed(answer([("T1059", "  "), ("T1047", "WMI")])))


def test_broken_json_is_an_error_not_an_empty_result() -> None:
    with pytest.raises(TranslationError, match="не разбирается"):
        translate_batch(items(), Fixed("не json"))


def test_nothing_to_translate_needs_no_model() -> None:
    class Explodes:
        def complete(self, prompt: str, schema: dict[str, Any]) -> str:
            raise AssertionError("обращение к модели при пустом списке")

    assert translate_batch([], Explodes()) == []
