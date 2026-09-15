"""Выбор техники моделью: проверяется без сети и без весов."""
import json
from typing import Any

import pytest

from kbaudit.attack.bundle import Technique
from kbaudit.attack.candidates import Candidate
from kbaudit.attack.payload import GroupPayload
from kbaudit.attack.prompt import build_prompt, response_schema
from kbaudit.attack.provider import (
    ModelError,
    OllamaCompletion,
    OllamaSettings,
    suggest_techniques,
)


def candidates() -> list[Candidate]:
    return [
        Candidate(technique_id="T1569", name="System Services", similarity=0.8),
        Candidate(technique_id="T1053", name="Scheduled Task/Job", similarity=0.7),
    ]


def techniques() -> dict[str, Technique]:
    return {
        "T1569": Technique(
            technique_id="T1569",
            name="System Services",
            name_ru="Запуск через системные службы",
            description_ru="Злоумышленник запускает код через диспетчер служб.",
        ),
        "T1053": Technique(technique_id="T1053", name="Scheduled Task/Job"),
    }


def payload() -> GroupPayload:
    return GroupPayload(
        group="ACME/HC/002",
        rule_count=3,
        titles=["Запуск через диспетчер служб"],
        event_ids=["4697"],
        literals=["svcctl"],
    )


class Fixed:
    """Заглушка модели: возвращает заранее заданный ответ."""

    def __init__(self, response: str) -> None:
        self.response = response
        self.seen_schema: dict[str, Any] | None = None
        self.seen_prompt: str | None = None

    def complete(self, prompt: str, schema: dict[str, Any]) -> str:
        self.seen_prompt = prompt
        self.seen_schema = schema
        return self.response


def test_schema_restricts_ids_to_offered_candidates() -> None:
    """Перечисление — то, что делает выдумывание невозможным,
    а не маловероятным."""
    schema = response_schema(candidates())
    enum = schema["properties"]["techniques"]["items"]["properties"]["technique_id"]["enum"]
    assert enum == ["T1569", "T1053"]


def test_schema_allows_several_techniques_per_group() -> None:
    """Impacket — это и службы, и планировщик, и WMI. Требование выбрать
    ровно одну заставляет отбрасывать верные ответы."""
    items = response_schema(candidates())["properties"]["techniques"]
    assert items["minItems"] == 1
    assert items["maxItems"] >= 2


def test_confidence_is_qualitative_not_numeric() -> None:
    """Число создаёт ложную точность: на живом прогоне одна модель выдала
    и 0.95, и 75 по схеме, объявлявшей просто number."""
    props = response_schema(candidates())["properties"]["techniques"]["items"]["properties"]
    assert props["confidence"]["enum"] == ["высокая", "средняя", "низкая"]
    assert props["confidence"]["type"] == "string"


def test_prompt_prefers_russian_descriptions() -> None:
    text = build_prompt(payload(), candidates(), techniques())
    assert "Запуск через системные службы" in text
    assert "диспетчер служб" in text


def test_prompt_falls_back_to_english_when_untranslated() -> None:
    text = build_prompt(payload(), candidates(), techniques())
    assert "Scheduled Task/Job" in text


def test_suggestion_is_parsed() -> None:
    model = Fixed(
        json.dumps(
            {
                "techniques": [
                    {"technique_id": "T1569", "confidence": "высокая", "evidence": "svcctl"}
                ]
            }
        )
    )
    got = suggest_techniques(payload(), candidates(), techniques(), model, model_name="m")
    assert [t.technique_id for t in got.techniques] == ["T1569"]
    assert got.candidates == ["T1569", "T1053"]
    assert got.model == "m"


def test_technique_outside_candidates_is_discarded() -> None:
    """Схема уже не даёт назвать чужую технику, но другой провайдер может
    её не поддержать — тогда молчаливое доверие обернётся выдуманным
    идентификатором в базе."""
    model = Fixed(
        json.dumps(
            {
                "techniques": [
                    {"technique_id": "T1003", "confidence": "высокая", "evidence": "выдумано"},
                    {"technique_id": "T1053", "confidence": "низкая", "evidence": "по существу"},
                ]
            }
        )
    )
    got = suggest_techniques(payload(), candidates(), techniques(), model)
    assert [t.technique_id for t in got.techniques] == ["T1053"]


def test_broken_json_is_an_error_not_an_empty_result() -> None:
    """Пустая разметка неотличима от «модель ничего не нашла» — а это
    разные вещи, и вторая не должна маскировать первую."""
    with pytest.raises(ModelError, match="не разбирается"):
        suggest_techniques(payload(), candidates(), techniques(), Fixed("не json"))


def test_unconfigured_provider_does_not_reach_the_network() -> None:
    """Без явно заданного адреса инструмент наружу не ходит."""
    provider = OllamaCompletion(OllamaSettings())
    assert provider._settings.configured is False
    with pytest.raises(ModelError, match="адрес модели не задан"):
        provider.complete("prompt", {})
