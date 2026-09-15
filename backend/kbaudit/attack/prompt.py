"""Промпт для выбора техники и схема ответа.

Модель не называет технику свободным текстом. Ей дают короткий список
отобранных кандидатов и схему, в которой `technique_id` — перечисление
ровно из этих кандидатов. Grammar-constrained вывод делает выдумывание
несуществующего идентификатора физически невозможным, а не маловероятным.

Побочный выигрыш: описания техник лежат в промпте, поэтому модель не
опирается на память. Версия ATT&CK берётся из вложенного бандла,
а не из весов, которые обучались неизвестно на какой.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from kbaudit.attack.bundle import Technique
from kbaudit.attack.candidates import Candidate
from kbaudit.attack.payload import GroupPayload

#: Уверенность качественная, а не числовая. Число здесь создаёт ложную
#: точность: на живом прогоне одна и та же модель выдавала `0.95` и `75`
#: по схеме, объявлявшей просто `number`, — то есть трактовала шкалу как
#: хотела. Три градации честнее и не притворяются измерением.
CONFIDENCE_LEVELS = ("высокая", "средняя", "низкая")

#: Группа правил законно соответствует нескольким техникам: Impacket —
#: это и запуск через службы, и планировщик задач, и WMI. Требование
#: выбрать ровно одну заставляет модель отбрасывать верные ответы,
#: и матрица покрытия систематически недосчитывает.
MAX_TECHNIQUES = 3


class TechniqueSuggestion(BaseModel):
    """Предложение модели. Именно предложение, а не факт."""

    technique_id: str
    confidence: str
    evidence: str


class GroupSuggestion(BaseModel):
    group: str
    techniques: list[TechniqueSuggestion] = Field(default_factory=list)
    #: Что именно видела модель. Без этого разобраться в спорной разметке
    #: через полгода невозможно: кандидаты меняются вместе с бандлом,
    #: моделью и выжимкой.
    candidates: list[str] = Field(default_factory=list)
    model: str | None = None
    attack_version: str | None = None


def response_schema(candidates: list[Candidate]) -> dict[str, Any]:
    """JSON-схема ответа с перечислением из отобранных кандидатов."""
    ids = [c.technique_id for c in candidates]
    return {
        "type": "object",
        "properties": {
            "techniques": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_TECHNIQUES,
                "items": {
                    "type": "object",
                    "properties": {
                        "technique_id": {"type": "string", "enum": ids},
                        "confidence": {"type": "string", "enum": list(CONFIDENCE_LEVELS)},
                        "evidence": {"type": "string"},
                    },
                    "required": ["technique_id", "confidence", "evidence"],
                },
            }
        },
        "required": ["techniques"],
    }


def build_prompt(
    payload: GroupPayload,
    candidates: list[Candidate],
    techniques: dict[str, Technique],
) -> str:
    """Промпт: выжимка по группе и подписанные кандидаты.

    Описания кандидатов даются по-русски, если перевод есть: выжимка тоже
    русская, и заставлять модель мысленно переводить туда-сюда незачем.
    """
    lines = [
        "Ты размечаешь правила детекта SIEM по матрице MITRE ATT&CK.",
        "",
        f"ГРУППА ПРАВИЛ: {payload.group} ({payload.rule_count} правил)",
    ]
    if payload.titles:
        lines.append("Заголовки правил:")
        lines += [f"  - {t}" for t in payload.titles]
    if payload.descriptions:
        # Что правило сообщает при срабатывании. Для модели это самый
        # прямой рассказ о технике: заголовок называет правило, а описание
        # объясняет, что именно произошло.
        lines.append("Что правило сообщает при срабатывании:")
        lines += [f"  - {t}" for t in payload.descriptions]
    if payload.event_ids:
        lines.append(f"События: {', '.join(payload.event_ids)}")
    if payload.literals:
        lines.append(f"Характерные значения: {', '.join(payload.literals)}")
    if payload.fields:
        lines.append(f"Поля: {', '.join(payload.fields)}")

    lines += ["", "КАНДИДАТЫ (выбирать только из них):"]
    for c in candidates:
        technique = techniques.get(c.technique_id)
        name = (technique.name_ru or technique.name) if technique else c.name
        description = ""
        if technique:
            description = (technique.description_ru or technique.description)[:400]
        lines.append(f"  {c.technique_id} — {name}")
        if description:
            lines.append(f"      {description}")

    lines += [
        "",
        "Выбери от одной до трёх техник, которые эта группа правил действительно",
        "обнаруживает. Несколько — только если группа покрывает разные техники",
        "по существу, а не для полноты картины.",
        "",
        "Уверенность ставь честно: «высокая» — если описание прямо соответствует",
        "технике; «низкая» — если сходство косвенное. Заниженная уверенность",
        "полезнее завышенной: разметку проверяет человек, и ему важно понимать,",
        "куда смотреть в первую очередь.",
        "",
        "В evidence одним предложением по-русски укажи, что именно в описании",
        "или значениях указывает на технику. Не пересказывай саму технику.",
    ]
    return "\n".join(lines)
