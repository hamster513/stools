"""Перевод описаний техник ATT&CK на русский.

Отдельно от разметки намеренно. Разметку человек подтверждает — ошибка
в ней рано или поздно всплывёт на проверке. Перевод не подтверждает
никто: неверный русский текст выглядит как верный и живёт годами,
подмешиваясь в отбор кандидатов. Поэтому здесь ограничение вывода
схемой, отказ от догадок и явная пометка происхождения.

Провайдер описан протоколом: сегодня это локальная Ollama, завтра
может быть большая модель, и выбор делает человек в настройках.
"""
from __future__ import annotations

import json
from typing import Any, Protocol

from pydantic import BaseModel

#: Сколько техник переводить одним запросом. Больше — дешевле по
#: накладным расходам, но длинный ответ модель чаще обрывает на середине.
BATCH_SIZE = 5

#: Описание обрезается: полные тексты ATT&CK бывают в несколько экранов,
#: а для отбора кандидатов и чтения человеком нужна суть.
MAX_DESCRIPTION = 1200


class TranslationRequest(BaseModel):
    technique_id: str
    name: str
    description: str = ""


class TranslatedTechnique(BaseModel):
    technique_id: str
    name_ru: str
    description_ru: str


class Completion(Protocol):
    def complete(self, prompt: str, schema: dict[str, Any]) -> str: ...


def response_schema(items: list[TranslationRequest]) -> dict[str, Any]:
    """Схема ответа с перечислением идентификаторов из запроса.

    Перечисление не даёт модели придумать технику, которой не просили,
    и не даёт молча пропустить: длина массива задана обеими границами.
    """
    ids = [i.technique_id for i in items]
    return {
        "type": "object",
        "properties": {
            "techniques": {
                "type": "array",
                "minItems": len(ids),
                "maxItems": len(ids),
                "items": {
                    "type": "object",
                    "properties": {
                        "technique_id": {"type": "string", "enum": ids},
                        "name_ru": {"type": "string"},
                        "description_ru": {"type": "string"},
                    },
                    "required": ["technique_id", "name_ru", "description_ru"],
                },
            }
        },
        "required": ["techniques"],
    }


def build_prompt(items: list[TranslationRequest], glossary: dict[str, str]) -> str:
    """Промпт с выдержкой из уже принятого перевода.

    Глоссарий — не украшение: без него модель переведёт «Defense Evasion»
    как «уклонение от защиты» там, где в матрице уже написано «обход
    защиты», и в одном интерфейсе окажутся два названия одного.
    """
    lines = [
        "Ты переводишь описания техник MITRE ATT&CK на русский язык для",
        "инструмента, которым пользуются аналитики SOC.",
        "",
        "Правила перевода:",
        "— Названия продуктов, утилит, протоколов и служб оставляй как есть:",
        "  PowerShell, LSASS, Regsvr32, Kerberoasting, DNS, WMI.",
        "— Устоявшиеся термины переводи привычно: adversary — «злоумышленник»,",
        "  persistence — «закрепление», payload — «полезная нагрузка».",
        "— Описание давай сжатым: два-три предложения по сути техники,",
        "  без пересказа примеров и без ссылок на источники.",
        "— Ничего не выдумывай: если в исходнике нет подробности, её нет и в переводе.",
    ]
    if glossary:
        lines += ["", "Уже принятый перевод — придерживайся его терминологии:"]
        lines += [f"  {en} — {ru}" for en, ru in sorted(glossary.items())[:20]]

    lines += ["", "ПЕРЕВЕДИ:"]
    for item in items:
        lines.append(f"  {item.technique_id} — {item.name}")
        if item.description:
            lines.append(f"      {item.description[:MAX_DESCRIPTION]}")
    return "\n".join(lines)


class TranslationError(RuntimeError):
    """Перевод не получен или не разбирается."""


def translate_batch(
    items: list[TranslationRequest],
    completion: Completion,
    glossary: dict[str, str] | None = None,
) -> list[TranslatedTechnique]:
    """Перевод пачки техник.

    Ответ, в котором не хватает техник или есть чужие, отбрасывается
    целиком: частично разобранная пачка тихо оставила бы часть техник
    без перевода, и понять это было бы уже неоткуда.
    """
    if not items:
        return []
    raw = completion.complete(build_prompt(items, glossary or {}), response_schema(items))
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TranslationError("ответ модели не разбирается как JSON") from exc

    wanted = {i.technique_id for i in items}
    out: list[TranslatedTechnique] = []
    for entry in parsed.get("techniques") or []:
        if not isinstance(entry, dict):
            continue
        technique_id = entry.get("technique_id")
        if technique_id not in wanted:
            continue
        name_ru = str(entry.get("name_ru") or "").strip()
        if not name_ru:
            continue
        out.append(
            TranslatedTechnique(
                technique_id=str(technique_id),
                name_ru=name_ru,
                description_ru=str(entry.get("description_ru") or "").strip(),
            )
        )

    got = {t.technique_id for t in out}
    if got != wanted:
        missing = sorted(wanted - got)
        raise TranslationError(f"модель не перевела {len(missing)} техник из {len(items)}")
    return out
