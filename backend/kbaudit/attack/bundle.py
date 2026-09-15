"""Чтение STIX-бандла ATT&CK.

Бандл вкладывается в образ и не тянется из сети при старте: работоспособность
при полностью отключённой сети — критерий приёмки. Версия фиксируется и
показывается в интерфейсе, потому что разметка, подтверждённая на одной
версии ATT&CK, на другой может устареть — техника переезжает, дробится
на подтехники или объявляется устаревшей.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

#: Тип объекта STIX, которым описываются техники и подтехники.
ATTACK_PATTERN = "attack-pattern"

#: Тактика и матрица: из них берётся порядок колонок.
TACTIC = "x-mitre-tactic"
MATRIX = "x-mitre-matrix"

#: Внешний источник, из которого берётся человекочитаемый идентификатор
#: вида T1569.002. Другие источники (CAPEC, NIST) для наших целей не нужны.
MITRE_SOURCE = "mitre-attack"


class Technique(BaseModel):
    """Техника или подтехника ATT&CK."""

    technique_id: str
    name: str
    description: str = ""
    #: Перевод на русский. Нужен по двум причинам сразу: описания правил
    #: в базе знаний написаны по-русски, и сопоставление русского текста
    #: с русским работает заметно лучше кросс-языкового; плюс аналитик
    #: читает это описание в интерфейсе рядом с матрицей покрытия.
    name_ru: str | None = None
    description_ru: str | None = None
    tactics: list[str] = Field(default_factory=list)
    #: Подтехники отбираются отдельно: у одной техники их бывает до десятка,
    #: и с почти одинаковыми описаниями они забивают верхушку выдачи.
    is_subtechnique: bool = False
    parent_id: str | None = None
    deprecated: bool = False

    @property
    def embedding_text(self) -> str:
        """Текст, по которому техника ищется.

        Русский перевод, если он есть, ставится первым и дополняется
        английским оригиналом: часть сигнала в выжимках по правилам —
        это непереводимые имена (`LSASS`, `svcctl`, `PowerShell`), и они
        живут в английском тексте.

        Название идёт раньше описания: в коротких выжимках совпадение
        по названию — более сильный сигнал, чем совпадение где-то
        в середине описания на несколько абзацев.
        """
        tactics = ", ".join(self.tactics)
        parts = [self.name_ru or "", self.description_ru or "", self.name, tactics, self.description]
        return "\n".join(p for p in parts if p).strip()


class Tactic(BaseModel):
    """Тактика матрицы — колонка в её привычном виде."""

    shortname: str
    name: str


class AttackBundle(BaseModel):
    version: str | None = None
    techniques: list[Technique] = Field(default_factory=list)
    #: Тактики в порядке матрицы, а не по алфавиту. Порядок задан MITRE
    #: и несёт смысл: это последовательность шагов атаки, и матрица,
    #: отсортированная как-то иначе, читается неправильно.
    tactics: list[Tactic] = Field(default_factory=list)

    def by_id(self) -> dict[str, Technique]:
        return {t.technique_id: t for t in self.techniques}

    def parents_only(self) -> list[Technique]:
        """Только родительские техники.

        Отбор кандидатов идёт по ним, а подтехника уточняется вторым шагом
        внутри выбранной ветки: иначе четыре почти одинаковые подтехники
        одного семейства занимают четыре места из пятнадцати.
        """
        return [t for t in self.techniques if not t.is_subtechnique]

    def children_of(self, technique_id: str) -> list[Technique]:
        return [t for t in self.techniques if t.parent_id == technique_id]


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == MITRE_SOURCE:
            value = ref.get("external_id")
            if isinstance(value, str):
                return value
    return None


def _tactics(obj: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for phase in obj.get("kill_chain_phases") or []:
        if isinstance(phase, dict) and phase.get("kill_chain_name") == MITRE_SOURCE:
            name = phase.get("phase_name")
            if isinstance(name, str):
                out.append(name)
    return out


def _collection_version(objects: list[Any]) -> str | None:
    """Версия ATT&CK из объекта коллекции.

    Нужна не для порядка: разметка, подтверждённая человеком на одной
    версии, на другой может относиться к технике, которую с тех пор
    раздробили на подтехники или отозвали. Версия показывается рядом
    с матрицей покрытия, чтобы это было видно.
    """
    for obj in objects:
        if isinstance(obj, dict) and obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version")
            if isinstance(version, str):
                return version
    return None


def apply_translations(bundle: AttackBundle, translations: Path) -> AttackBundle:
    """Подмешать русские названия и описания.

    Отсутствие файла не ошибка: без перевода инструмент работает, просто
    хуже сопоставляет. Техники, которых нет в переводе, остаются
    английскими — так добавление техник новой версией ATT&CK не ломает
    разбор, а лишь показывает, что перевод отстал.
    """
    if not translations.is_file():
        return bundle
    raw = json.loads(translations.read_text(encoding="utf-8"))
    by_id = {item["id"]: item for item in raw if isinstance(item, dict) and "id" in item}
    for technique in bundle.techniques:
        item = by_id.get(technique.technique_id)
        if item:
            technique.name_ru = item.get("name_ru")
            technique.description_ru = item.get("description_ru")
    return bundle


def _ordered_tactics(objects: list[Any]) -> list[Tactic]:
    """Тактики в порядке матрицы Enterprise.

    Порядок берётся из `tactic_refs`, а не из порядка объектов в файле:
    в STIX объекты лежат как попало, а колонки матрицы обязаны идти
    от разведки к воздействию.
    """
    by_id = {
        o["id"]: o
        for o in objects
        if isinstance(o, dict) and o.get("type") == TACTIC and "id" in o
    }
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != MATRIX:
            continue
        out: list[Tactic] = []
        for ref in obj.get("tactic_refs") or []:
            tactic = by_id.get(ref)
            if tactic and tactic.get("x_mitre_shortname"):
                out.append(
                    Tactic(
                        shortname=str(tactic["x_mitre_shortname"]),
                        name=str(tactic.get("name") or ""),
                    )
                )
        if out:
            return out
    return []


def load_bundle(path: Path) -> AttackBundle:
    """Разбор STIX-бандла в плоский список техник.

    Устаревшие и отозванные техники отбрасываются: предлагать разметку
    техникой, которой в текущей версии ATT&CK уже нет, — значит создавать
    работу по её последующему исправлению.
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    objects = raw.get("objects") or []

    techniques: list[Technique] = []
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != ATTACK_PATTERN:
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        technique_id = _external_id(obj)
        if not technique_id:
            continue
        is_sub = bool(obj.get("x_mitre_is_subtechnique"))
        techniques.append(
            Technique(
                technique_id=technique_id,
                name=str(obj.get("name") or ""),
                description=str(obj.get("description") or ""),
                tactics=_tactics(obj),
                is_subtechnique=is_sub,
                parent_id=technique_id.split(".")[0] if is_sub else None,
            )
        )

    return AttackBundle(
        version=_collection_version(objects),
        techniques=sorted(techniques, key=lambda t: t.technique_id),
        tactics=_ordered_tactics(objects),
    )


#: Компактный бандл, вложенный в пакет. Полный STIX-файл MITRE — 51 МБ,
#: из которых техники занимают около одного: остальное — группировки,
#: ПО, меры защиты и связи между ними, которых разметка не касается.
#: Вкладывается именно выжимка: 51 МБ в образе ради двух процентов
#: содержимого не нужны, а работа при отключённой сети — критерий приёмки.
COMPACT_BUNDLE = Path(__file__).with_name("attack_techniques.json")

#: Русские названия и описания техник, 697 записей.
TRANSLATIONS = Path(__file__).with_name("attack_ru.json")


def load_compact(path: Path = COMPACT_BUNDLE) -> AttackBundle:
    """Разбор компактного бандла — плоского списка техник."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    return AttackBundle(
        version=raw.get("version"),
        techniques=[Technique.model_validate(t) for t in raw.get("techniques") or []],
        tactics=[Tactic.model_validate(t) for t in raw.get("tactics") or []],
    )


def load_default() -> AttackBundle:
    """Вложенный бандл с наложенными русскими описаниями."""
    return apply_translations(load_compact(), TRANSLATIONS)
