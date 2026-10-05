"""Словари продуктов: настройки политики («секция, путь = значение») → человеческие названия по компонентам защиты.

Секция сопоставляется по точному имени, настройка — по точному пути `Setting.path`; всё, чего нет в словаре,
остаётся нераспознанным (раздел «Прочее»), догадок нет. Неизвестный код перечисления показывается «код N».
"""
from __future__ import annotations

from typing import Any

from api.modules.ksc.core.dictionary.kes_windows import KES_WINDOWS
from api.modules.ksc.core.dictionary.model import Described, Entry, ProductDict, SectionDef
from api.modules.ksc.core.policy_contents import Setting, truncate_value, walk_settings

DICTIONARIES: dict[str, ProductDict] = {KES_WINDOWS.product: KES_WINDOWS}


def _index(d: ProductDict) -> dict[tuple[str, str], tuple[tuple[int, int], SectionDef, Entry]]:
    """(секция, путь) → (позиция показа: порядок компонента, порядок в словаре; секция словаря; настройка)."""
    order = {code: i for i, code in enumerate(d.components)}
    out: dict[tuple[str, str], tuple[tuple[int, int], SectionDef, Entry]] = {}
    for section in d.sections.values():
        for entry in section.entries:
            out[(section.name, entry.path)] = ((order[entry.component or section.component], len(out)), section, entry)
    return out


_INDEX = {code: _index(d) for code, d in DICTIONARIES.items()}

__all__ = ["DICTIONARIES", "Described", "component_enabled", "describe", "dictionary_for", "display_value"]


def dictionary_for(product: str) -> ProductDict | None:
    return DICTIONARIES.get(product)


def _shown(value: Any) -> str:
    """Значение не того вида, что ждёт словарь: строка как есть («—» для пустой), остальное — JSON-текст."""
    if isinstance(value, str):
        return value or "—"
    return truncate_value(value)


def display_value(entry: Entry, value: Any) -> str:
    """Значение настройки человеческим языком по виду из словаря; значение не того вида — без толкования."""
    if entry.kind == "bool" and isinstance(value, bool):
        return "включено" if value else "выключено"
    if entry.kind == "enum" and isinstance(value, int) and not isinstance(value, bool):
        return (entry.enum or {}).get(value) or f"код {value}"
    if entry.kind == "number" and isinstance(value, int | float) and not isinstance(value, bool):
        return f"{value} {entry.unit}".strip()
    if entry.kind == "list" and isinstance(value, list | dict):
        return f"записей: {len(value)}"
    return _shown(value)


def describe(product: str, sections: dict[str, Any]) -> tuple[list[Described], list[Setting]] | None:
    """(распознанные — в порядке словаря: компонент, затем настройка; нераспознанные — в порядке обхода);
    None — словаря для продукта нет."""
    index = _INDEX.get(product)
    if index is None:
        return None
    known: list[tuple[tuple[int, int], Described]] = []
    other: list[Setting] = []
    for s in walk_settings(sections):
        hit = index.get((s.section, s.path))
        if hit is None:
            other.append(s)
            continue
        pos, section, entry = hit
        known.append((pos, Described(
            section=s.section, path=s.path, component=entry.component or section.component, title=entry.title,
            value=display_value(entry, s.value), raw=truncate_value(s.value), locked=s.locked, verified=entry.verified,
        )))
    known.sort(key=lambda item: item[0])
    return [d for _, d in known], other


def component_enabled(product: str, sections: dict[str, Any], component: str) -> bool | None:
    """Признак «включён» компонента в политике; None — словаря нет, у компонента нет признака, его нет в политике
    или значение не булево."""
    d = DICTIONARIES.get(product)
    if d is None or component not in d.enabled_paths:
        return None
    name, path = d.enabled_paths[component]
    if name not in sections:
        return None
    value = next((s.value for s in walk_settings({name: sections[name]}) if s.path == path), None)
    return value if isinstance(value, bool) else None
