"""Форма словаря продукта: секции политики → настройки с названиями, видом значения и компонентом защиты."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Entry:
    #: Путь настройки внутри секции, как у `walk_settings` (`firewall.enabled`).
    path: str
    title: str
    #: bool | enum | number | text | list
    kind: str = "bool"
    enum: dict[int, str] | None = None
    unit: str = ""
    #: False — подписи значений не подтверждены калибровкой (показывается «код N»).
    verified: bool = True
    #: Переопределяет компонент секции (`cf9370d5`: hips / firewall).
    component: str = ""


@dataclass(frozen=True)
class SectionDef:
    name: str
    component: str
    entries: tuple[Entry, ...]


@dataclass(frozen=True)
class ProductDict:
    product: str
    title: str
    #: Код компонента → название; порядок — порядок показа.
    components: dict[str, str]
    sections: dict[str, SectionDef]
    #: Код компонента → (секция, путь признака «включён»).
    enabled_paths: dict[str, tuple[str, str]]


@dataclass(frozen=True)
class Described:
    section: str
    path: str
    component: str
    title: str
    value: str
    raw: str
    locked: bool | None
    verified: bool
