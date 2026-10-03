"""Записи политики, которые нужны отдельно от дерева настроек: исключения и сетевые правила.

Извлекатель по продукту (`EXTRACTORS`, код `KLPOL_PRODUCT`) получает секции политики или профиля
и возвращает записи. На этапе 1 реестр пуст: продукт «не описан», записи не строятся; этап 2
добавляет извлекатель KES. Ключи записей не включают политику и профиль — по ним ищутся дубли.
"""
from __future__ import annotations

import fnmatch
import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

#: Виды исключений, которые сравниваются как пути: каталог или маска покрывает файл.
PATH_KINDS = {"path", "mask"}


@dataclass(frozen=True)
class Exclusion:
    kind: str
    value: str
    components: tuple[str, ...] = ()
    enabled: bool = True
    comment: str = ""
    #: Имя профиля; "" — сама политика.
    profile: str = ""


@dataclass(frozen=True)
class NetRule:
    layer: str
    position: int
    name: str
    action: str
    direction: str = ""
    protocol: str = ""
    local_ports: str = ""
    remote_ports: str = ""
    addresses: str = ""
    enabled: bool = True
    #: Имя профиля; "" — сама политика.
    profile: str = ""


@dataclass
class PolicyObjects:
    exclusions: list[Exclusion] = field(default_factory=list)
    net_rules: list[NetRule] = field(default_factory=list)
    #: (секция, путь) настроек, из которых получены записи: журнал изменений их как `setting` не считает.
    consumed: set[tuple[str, str]] = field(default_factory=set)


#: Секции политики или профиля → записи.
Extractor = Callable[[dict[str, Any]], PolicyObjects]
#: Код продукта (KLPOL_PRODUCT) → извлекатель; заполняет этап 2.
EXTRACTORS: dict[str, Extractor] = {}


def extract(product: str, sections: dict[str, Any]) -> PolicyObjects | None:
    """Записи из секций; None — для продукта нет извлекателя (продукт не описан)."""
    extractor = EXTRACTORS.get(product)
    return extractor(sections) if extractor is not None else None


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def exclusion_key(e: Exclusion) -> str:
    return _digest(f"{e.kind}|{e.value.strip().lower()}")


def net_rule_key(r: NetRule) -> str:
    return _digest(f"{r.layer}|{r.name}|{r.direction}|{r.protocol}|{r.local_ports}|{r.remote_ports}|{r.addresses}".lower())


def _wider(other: str, value: str) -> bool:
    """`other` — каталог-префикс `value` (граница по разделителю) или маска, под которую `value` подходит.
    Замыкающие разделители не в счёт: `C:\\Tools\\` и `C:\\Tools` — один каталог, шире он не бывает."""
    prefix, bare = other.rstrip("\\/"), value.rstrip("\\/")
    if prefix and len(bare) > len(prefix) and bare.startswith(prefix) and bare[len(prefix)] in "\\/":
        return True
    return ("*" in other or "?" in other) and fnmatch.fnmatchcase(value, other)


def covered_by(e: Exclusion, others: Iterable[Exclusion]) -> Exclusion | None:
    """Первое другое включённое исключение-путь или маска, которое шире `e`; равные значения перекрытием не считаются."""
    if e.kind not in PATH_KINDS:
        return None
    value = e.value.strip().lower()
    for o in others:
        if o is e or not o.enabled or o.kind not in PATH_KINDS:
            continue
        other = o.value.strip().lower()
        if other != value and _wider(other, value):
            return o
    return None
