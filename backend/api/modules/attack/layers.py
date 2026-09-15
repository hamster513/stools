"""Слои матрицы: каждый модуль отдаёт своё «technique_id → ячейка».

Реестр заполняется при импорте модулей (api/modules/__init__.py импортирует
их все), поэтому к первому запросу слои уже на месте. Направление
зависимостей одно: модули знают про `attack`, `attack` про модули — нет.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

#: Сколько элементов слой кладёт в карточку техники.
MAX_ITEMS = 20


@dataclass(frozen=True)
class LayerItem:
    """Строка в карточке техники: что именно даёт экспозицию или покрытие."""

    title: str
    subtitle: str
    href: str


@dataclass(frozen=True)
class LayerCell:
    count: int
    #: Только для покрытия: confirmed | suggested.
    status: str | None = None
    items: tuple[LayerItem, ...] = ()


@dataclass(frozen=True)
class LayerResult:
    cells: dict[str, LayerCell]
    #: Все техники слоя с полными идентификаторами (и подтехники) — для
    #: цепочек и признака «подтехника закрыта».
    technique_ids: frozenset[str] = frozenset()
    #: Подпись слоя на экране: «риск ≥ 40», «нет снапшотов», текст ошибки.
    note: str | None = None
    available: bool = True


@dataclass(frozen=True)
class Layer:
    id: str
    title: str
    kind: Literal["coverage", "exposure"]
    #: Формы единицы для счётчика: («хост», «хоста», «хостов»).
    unit: tuple[str, str, str]
    build: Callable[[Session], LayerResult]


LAYERS: dict[str, Layer] = {}


def register_layer(layer: Layer) -> None:
    if layer.id in LAYERS:
        raise ValueError(f"слой {layer.id} уже зарегистрирован")
    LAYERS[layer.id] = layer


def parent_of(technique_id: str) -> str:
    return technique_id.split(".", 1)[0]


def collect(db: Session) -> dict[str, LayerResult]:
    """Все слои; упавший помечается недоступным, остальные не страдают."""
    out: dict[str, LayerResult] = {}
    for layer in LAYERS.values():
        try:
            out[layer.id] = layer.build(db)
        except Exception as exc:
            logger.exception("слой %s не построен", layer.id)
            out[layer.id] = LayerResult(cells={}, note=f"ошибка: {exc}"[:200], available=False)
    return out
