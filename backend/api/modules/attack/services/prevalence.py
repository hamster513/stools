"""Распространённость техник для наложения на матрицу.

Обёртка над доменным паком: кеширует разбор и связывает его с
действующей матрицей, которая у заказчика может быть своей.
"""
from __future__ import annotations

from functools import lru_cache

from sqlalchemy.orm import Session

from api.modules.attack.services.attack_bundle import current as current_bundle
from kbaudit.attack.campaigns import Campaign
from kbaudit.attack.campaigns import load as load_campaigns
from kbaudit.attack.prevalence import Prevalence, load

#: Тактики, которые сенсоры не видят по своей природе: всё это
#: происходит вне периметра — у регистратора доменов, на площадке
#: с эксплойтами, в чужой почте. Нулевая телеметрия здесь означает
#: «не наблюдаемо», а не «не применяется», и подавать её как пробел
#: в покрытии значит требовать правил, которых не может быть.
UNOBSERVABLE_TACTICS = frozenset({"reconnaissance", "resource-development"})


@lru_cache(maxsize=4)
def _cached(version: str | None, parents: tuple[tuple[str, str], ...]) -> Prevalence:
    return load(parent_of=dict(parents))


def prevalence_for(db: Session) -> Prevalence:
    """Пак, свёрнутый под действующую матрицу — вид для матрицы."""
    book = current_bundle(db)
    parents = tuple(
        sorted((t.technique_id, t.parent_id) for t in book.techniques if t.parent_id)
    )
    return _cached(book.version, parents)


@lru_cache(maxsize=1)
def prevalence_raw() -> Prevalence:
    """Пак без свёртки — вид для карточки техники.

    В карточке человек сравнивает подтехники между собой и решает, какие
    из них правило действительно закрывает. Свёрнутые числа там были бы
    у всех девяти подтехник одинаковыми и ничего бы не подсказывали.
    """
    return load()


@lru_cache(maxsize=1)
def campaigns() -> tuple[Campaign, ...]:
    """Кампании ATT&CK. Файл неизменен, разбор кешируется навсегда."""
    return tuple(load_campaigns())
