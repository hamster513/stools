"""Многозначные фильтры списков (спека §1.1).

Значения фасета приходят одной строкой через запятую (`severity=high,critical`), как уже было у
`status`; внутри фасета — «ИЛИ», между фасетами — «И». Пустое значение и `all` — фильтр не задан.

`multi_int` сам отвечает 422 (`HTTPException`), а не отдаёт `ValueError` ручке: разбор вызывается
из десятка ручек, и пусть ни одна не забудет превратить мусор в понятный отказ вместо 500.
"""
from __future__ import annotations

from fastapi import HTTPException, status


def multi(value: str | None) -> frozenset[str] | None:
    """'a,b,,c' → {'a','b','c'}; None, '', 'all' и одни запятые → None (фильтр не задан)."""
    if not value or value == "all":
        return None
    picked = frozenset(v for v in value.split(",") if v)
    return picked or None


def multi_int(value: str | None) -> frozenset[int] | None:
    """'1,2' → {1, 2}; не задан — как у `multi`; не число → 422."""
    picked = multi(value)
    if picked is None:
        return None
    try:
        return frozenset(int(v) for v in picked)
    except ValueError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"ожидались числа через запятую: {value}") from None


def matches(value: str | None, chosen: frozenset[str] | None) -> bool:
    """Фильтр не задан — подходит всё; иначе значение среди выбранных. None — то же, что '':
    «не задано» — отдельное значение фасета."""
    return chosen is None or (value or "") in chosen
