"""Многозначные фильтры списков (спека §1.1 и дополнение о формате).

Значения фасета приходят повтором ключа (`?zone=DMZ&zone=Офис`), каждый элемент — значение как есть:
свободные значения (ОС, группы и продукты KSC, теги, зоны) сами содержат запятые, и разбор по
запятой молча превращал бы выбор в пустой список. Внутри фасета — «ИЛИ», между фасетами — «И».
`all` — фильтр не задан. Только статусы (`status`, `disc_status`) ещё понимают старую строку через
запятую (`status=new,in_work`): на неё есть ссылки и скрипты, а в кодах статусов запятых нет.

`multi_int` сам отвечает 422 (`HTTPException`), а не отдаёт `ValueError` ручке: разбор вызывается
из десятка ручек, и пусть ни одна не забудет превратить мусор в понятный отказ вместо 500.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated

from fastapi import HTTPException, Query, status

#: Пустое значение фасета («не задано»): страница не шлёт пустой параметр, поэтому шлёт `-`.
#: Тот же `-`, что у тегов KSC («без тегов»).
EMPTY = "-"

#: Многозначный параметр запроса: `?name=a&name=b`.
QueryList = Annotated[list[str] | None, Query()]
#: То же для id: не число — 422 от самого FastAPI.
QueryInts = Annotated[list[int] | None, Query()]
#: Статусы: повтор ключа и старая строка через запятую.
QueryStatus = Annotated[list[str] | None, Query(alias="status")]

Values = str | Sequence[str] | None


def _items(value: Values) -> list[str]:
    """Строка — одно значение (старые вызовы и фильтр массовой смены), список — как есть."""
    return [value] if isinstance(value, str) else list(value or ())


def is_all(value: Values) -> bool:
    """Выбрано `all` — для статусов это «любые», а не «по умолчанию»."""
    return "all" in _items(value)


def multi(value: Values, *, commas: bool = False) -> frozenset[str] | None:
    """Элементы как есть; `-` и '' → '' («не задано»); `all` или пусто → None (фильтр не задан).
    `commas` — только для статусов: элементы ещё и делятся по запятой, пустые части отбрасываются."""
    items = _items(value)
    if "all" in items:
        return None
    if commas:
        items = [part for v in items for part in v.split(",") if part]
    picked = frozenset("" if v == EMPTY else v for v in items)
    return picked or None


def multi_int(value: str | Sequence[str | int] | None) -> frozenset[int] | None:
    """Id: числа как есть, строки — `int`; `all` или пусто → None; не число → 422."""
    items: list[str | int] = [value] if isinstance(value, str) else list(value or ())
    if "all" in items:
        return None
    try:
        picked = frozenset(int(v) for v in items)
    except ValueError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"ожидались числа: {', '.join(map(str, items))}") from None
    return picked or None


def matches(value: str | None, chosen: frozenset[str] | None) -> bool:
    """Фильтр не задан — подходит всё; иначе значение среди выбранных. None — то же, что '':
    «не задано» — отдельное значение фасета."""
    return chosen is None or (value or "") in chosen
