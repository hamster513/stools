"""Разборщик многозначных фильтров (спека §1.1, дополнение о формате): значение фасета — повтором
ключа (`?zone=a&zone=b`), каждый элемент как есть, без разбора по запятым; `-` и '' — «не задано»;
`all` — фильтр не задан. Только статусы ещё понимают старую строку через запятую."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from api.platform.filters import is_all, matches, multi, multi_int


def test_multi_takes_each_item_as_is() -> None:
    assert multi(["high", "critical"]) == frozenset({"high", "critical"})
    assert multi(["Windows 10, Pro"]) == frozenset({"Windows 10, Pro"})  # запятая — часть значения
    assert multi("Серверы, Москва") == frozenset({"Серверы, Москва"})  # строка — одно значение


@pytest.mark.parametrize("raw", [None, [], ["all"], ["high", "all"], "all"])
def test_multi_unset(raw: list[str] | str | None) -> None:
    assert multi(raw) is None


def test_multi_empty_value_markers() -> None:
    """`-` и пустой элемент — «не задано» (''); страница шлёт `-`, потому что пустой параметр не шлёт."""
    assert multi(["high", "-"]) == frozenset({"high", ""})
    assert multi(["-"]) == frozenset({""}) == multi([""])


def test_status_keeps_the_old_comma_string() -> None:
    assert multi(["new,in_work"], commas=True) == frozenset({"new", "in_work"})
    assert multi(["new", "fixed,resolved"], commas=True) == frozenset({"new", "fixed", "resolved"})
    assert multi([","], commas=True) is None and multi([""], commas=True) is None
    assert is_all(["all"]) and is_all("all") and not is_all(None) and not is_all(["new"])


def test_multi_int() -> None:
    assert multi_int([1, 2, 3]) == frozenset({1, 2, 3})
    assert multi_int(["1", "2"]) == frozenset({1, 2})
    assert multi_int(None) is None and multi_int([]) is None and multi_int(["all"]) is None


@pytest.mark.parametrize("raw", [["1", "x"], ["abc"], ["1.5"], ["1,2"]])
def test_multi_int_rejects_garbage_with_422(raw: list[str]) -> None:
    with pytest.raises(HTTPException) as caught:
        multi_int(raw)
    assert caught.value.status_code == 422


def test_matches() -> None:
    assert matches("x", None) and matches(None, None)
    chosen = frozenset({"high", "critical"})
    assert matches("high", chosen) and matches("critical", chosen)
    assert not matches("low", chosen) and not matches(None, chosen)


def test_matches_empty_value_is_its_own_facet_value() -> None:
    """«Не задано» — отдельное значение фасета: None и '' выбираются через ''."""
    unset = frozenset({"", "high"})
    assert matches(None, unset) and matches("", unset) and matches("high", unset)
    assert not matches("low", unset)
