"""Разборщик многозначных фильтров (спека §1.1): значения через запятую, `all` и пустое — «не задан»."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from api.platform.filters import matches, multi, multi_int


def test_multi_splits_on_commas_and_drops_empty_items() -> None:
    assert multi("a,b,,c") == frozenset({"a", "b", "c"})
    assert multi("high") == frozenset({"high"})


@pytest.mark.parametrize("raw", [None, "", "all", ",", ",,"])
def test_multi_unset(raw: str | None) -> None:
    assert multi(raw) is None


def test_multi_int() -> None:
    assert multi_int("1,2,,3") == frozenset({1, 2, 3})
    assert multi_int(None) is None and multi_int("") is None and multi_int("all") is None


@pytest.mark.parametrize("raw", ["1,x", "abc", "1.5"])
def test_multi_int_rejects_garbage_with_422(raw: str) -> None:
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
