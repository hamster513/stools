"""Реестр свежести данных модулей: границы stale_after и изоляция упавшего провайдера."""
from __future__ import annotations

import datetime as dt

import pytest

from api.platform import data_status
from api.platform.data_status import DataItem, collect, register_data_status, stale_after


def test_stale_after_boundaries() -> None:
    now = dt.datetime.now(dt.UTC)
    assert stale_after(None, 7) == "missing"
    assert stale_after(now - dt.timedelta(days=6, hours=23), 7) == "fresh"
    assert stale_after(now - dt.timedelta(days=7, minutes=1), 7) == "stale"
    assert stale_after(now, 7, running=True) == "running"
    assert stale_after(now.replace(tzinfo=None) - dt.timedelta(days=1), 7) == "fresh"  # naive → UTC


def test_collect_isolates_failing_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(data_status, "_PROVIDERS", {})

    def boom(db: object) -> list[DataItem]:
        raise ValueError("boom")

    register_data_status("x", boom)
    register_data_status("y", lambda db: [DataItem("y", "k", "T", "source", None, "missing", None, "", "a")])
    items = collect(db=None)  # type: ignore[arg-type]
    assert [(i.module, i.state, i.detail) for i in items] == [
        ("x", "missing", "ошибка: ValueError"),
        ("y", "missing", ""),
    ]


def test_collect_orders_by_module_routers_then_unknown_by_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(data_status, "_PROVIDERS", {})
    for module in ("zzz", "vm", "aaa", "attack"):
        register_data_status(module, lambda db, m=module: [DataItem(m, "k", "T", "source", None, "missing", None, "", "")])
    assert [i.module for i in collect(db=None)] == ["attack", "vm", "aaa", "zzz"]  # type: ignore[arg-type]


def test_register_replaces_module_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(data_status, "_PROVIDERS", {})
    register_data_status("x", lambda db: [])
    register_data_status("x", lambda db: [DataItem("x", "k", "T", "source", None, "missing", None, "", "")])
    assert data_status.registered_modules() == frozenset({"x"})
    assert len(collect(db=None)) == 1  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("n", "expected"),
    [
        (1, "1 запись"),
        (2, "2 записи"),
        (5, "5 записей"),
        (11, "11 записей"),
        (21, "21 запись"),
        (248312, "248 312 записей"),
    ],
)
def test_count_ru(n: int, expected: str) -> None:
    assert data_status.count_ru(n, ("запись", "записи", "записей")) == expected
