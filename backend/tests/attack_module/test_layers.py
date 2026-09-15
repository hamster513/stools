from __future__ import annotations

from typing import Any

import pytest

from api.modules.attack.layers import (
    Layer,
    LayerCell,
    LayerItem,
    LayerResult,
    collect,
    parent_of,
    register_layer,
)


def _layer(id_: str, build: Any, kind: str = "exposure") -> Layer:
    return Layer(id=id_, title=id_.upper(), kind=kind, unit=("шт", "шт", "шт"), build=build)  # type: ignore[arg-type]


def test_parent_of() -> None:
    assert parent_of("T1003.006") == "T1003"
    assert parent_of("T1190") == "T1190"


def test_register_and_collect(clean_layers: dict[str, Layer]) -> None:
    cell = LayerCell(count=2, items=(LayerItem("a", "b", "/x"),))
    register_layer(_layer("vm", lambda db: LayerResult(cells={"T1190": cell}, note="риск ≥ 40")))
    out = collect(db=None)
    assert out["vm"].cells["T1190"].count == 2 and out["vm"].note == "риск ≥ 40" and out["vm"].available


def test_duplicate_id_rejected(clean_layers: dict[str, Layer]) -> None:
    register_layer(_layer("vm", lambda db: LayerResult(cells={})))
    with pytest.raises(ValueError, match="vm"):
        register_layer(_layer("vm", lambda db: LayerResult(cells={})))


def test_failing_layer_does_not_break_others(clean_layers: dict[str, Layer]) -> None:
    def boom(db: Any) -> LayerResult:
        raise RuntimeError("база недоступна")

    register_layer(_layer("ad", boom))
    register_layer(_layer("vm", lambda db: LayerResult(cells={"T1190": LayerCell(count=1)})))
    out = collect(db=None)
    assert out["ad"].available is False and "база недоступна" in (out["ad"].note or "")
    assert out["ad"].cells == {} and out["vm"].cells["T1190"].count == 1
