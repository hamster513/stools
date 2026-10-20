"""Слой «Threat Hunting» платформенной матрицы ATT&CK."""
from __future__ import annotations

import datetime as dt
from typing import Any

from api.modules.attack.layers import LAYERS, MAX_ITEMS
from api.modules.siem.hunting.models import ThHunt
from tests.siem_hunting.conftest import db_session  # noqa: F401 — фикстура


def _hunt(db: Any, code: str, technique: str | None, **kw: Any) -> ThHunt:
    hunt = ThHunt(code=code, name=f"Хант {code}", technique_id=technique, **kw)
    db.add(hunt)
    db.flush()
    return hunt


def test_layer_counts_enabled_hunts_only(db_session: Any) -> None:  # noqa: F811
    on = _hunt(db_session, "H1", "T1059.001")
    _hunt(db_session, "H2", "T1059")
    _hunt(db_session, "H3", "T1059", enabled=False)
    _hunt(db_session, "H4", "T1059", deleted_at=dt.datetime.now(dt.UTC))
    _hunt(db_session, "H5", None)
    _hunt(db_session, "H6", "T1003")
    db_session.commit()

    result = LAYERS["siem_hunting"].build(db_session)

    assert result.available
    assert set(result.cells) == {"T1059", "T1003"}
    cell = result.cells["T1059"]
    # Выключенный и удалённый хант покрытия не дают; подтехника засчитана родителю.
    assert cell.count == 2 and cell.status == "confirmed"
    first = next(i for i in cell.items if i.title == "H1")
    assert first.subtitle == "Хант H1" and first.href == f"/siem/hunting/library/{on.id}"
    # Полный идентификатор подтехники и её родитель — оба в наборе слоя.
    assert result.technique_ids == {"T1059.001", "T1059", "T1003"}


def test_layer_caps_items_but_not_count(db_session: Any) -> None:  # noqa: F811
    for i in range(MAX_ITEMS + 3):
        _hunt(db_session, f"C{i:02d}", "T1087")
    db_session.commit()

    cell = LAYERS["siem_hunting"].build(db_session).cells["T1087"]

    assert cell.count == MAX_ITEMS + 3 and len(cell.items) == MAX_ITEMS


def test_layer_without_technique_hunts(db_session: Any) -> None:  # noqa: F811
    _hunt(db_session, "H1", None)
    db_session.commit()

    result = LAYERS["siem_hunting"].build(db_session)

    assert result.available is False and result.cells == {}
    assert result.note == "хантов с техникой нет"
