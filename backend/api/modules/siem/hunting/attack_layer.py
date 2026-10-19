"""Ханты с техникой ATT&CK как слой платформенной матрицы «Threat Hunting».

Хант, привязанный к технике, — это покрытие: аналитик регулярно ищет её
следы в событиях. Поэтому слой того же рода, что и покрытие правилами SIEM,
и подтверждённым считается любой включённый хант: пометки «предположительно»
у ханта нет, его технику выбрал человек. Выключенный и удалённый хант ничего
не ищет, и показывать его в матрице как покрытие значило бы приукрашивать.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from api.modules.attack.layers import (
    MAX_ITEMS,
    Layer,
    LayerCell,
    LayerItem,
    LayerResult,
    parent_of,
)
from api.modules.siem.hunting.models import ThHunt

STATUS_CONFIRMED = "confirmed"


def build(db: Session) -> LayerResult:
    """Ячейки по родительским техникам включённых неудалённых хантов."""
    hunts = (
        db.query(ThHunt)
        .filter(
            ThHunt.technique_id.is_not(None),
            ThHunt.technique_id != "",
            ThHunt.enabled.is_(True),
            ThHunt.deleted_at.is_(None),
        )
        .order_by(ThHunt.code)
        .all()
    )
    if not hunts:
        return LayerResult(cells={}, note="хантов с техникой нет", available=False)
    by_parent: dict[str, list[ThHunt]] = {}
    ids: set[str] = set()
    for hunt in hunts:
        technique = str(hunt.technique_id)
        # Подтехника засчитывается родителю (как в слое правил), но в набор
        # слоя идёт и полный идентификатор — платформе нужно отличать
        # закрытую подтехнику от закрытой техники целиком.
        ids.update((technique, parent_of(technique)))
        by_parent.setdefault(parent_of(technique), []).append(hunt)
    cells = {
        parent: LayerCell(
            count=len(group),
            status=STATUS_CONFIRMED,
            items=tuple(
                LayerItem(
                    title=hunt.code,
                    subtitle=hunt.name,
                    href=f"/siem/hunting/library/{hunt.id}",
                )
                for hunt in group[:MAX_ITEMS]
            ),
        )
        for parent, group in by_parent.items()
    }
    return LayerResult(cells=cells, technique_ids=frozenset(ids))


TH_LAYER = Layer(
    id="siem_hunting",
    title="Threat Hunting",
    kind="coverage",
    unit=("хант", "ханта", "хантов"),
    build=build,
)
