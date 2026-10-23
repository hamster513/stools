"""Фильтр «состав ячейки сводки AD» списков «Активов» и сверка с ним (дизайн «Интерактивная сводка AD»
§5.3–5.4; контракт AD — docs/ad/api.md, «Ячейки сводки»).

Состав ячейки даёт модуль AD функцией в процессе (`cell_info`, кэш по снапшоту; резолвит роутер —
`routers.assets.ad_cell_filter`): листание и фасеты выгрузку повторно не разбирают. Ключ учётки в
составе — `sid or dn`: у пользователей он сверяется с `AssetUser.sid`, у активов — с `source_key`
наблюдений AD (и пропавших). Множество уходит в базу одним параметром-массивом (`= ANY`), а не списком
`IN`: у psycopg предел 65 535 параметров.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import ARRAY, String, any_, distinct, func, literal, select
from sqlalchemy.orm import Session

from api.modules.ad.services.summary_cells import CellInfo
from api.modules.assets.models import Asset, AssetObservation, AssetUser
from api.modules.assets.services.users import ad_user_managed


def key_in(column: Any, keys: frozenset[str]) -> Any:
    """`column = ANY(:массив)` — один параметр на любое число ключей."""
    return column == any_(literal(sorted(keys), ARRAY(String)))


def _check(info: CellInfo, mine: frozenset[str], other: frozenset[str], found: int, not_managed: int) -> dict[str, Any]:
    return {"label": info.label, "collected_at": info.collected_at.isoformat(), "domain": info.domain,
            "in_summary": len(mine), "found": found, "not_managed": not_managed, "other": len(other),
            "summary_n": info.summary_n}


def users_check(db: Session, info: CellInfo) -> dict[str, Any]:
    """Сверка страницы пользователей: `found` — ключи ячейки среди живых (не слитых) пользователей без учёта
    прочих фильтров; `not_managed` — учётки, которых «Активы» по своему правилу не заводят. Ключ-DN —
    учётка без SID."""
    found = db.scalar(select(func.count(distinct(AssetUser.sid))).where(
        AssetUser.merged_into.is_(None), key_in(AssetUser.sid, info.users)))
    not_managed = sum(1 for key in info.users
                      if not ad_user_managed(key if key.upper().startswith("S-1-") else None, info.user_sams.get(key)))
    return _check(info, info.users, info.computers, int(found or 0), not_managed)


def assets_check(db: Session, info: CellInfo) -> dict[str, Any]:
    """Сверка страницы активов: `found` — ключи ячейки среди наблюдений AD (и пропавших) не слитых активов,
    без учёта прочих фильтров."""
    o = AssetObservation
    found = db.scalar(
        select(func.count(distinct(o.source_key))).join(Asset, Asset.id == o.asset_id)
        .where(o.source == "ad", Asset.merged_into.is_(None), key_in(o.source_key, info.computers))
    )
    return _check(info, info.computers, info.users, int(found or 0), 0)
