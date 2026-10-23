"""Расхождения активов на общих статусах находок (спека статусов §3).

Область одна (`scope_id = 0`), находка — расхождение актива, ключ —
`asset_id|code`, у расхождений полей — `asset_id|code|source|field`
(`core.discrepancies.finding_key`). Свежие данные — расхождения всех
активов, посчитанные тем же расчётом, что список и карточка
(`services.assets.current_discrepancies`): сами расхождения не хранятся,
поэтому истории у них нет — возраста нет (`first_seen_many` → `{}`), а
исчезнувшее расхождение без решения следа не оставляет, как пара VM.

Сверка (`reconcile`) — в конце синхронизации, DNS, RackTables и после ручных
правок реестра, которые меняют расхождения (объединение, отвязка,
закрепление поля, смена сети актива).
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Iterable

from sqlalchemy.orm import Session

from api.modules.assets.core.discrepancies import finding_key
from api.modules.assets.services.assets import (
    FINDINGS_MODULE,
    FINDINGS_SCOPE,
    current_discrepancies,
    finding_title,
)
from api.platform.findings.adapters import CurrentFinding, safe_reconcile

MODULE = FINDINGS_MODULE
SCOPE = FINDINGS_SCOPE


class AssetsFindingAdapter:
    module = MODULE

    def scopes(self, db: Session) -> Iterable[int]:
        return [SCOPE]

    def has_scope(self, db: Session, scope_id: int) -> bool:
        return scope_id == SCOPE

    def current(self, db: Session, scope_id: int) -> Iterable[CurrentFinding] | None:
        """Расхождения всех активов; в реестре нет активов — данных нет (None). Тяжести у
        расхождений нет: severity пустая."""
        if scope_id != SCOPE:
            return None
        found = current_discrepancies(db)
        if found is None:
            return None
        out: dict[str, CurrentFinding] = {}
        for asset, discrepancies in found:
            for d in discrepancies:
                key = finding_key(asset.id, d)
                out.setdefault(key, CurrentFinding(key=key, title=finding_title(asset, d), severity=""))
        return list(out.values())

    def first_seen_many(self, db: Session, scope_id: int, keys: Iterable[str]) -> dict[str, dt.datetime]:
        return {}

    def first_seen(self, db: Session, scope_id: int, key: str) -> dt.datetime | None:
        return None

    def link(self, scope_id: int, key: str) -> str:
        """Карточка актива в списке: страница открывает её по `?asset=`."""
        return f"/assets/list?asset={key.partition('|')[0]}"


ADAPTER = AssetsFindingAdapter()


def reconcile(db: Session, ref: str) -> None:
    """Сверка статусов расхождений — после commit данных модуля; сбой не роняет задачу или запрос."""
    safe_reconcile(db, MODULE, SCOPE, ref)
