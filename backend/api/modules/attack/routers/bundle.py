"""Справочник техник ATT&CK — для ручной разметки.

База знаний общая для всех модулей: разметка правил, техники VM и AD
ссылаются на одни и те же идентификаторы. Обновление матрицы и её перевод
живут в общих настройках (`/api/settings/attack`), потому что это дело
администратора; здесь остаётся только чтение справочника.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.attack.services.attack_bundle import current as current_bundle

router = APIRouter(tags=["attack"])


@router.get("/techniques")
def techniques(
    q: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Справочник техник с русскими описаниями — для ручной разметки."""
    needle = (q or "").strip().lower()
    items = []
    for technique in current_bundle(db).techniques:
        haystack = " ".join(
            filter(None, [technique.technique_id, technique.name, technique.name_ru])
        ).lower()
        if needle and needle not in haystack:
            continue
        items.append(
            {
                "technique_id": technique.technique_id,
                "name": technique.name,
                "name_ru": technique.name_ru,
                "description_ru": technique.description_ru,
                "tactics": technique.tactics,
                "is_subtechnique": technique.is_subtechnique,
                "parent_id": technique.parent_id,
            }
        )
        if len(items) >= limit:
            break
    return {"total": len(items), "items": items}
