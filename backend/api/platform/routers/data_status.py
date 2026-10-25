"""Ручка сводки свежести данных: /api/settings/data-status.

Читать её может любая роль (GET под /api/settings/ открыт правилом api/rbac.py).
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.platform.data_status import collect

router = APIRouter(prefix="/data-status", tags=["settings"])


@router.get("")
def data_status(
    db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)
) -> dict[str, Any]:
    """Свежесть справочников, снимков и источников всех модулей."""
    items = []
    for item in collect(db):
        row = asdict(item)
        row["updated_at"] = item.updated_at.isoformat() if item.updated_at else None
        items.append(row)
    return {"items": items}
