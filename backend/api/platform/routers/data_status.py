"""Ручка сводки свежести данных: /api/settings/data-status.

Читать её может любой вошедший (api/rbac.py); строки — только модулей, где у него есть чтение.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.platform.data_status import collect
from api.platform.services.access import Access, allows
from api.rbac import current_access

router = APIRouter(prefix="/data-status", tags=["settings"])


@router.get("")
def data_status(db: Session = Depends(get_db), access: Access = Depends(current_access)) -> dict[str, Any]:
    """Свежесть справочников, снимков и источников модулей, открытых вызывающему на чтение."""
    items = []
    for item in collect(db):
        if not allows(access, item.module, "read"):
            continue
        row = asdict(item)
        row["updated_at"] = item.updated_at.isoformat() if item.updated_at else None
        items.append(row)
    return {"items": items}
