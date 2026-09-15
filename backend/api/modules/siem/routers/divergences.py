"""Расхождения «правило ↔ табличный список». Значение находки в список не
входит — контракт не даёт для расхождений ручку /detail, значение смотрят
через /api/findings/{id}/detail по классу 1."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser, DivergenceRow
from api.deps import get_current_user

router = APIRouter(prefix="/divergences", tags=["divergences"])


class DivergenceItem(BaseModel):
    id: int
    field: str
    table_name: str
    hardcoded_in: str
    blast_radius: int
    has_value: bool


class DivergenceListResponse(BaseModel):
    total: int
    items: list[DivergenceItem]


@router.get("", response_model=DivergenceListResponse)
def list_divergences(
    snapshot_id: int = Query(...),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> DivergenceListResponse:
    base = db.query(DivergenceRow).filter(DivergenceRow.snapshot_id == snapshot_id)
    total = base.count()
    rows = (
        base.order_by(DivergenceRow.blast_radius.desc(), DivergenceRow.id)
        .offset(offset)
        .limit(limit)
        .all()
    )
    items = [
        DivergenceItem(
            id=r.id,
            field=r.field,
            table_name=r.table_name,
            hardcoded_in=r.hardcoded_in,
            blast_radius=r.blast_radius,
            has_value=bool(r.value),
        )
        for r in rows
    ]
    return DivergenceListResponse(total=total, items=items)
