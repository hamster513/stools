"""Пары правил-клонов."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser, ClonePairRow
from api.deps import get_current_user
from api.modules.siem.services import clones as clones_service

router = APIRouter(prefix="/clones", tags=["clones"])


class ClonePairItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    rule_a: str
    rule_b: str
    similarity: float


@router.get("", response_model=list[ClonePairItem])
def list_clones(
    snapshot_id: int = Query(...),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> list[ClonePairRow]:
    return (
        db.query(ClonePairRow)
        .filter(ClonePairRow.snapshot_id == snapshot_id)
        .order_by(ClonePairRow.similarity.desc(), ClonePairRow.rule_a, ClonePairRow.rule_b)
        .all()
    )


@router.get("/compare")
def compare_clones(
    snapshot_id: int = Query(...),
    rule_a: str = Query(...),
    rule_b: str = Query(...),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Две стороны пары, расхождение сигнатур и тела построчно бок о бок."""
    return clones_service.compare(db, snapshot_id, rule_a, rule_b)
