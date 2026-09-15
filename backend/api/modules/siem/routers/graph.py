"""Граф зависимостей правило -> правило."""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser, RuleDependency, Snapshot
from api.deps import get_current_user

router = APIRouter(prefix="/graph", tags=["graph"])


@router.get("")
def get_graph(
    snapshot_id: int = Query(...),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    snapshot = db.get(Snapshot, snapshot_id)
    if snapshot is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")

    edges = (
        db.query(RuleDependency)
        .filter(RuleDependency.snapshot_id == snapshot_id)
        .order_by(RuleDependency.parent, RuleDependency.child)
        .all()
    )
    return {
        "edges": [{"parent": e.parent, "child": e.child} for e in edges],
        "unresolved": json.loads(snapshot.unresolved_json),
    }
