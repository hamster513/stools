"""Журнал изменений сервера: записи по всем снапшотам (от новых к старым) со сводом каждого снапшота."""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import ColumnElement, func, select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.ksc.models import KscChange, KscServer, KscSnapshot
from api.modules.ksc.services.changes import summary_view
from api.platform.filters import multi, multi_int

router = APIRouter(tags=["ksc"])

MAX_LIMIT = 1000


@router.get("/servers/{server_id}/changes")
def list_changes(
    server_id: int,
    kind: str = "",
    action: str = "",
    policy_id: str | None = None,
    snapshot_id: str | None = None,
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Фасеты `kind, action, policy_id, snapshot_id` — значения через запятую, внутри фасета «или»."""
    kinds, actions, policy_ids, snapshot_ids = multi(kind), multi(action), multi_int(policy_id), multi_int(snapshot_id)
    if db.get(KscServer, server_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="сервер не найден")
    snapshots = list(
        db.execute(
            select(KscSnapshot).where(KscSnapshot.server_id == server_id).order_by(KscSnapshot.collected_at.desc(), KscSnapshot.id.desc())
        ).scalars()
    )
    conditions: list[ColumnElement[bool]] = [KscChange.snapshot_id.in_([s.id for s in snapshots])]
    if kinds is not None:
        conditions.append(KscChange.kind.in_(sorted(kinds)))
    if actions is not None:
        conditions.append(KscChange.action.in_(sorted(actions)))
    if policy_ids is not None:
        conditions.append(KscChange.policy_id.in_(sorted(policy_ids)))
    if snapshot_ids is not None:
        conditions.append(KscChange.snapshot_id.in_(sorted(snapshot_ids)))
    total = db.scalar(select(func.count()).select_from(KscChange).where(*conditions)) or 0
    rows = db.execute(
        select(KscChange, KscSnapshot.collected_at).join(KscSnapshot, KscSnapshot.id == KscChange.snapshot_id).where(*conditions)
        .order_by(KscSnapshot.collected_at.desc(), KscChange.snapshot_id.desc(), KscChange.id).limit(limit).offset(offset)
    ).all()
    facets: dict[str, dict[str, int]] | None = None
    if offset == 0:
        facets = {
            name: {value: n for value, n in db.execute(select(column, func.count()).where(*conditions).group_by(column).order_by(column)).all()}
            for name, column in (("kind", KscChange.kind), ("action", KscChange.action))
        }
    return {
        "total": total,
        "items": [
            {"id": c.id, "snapshot_id": c.snapshot_id, "collected_at": collected_at.isoformat(), "kind": c.kind, "action": c.action,
             "policy_id": c.policy_id, "policy_name": c.policy_name, "profile": c.profile, "section": c.section, "path": c.path,
             "before": json.loads(c.before_json or "null"), "after": json.loads(c.after_json or "null")}
            for c, collected_at in rows
        ],
        "facets": facets,
        "snapshots": [{"id": s.id, "collected_at": s.collected_at.isoformat(), **summary_view(s)} for s in snapshots],
    }
