"""Находки снапшота с фасетами, статусами и вердиктами."""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.collector_routes import (
    FINDING_STATUSES,
    filter_findings,
    finding_history,
    finding_or_404,
    finding_rows,
    findings_page,
    snapshot_or_404,
    verdict_view,
)
from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.ksc.core.checks import CHECK_BY_CODE
from api.modules.ksc.core.findings import SEVERITIES, SEVERITY_RANK
from api.modules.ksc.models import KscFinding, KscServer, KscSnapshot, KscVerdict
from api.modules.ksc.services.snapshots import accepted_keys, compare

router = APIRouter(tags=["ksc"])

MAX_LIMIT = 1000


def _item(f: KscFinding, status_: str) -> dict[str, Any]:
    return {
        "id": f.id,
        "key": f.key,
        "check": f.check,
        "check_title": CHECK_BY_CODE[f.check].title if f.check in CHECK_BY_CODE else f.check,
        "severity": f.severity,
        "severity_original": f.severity_original,
        "host": f.host,
        "target": f.target,
        "allowlisted": f.allowlisted,
        "status": status_,
        "details": json.loads(f.details_json or "{}"),
    }


@router.get("/snapshots/{snapshot_id}/findings")
def list_findings(
    snapshot_id: int,
    check: str | None = None,
    severity: str | None = None,
    status_: str | None = Query(default=None, alias="status"),
    allowlisted: bool | None = None,
    q: str | None = None,
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    snap = snapshot_or_404(db, KscSnapshot, snapshot_id)
    if status_ is not None and status_ not in FINDING_STATUSES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="неизвестный статус")
    cmp_ = compare(db, snap)
    accepted = accepted_keys(db, snap.server_id)

    # Находок у сервера тысячи, не миллионы: статусы и фасеты считаются
    # в памяти, а не в SQL, — статус зависит от двух других снапшотов.
    rows, statuses = finding_rows(db, KscFinding, snapshot_id, cmp_, accepted, status_)
    filtered = filter_findings(
        rows, statuses, check=check, severity=severity, allowlisted=allowlisted, status_=status_, q=q,
        haystack=lambda f: (f.host, f.target, CHECK_BY_CODE[f.check].title if f.check in CHECK_BY_CODE else f.check),
    )
    filtered.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.check, f.host.lower(), f.target.lower()))
    return findings_page(
        filtered, statuses, cmp_, status_=status_, offset=offset, limit=limit, item=_item, severities=SEVERITIES,
        check_titles={code: spec.title for code, spec in CHECK_BY_CODE.items()},
    )


@router.get("/snapshots/{snapshot_id}/findings/{key}")
def finding_detail(snapshot_id: int, key: str, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    snap = snapshot_or_404(db, KscSnapshot, snapshot_id)
    f = finding_or_404(db, KscFinding, snapshot_id, key)
    cmp_ = compare(db, snap)
    verdict = db.get(KscVerdict, (snap.server_id, key))
    status_ = "accepted" if verdict else "new" if key in cmp_.new_keys else "persisting"
    spec = CHECK_BY_CODE.get(f.check)
    return {
        **_item(f, status_),
        "description": spec.description if spec else "",
        "history": finding_history(db, KscSnapshot, KscFinding, KscSnapshot.server_id, snap.server_id, key),
        "verdict": verdict_view(verdict),
    }


class VerdictRequest(BaseModel):
    server_id: int
    reason: str = ""


@router.put("/verdicts/{key}", status_code=status.HTTP_204_NO_CONTENT)
def set_verdict(key: str, payload: VerdictRequest, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> None:
    if db.get(KscServer, payload.server_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="сервер не найден")
    v = db.get(KscVerdict, (payload.server_id, key))
    if v is None:
        v = KscVerdict(server_id=payload.server_id, key=key)
        db.add(v)
    v.status = "accepted"
    v.reason = payload.reason
    v.decided_by = user.login
    v.decided_at = dt.datetime.now(dt.UTC)
    db.commit()


@router.delete("/verdicts/{key}", status_code=status.HTTP_204_NO_CONTENT)
def drop_verdict(key: str, server_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> None:
    v = db.get(KscVerdict, (server_id, key))
    if v is not None:
        db.delete(v)
        db.commit()
