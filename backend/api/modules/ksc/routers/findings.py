"""Находки снапшота с фасетами, статусами и вердиктами."""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.ksc.core.checks import CHECK_BY_CODE
from api.modules.ksc.core.findings import SEVERITIES, SEVERITY_RANK
from api.modules.ksc.models import KscFinding, KscSnapshot, KscVerdict
from api.modules.ksc.services.snapshots import accepted_keys, compare

router = APIRouter(tags=["ksc"])

STATUSES = ("new", "persisting", "accepted", "fixed")
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
    snap = db.get(KscSnapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    if status_ is not None and status_ not in STATUSES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="неизвестный статус")
    cmp_ = compare(db, snap)
    accepted = accepted_keys(db, snap.server_id)

    # Находок у сервера тысячи, не миллионы: статусы и фасеты считаются
    # в памяти, а не в SQL, — статус зависит от двух других снапшотов.
    if status_ == "fixed":
        rows = list(cmp_.fixed)
        statuses = {f.id: "fixed" for f in rows}
    else:
        rows = list(db.execute(select(KscFinding).where(KscFinding.snapshot_id == snapshot_id)).scalars())
        statuses = {
            f.id: "accepted" if f.key in accepted else "new" if f.key in cmp_.new_keys else "persisting" for f in rows
        }

    def keep(f: KscFinding) -> bool:
        if check and f.check != check:
            return False
        if severity and f.severity != severity:
            return False
        if allowlisted is not None and f.allowlisted != allowlisted:
            return False
        if status_ and status_ != "fixed" and statuses[f.id] != status_:
            return False
        if q:
            needle = q.lower()
            check_title = CHECK_BY_CODE[f.check].title if f.check in CHECK_BY_CODE else f.check
            if needle not in f.host.lower() and needle not in f.target.lower() and needle not in check_title.lower():
                return False
        return True

    filtered = [f for f in rows if keep(f)]
    filtered.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.check, f.host.lower(), f.target.lower()))
    facets: dict[str, dict[str, int]] = {"check": {}, "severity": dict.fromkeys(SEVERITIES, 0), "status": dict.fromkeys(STATUSES, 0), "allowlisted": {"yes": 0, "no": 0}}
    for f in filtered:
        facets["check"][f.check] = facets["check"].get(f.check, 0) + 1
        facets["severity"][f.severity] = facets["severity"].get(f.severity, 0) + 1
        facets["status"][statuses[f.id]] += 1
        facets["allowlisted"]["yes" if f.allowlisted else "no"] += 1
    if status_ != "fixed":
        facets["status"]["fixed"] = len(cmp_.fixed)
    page = filtered[offset : offset + limit]
    return {
        "total": len(filtered),
        "items": [_item(f, statuses[f.id]) for f in page],
        "facets": facets if offset == 0 else None,
        "compared_to": {"previous_id": cmp_.previous_id, "collected_at": cmp_.previous_collected_at.isoformat() if cmp_.previous_collected_at else None, "new": cmp_.new, "fixed": len(cmp_.fixed)},
        "check_titles": {code: spec.title for code, spec in CHECK_BY_CODE.items()},
    }


@router.get("/snapshots/{snapshot_id}/findings/{key}")
def finding_detail(snapshot_id: int, key: str, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    snap = db.get(KscSnapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    f = db.execute(select(KscFinding).where(KscFinding.snapshot_id == snapshot_id, KscFinding.key == key)).scalars().first()
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="находка не найдена")
    cmp_ = compare(db, snap)
    verdict = db.get(KscVerdict, (snap.server_id, key))
    status_ = "accepted" if verdict else "new" if key in cmp_.new_keys else "persisting"
    history = db.execute(
        select(KscSnapshot.id, KscSnapshot.collected_at)
        .join(KscFinding, KscFinding.snapshot_id == KscSnapshot.id)
        .where(KscSnapshot.server_id == snap.server_id, KscFinding.key == key)
        .order_by(KscSnapshot.collected_at.desc())
    ).all()
    spec = CHECK_BY_CODE.get(f.check)
    return {
        **_item(f, status_),
        "description": spec.description if spec else "",
        "history": [{"snapshot_id": sid, "collected_at": at.isoformat()} for sid, at in history],
        "verdict": {"status": verdict.status, "reason": verdict.reason, "decided_by": verdict.decided_by, "decided_at": verdict.decided_at.isoformat()} if verdict else None,
    }


class VerdictRequest(BaseModel):
    server_id: int
    reason: str = ""


@router.put("/verdicts/{key}", status_code=status.HTTP_204_NO_CONTENT)
def set_verdict(key: str, payload: VerdictRequest, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> None:
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
