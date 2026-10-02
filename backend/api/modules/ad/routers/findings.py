"""Находки снапшота с фасетами и статусами (статусы — общий механизм платформы)."""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from api.collector_routes import (
    finding_detail_row,
    finding_filter,
    finding_history,
    finding_rows,
    findings_page,
    snapshot_or_404,
)
from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.ad.core.checks import CHECK_BY_CODE
from api.modules.ad.core.findings import SEVERITIES, SEVERITY_RANK
from api.modules.ad.findings_adapter import ADAPTER
from api.modules.ad.models import AdFinding, AdSnapshot
from api.modules.ad.services.snapshots import compare

router = APIRouter(tags=["ad"])

MAX_LIMIT = 1000


def _item(f: AdFinding) -> dict[str, Any]:
    return {
        "id": f.id,
        "key": f.key,
        "check": f.check,
        "check_title": CHECK_BY_CODE[f.check].title if f.check in CHECK_BY_CODE else f.check,
        "severity": f.severity,
        "severity_original": f.severity_original,
        "identity": f.identity,
        "identity_sid": f.identity_sid,
        "target": f.target,
        "right": f.right,
        "allowlisted": f.allowlisted,
        "details": json.loads(f.details_json or "{}"),
    }


@router.get("/snapshots/{snapshot_id}/findings")
def list_findings(
    snapshot_id: int,
    check: str | None = None,
    severity: str | None = None,
    status_: str | None = Query(default=None, alias="status"),
    delta: str | None = None,
    assignee: str | None = None,
    overdue: bool = False,
    risk_expiring: bool = False,
    allowlisted: bool | None = None,
    q: str | None = None,
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    snap = snapshot_or_404(db, AdSnapshot, snapshot_id)
    flt = finding_filter(user, check=check, severity=severity, allowlisted=allowlisted, status_=status_, delta=delta,
                         assignee=assignee, overdue=overdue, risk_expiring=risk_expiring, q=q)
    cmp_ = compare(db, snap)
    # Находок у домена тысячи, не миллионы: статусы и фасеты считаются в памяти.
    rows = finding_rows(db, ADAPTER, snap, cmp_)
    return findings_page(
        db, ADAPTER, snap.domain_id, rows, flt, cmp_, offset=offset, limit=limit,
        haystack=lambda f: (f.identity, f.target, f.right),
        sort_key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.check, f.identity.lower(), f.target.lower()),
        item=_item, severities=SEVERITIES, check_titles={code: spec.title for code, spec in CHECK_BY_CODE.items()},
    )


@router.get("/snapshots/{snapshot_id}/findings/{key}")
def finding_detail(snapshot_id: int, key: str, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    snap = snapshot_or_404(db, AdSnapshot, snapshot_id)
    f, fields = finding_detail_row(db, ADAPTER, snap, key, compare(db, snap))
    spec = CHECK_BY_CODE.get(f.check)
    return {
        **_item(f),
        **fields,
        "description": spec.description if spec else "",
        "history": finding_history(db, AdSnapshot, AdFinding, AdSnapshot.domain_id, snap.domain_id, key),
    }
