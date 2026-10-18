"""Находки снапшота с фасетами и статусами (статусы — общий механизм платформы)."""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from api.collector_routes import (
    FindingFilter,
    finding_detail_row,
    finding_export_rows,
    finding_history,
    finding_params,
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
from api.platform.export import Column, export_response

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


def _haystack(f: AdFinding) -> tuple[str, ...]:
    return (f.identity, f.target, f.right)


def _sort_key(f: AdFinding) -> tuple[Any, ...]:
    return (SEVERITY_RANK.get(f.severity, 9), f.check, f.identity.lower(), f.target.lower())


CHECK_TITLES = {code: spec.title for code, spec in CHECK_BY_CODE.items()}


@router.get("/snapshots/{snapshot_id}/findings")
def list_findings(
    snapshot_id: int,
    flt: FindingFilter = Depends(finding_params),
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    snap = snapshot_or_404(db, AdSnapshot, snapshot_id)
    cmp_ = compare(db, snap)
    # Находок у домена тысячи, не миллионы: статусы и фасеты считаются в памяти.
    found = finding_rows(db, ADAPTER, snap, cmp_, flt, first_page=offset == 0)
    return findings_page(
        db, ADAPTER, snap.domain_id, found, flt, cmp_, offset=offset, limit=limit, haystack=_haystack, sort_key=_sort_key,
        item=_item, severities=SEVERITIES, check_titles=CHECK_TITLES,
    )


def _detail(f: AdFinding) -> str:
    """Колонка «Право / детали» — как на экране: право, иначе текст деталей, иначе тип делегирования."""
    details = json.loads(f.details_json or "{}")
    for value in (f.right, details.get("details"), details.get("delegation_type")):
        if isinstance(value, str) and value:
            return value
    return ""


#: Подписи — как в таблице на экране; «Возраст» — числом дней, «Впервые» — датой.
EXPORT_COLUMNS = [
    Column("severity", "Серьёзность"), Column("check", "Проверка"), Column("identity", "Identity"), Column("target", "Цель"),
    Column("details", "Право/детали"), Column("status", "Статус"), Column("age", "Возраст (дней)"), Column("assignee", "Назначено"),
    Column("first_seen", "Впервые"),
]


@router.get("/snapshots/{snapshot_id}/findings/export")
def export_findings(
    snapshot_id: int,
    flt: FindingFilter = Depends(finding_params),
    fmt: str = Query(default="csv", alias="format"),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """Все находки под фильтрами списка, в его порядке (объявлена до карточки `/findings/{key}`)."""
    snap = snapshot_or_404(db, AdSnapshot, snapshot_id)
    cmp_ = compare(db, snap)
    found = finding_rows(db, ADAPTER, snap, cmp_, flt, first_page=False)
    rows = finding_export_rows(db, ADAPTER, snap.domain_id, found, flt, haystack=_haystack, sort_key=_sort_key,
                               check_titles=CHECK_TITLES, extra=lambda f: {"identity": f.identity, "details": _detail(f)})
    return export_response(fmt, EXPORT_COLUMNS, rows, module="ad", name="findings")


@router.get("/snapshots/{snapshot_id}/findings/{key}")
def finding_detail(snapshot_id: int, key: str, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    snap = snapshot_or_404(db, AdSnapshot, snapshot_id)
    f, fields = finding_detail_row(db, ADAPTER, snap, key, compare(db, snap))
    spec = CHECK_BY_CODE.get(f.check)
    return {
        **_item(f),
        **fields,
        "description": spec.description if spec else "",
        "guidance": {
            "remediation": spec.remediation if spec else "",
            "references": [{"title": t, "url": u} for t, u in spec.references] if spec else [],
        },
        "history": finding_history(db, AdSnapshot, AdFinding, AdSnapshot.domain_id, snap.domain_id, key),
    }
