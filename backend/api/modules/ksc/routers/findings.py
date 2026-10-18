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
from api.modules.ksc.core.checks import CHECK_BY_CODE
from api.modules.ksc.core.findings import SEVERITIES, SEVERITY_RANK
from api.modules.ksc.findings_adapter import ADAPTER
from api.modules.ksc.models import KscFinding, KscSnapshot
from api.modules.ksc.services.snapshots import compare
from api.platform.export import Column, export_response

router = APIRouter(tags=["ksc"])

MAX_LIMIT = 1000


def _item(f: KscFinding) -> dict[str, Any]:
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
        "details": json.loads(f.details_json or "{}"),
    }


def _haystack(f: KscFinding) -> tuple[str, ...]:
    return (f.host, f.target, CHECK_BY_CODE[f.check].title if f.check in CHECK_BY_CODE else f.check)


def _sort_key(f: KscFinding) -> tuple[Any, ...]:
    return (SEVERITY_RANK.get(f.severity, 9), f.check, f.host.lower(), f.target.lower())


CHECK_TITLES = {code: spec.title for code, spec in CHECK_BY_CODE.items()}


@router.get("/snapshots/{snapshot_id}/findings")
def list_findings(
    snapshot_id: int,
    flt: FindingFilter = Depends(finding_params),
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    snap = snapshot_or_404(db, KscSnapshot, snapshot_id)
    cmp_ = compare(db, snap)
    # Находок у сервера тысячи, не миллионы: статусы и фасеты считаются в памяти.
    found = finding_rows(db, ADAPTER, snap, cmp_, flt, first_page=offset == 0)
    return findings_page(
        db, ADAPTER, snap.server_id, found, flt, cmp_, offset=offset, limit=limit, haystack=_haystack, sort_key=_sort_key,
        item=_item, severities=SEVERITIES, check_titles=CHECK_TITLES,
    )


#: Подписи — как в таблице на экране; «Возраст» — числом дней, «Впервые» — датой.
EXPORT_COLUMNS = [
    Column("severity", "Серьёзность"), Column("check", "Проверка"), Column("host", "Хост"), Column("target", "Цель"),
    Column("status", "Статус"), Column("age", "Возраст (дней)"), Column("assignee", "Назначено"), Column("first_seen", "Впервые"),
]


@router.get("/snapshots/{snapshot_id}/findings/export")
def export_findings(
    snapshot_id: int,
    flt: FindingFilter = Depends(finding_params),
    fmt: str = Query(default="csv", alias="format"),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """Все находки под фильтрами списка, в его порядке (объявлена до карточки `/findings/{key}`)."""
    snap = snapshot_or_404(db, KscSnapshot, snapshot_id)
    cmp_ = compare(db, snap)
    found = finding_rows(db, ADAPTER, snap, cmp_, flt, first_page=False)
    rows = finding_export_rows(db, ADAPTER, snap.server_id, found, flt, haystack=_haystack, sort_key=_sort_key,
                               check_titles=CHECK_TITLES, extra=lambda f: {"host": f.host})
    return export_response(fmt, EXPORT_COLUMNS, rows, module="ksc", name="findings")


@router.get("/snapshots/{snapshot_id}/findings/{key}")
def finding_detail(snapshot_id: int, key: str, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    snap = snapshot_or_404(db, KscSnapshot, snapshot_id)
    f, fields = finding_detail_row(db, ADAPTER, snap, key, compare(db, snap))
    spec = CHECK_BY_CODE.get(f.check)
    return {
        **_item(f),
        **fields,
        "description": spec.description if spec else "",
        "history": finding_history(db, KscSnapshot, KscFinding, KscSnapshot.server_id, snap.server_id, key),
    }
