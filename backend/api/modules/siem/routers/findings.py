"""Находки: список с фасетами, деталь по запросу, вердикт.

Список НИКОГДА не содержит значений находок (контракт, «Общие правила»):
`FindingListItem` ниже физически не может нести поле `value` — сокрытие
проверяется отдельным тестом
(tests/api/test_findings_values_hidden.py), а не соглашением.
"""
from __future__ import annotations

import datetime as dt
import json

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser, DivergenceRow, FindingVerdict
from api.db.models import Finding as FindingRow
from api.deps import get_current_user
from api.modules.siem.services.facets import FindingFilters, FindingQuery
from api.security import hash_value

router = APIRouter(prefix="/findings", tags=["findings"])

_VALID_STATUS = {"open", "accepted", "in_progress"}


class FindingListItem(BaseModel):
    id: int
    kind: int
    severity: str
    object_type: str
    object_name: str
    object_uuid: str
    field: str
    polarity: str
    in_table: bool
    #: Форма значения независимо от класса: сетевое имя, попавшее
    #: в «дублирует список», иначе в интерфейсе не найти.
    shape: str | None
    table_name: str | None
    status: str
    has_value: bool


class FindingListResponse(BaseModel):
    total: int
    items: list[FindingListItem]
    facets: dict[str, dict[str, int]]


class FindingDetail(BaseModel):
    value: str
    body_excerpt: str | None
    table_name: str | None
    affected_rules: list[str]


class VerdictRequest(BaseModel):
    finding_id: int
    status: str
    reason: str | None = None


@router.get("", response_model=FindingListResponse)
def list_findings(
    snapshot_id: int = Query(...),
    kind: int | None = None,
    polarity: str | None = None,
    object_type: str | None = None,
    in_table: bool | None = None,
    shape: str | None = None,
    status_: str | None = Query(default=None, alias="status"),
    field: str | None = None,
    object_uuid: str | None = None,
    q: str | None = None,
    sort: str = "kind",
    order: str = "asc",
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> FindingListResponse:
    filters = FindingFilters(
        snapshot_id=snapshot_id,
        kind=kind,
        polarity=polarity,
        object_type=object_type,
        in_table=in_table,
        shape=shape,
        status=status_,
        field=field,
        object_uuid=object_uuid,
        q=q,
    )
    query = FindingQuery(db, filters)
    rows = query.page(sort=sort, order=order, limit=limit, offset=offset)
    items = [
        FindingListItem(
            id=r.finding.id,
            kind=r.finding.kind,
            severity=r.finding.severity,
            object_type=r.finding.object_type,
            object_name=r.finding.object_name,
            object_uuid=r.finding.object_uuid,
            field=r.finding.field,
            polarity=r.finding.polarity,
            in_table=r.finding.in_table,
            shape=r.finding.shape,
            table_name=r.finding.table_name,
            status=r.status,
            has_value=bool(r.finding.value),
        )
        for r in rows
    ]
    return FindingListResponse(total=query.total(), items=items, facets=query.facets())


@router.get("/{finding_id}/detail", response_model=FindingDetail)
def finding_detail(
    finding_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)
) -> FindingDetail:
    finding = db.get(FindingRow, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="находка не найдена")

    affected: list[str] = []
    if finding.in_table and finding.table_name:
        divergence = (
            db.query(DivergenceRow)
            .filter(
                DivergenceRow.snapshot_id == finding.snapshot_id,
                DivergenceRow.hardcoded_in == finding.object_name,
                DivergenceRow.field == finding.field,
                DivergenceRow.value == finding.value,
            )
            .one_or_none()
        )
        if divergence is not None:
            affected = json.loads(divergence.affected_rules_json)

    return FindingDetail(
        value=finding.value,
        body_excerpt=finding.body_excerpt,
        table_name=finding.table_name,
        affected_rules=affected,
    )


@router.post("/verdict", status_code=status.HTTP_204_NO_CONTENT)
def set_verdict(
    payload: VerdictRequest,
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> None:
    if payload.status not in _VALID_STATUS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"недопустимый статус: {payload.status}"
        )
    if payload.status == "accepted" and not (payload.reason or "").strip():
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="обоснование обязательно при статусе accepted",
        )

    finding = db.get(FindingRow, payload.finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="находка не найдена")

    value_hash = hash_value(finding.value)
    existing = (
        db.query(FindingVerdict)
        .filter_by(
            object_key=finding.object_uuid,
            key_kind="uuid",
            kind=finding.kind,
            field=finding.field,
            value_hash=value_hash,
        )
        .one_or_none()
    )

    if payload.status == "open":
        # Отсутствие строки означает open (спека §4.2) — явный сброс
        # вердикта удаляет запись, а не хранит статус "open" как значение.
        if existing is not None:
            db.delete(existing)
            db.commit()
        return

    if existing is None:
        existing = FindingVerdict(
            object_key=finding.object_uuid,
            key_kind="uuid",
            kind=finding.kind,
            field=finding.field,
            value_hash=value_hash,
        )
        db.add(existing)

    existing.status = payload.status
    existing.reason = payload.reason
    existing.decided_by = user.login
    existing.decided_at = dt.datetime.now(dt.UTC)
    db.commit()
