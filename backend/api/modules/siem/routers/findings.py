"""Находки: список с фасетами и деталь по запросу.

Список НИКОГДА не содержит значений находок (контракт, «Общие правила»):
`FindingListItem` ниже физически не может нести поле `value` — сокрытие
проверяется отдельным тестом
(tests/api/test_findings_values_hidden.py), а не соглашением. Ключ находки
несёт не хеш значения, а подпись с солью установки (findings_adapter).

Статусы, исполнитель и сроки — общие статусы находок платформы: меняются
через /api/findings/*, здесь только отбираются и показываются.
"""
from __future__ import annotations

import datetime as dt
import json
from collections.abc import Sequence
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser, DivergenceRow
from api.db.models import Finding as FindingRow
from api.deps import get_current_user
from api.modules.siem.findings_adapter import ADAPTER, SCOPE
from api.modules.siem.services.facets import FindingFilters, FindingQuery, ListRow
from api.platform.filters import multi, multi_int
from api.platform.findings.core import OPEN, STATUS_TITLES, STATUSES

router = APIRouter(prefix="/findings", tags=["findings"])


class FindingListItem(BaseModel):
    id: int
    #: Ключ находки для статусов платформы: (object_uuid, kind, field, значение) под подписью.
    key: str
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
    shape: str | None = None
    table_name: str | None = None
    status: str
    status_title: str
    assignee: str | None = None
    assignee_name: str | None = None
    due_date: dt.date | None = None
    overdue: bool = False
    risk_until: dt.date | None = None
    first_seen_at: dt.datetime | None = None
    age_days: int | None = None
    #: Находки нет в активном снапшоте: показана по последнему снапшоту, где была.
    gone: bool = False
    has_value: bool


class FindingListResponse(BaseModel):
    total: int
    items: list[FindingListItem]
    facets: dict[str, dict[str, int]]
    #: Снапшот — активный (последний разобранный); у прочих статусы всё равно на сегодня.
    is_latest: bool
    statuses_as_of: Literal["today"] = "today"
    #: Соли ключей нет, а решения есть: статусы не сопоставить, показаны как «Новая».
    status_keys_broken: bool = False


def _statuses(raw: str | None, risk_expiring: bool) -> frozenset[str]:
    """`status` — коды через запятую или `all`; не задан — открытые, а с «риск
    истекает» — принятые: среди открытых такого риска не бывает."""
    if raw == "all":
        return frozenset(STATUSES)
    picked = multi(raw)
    if picked is None:
        return frozenset({"risk_accepted"}) if risk_expiring else OPEN
    unknown = picked - set(STATUSES)
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"неизвестный статус: {', '.join(sorted(unknown))}")
    return picked


def _items(db: Session, rows: Sequence[ListRow]) -> list[FindingListItem]:
    """Строки страницы с полями состояния (спека статусов §5). Возраст без строки
    состояния — по снапшотам, одним запросом на страницу."""
    seen = ADAPTER.first_seen_many(db, SCOPE, [r.key for r in rows if r.state is None or r.state.first_seen_at is None])
    logins = {r.assignee for r in rows if r.assignee}
    names = {u.login: u.display_name or u.login for u in db.scalars(select(AppUser).where(AppUser.login.in_(logins)))} if logins else {}
    now = dt.datetime.now(dt.UTC)
    items = []
    for r in rows:
        f, st = r.finding, r.state
        first = (st.first_seen_at if st is not None else None) or seen.get(r.key)
        items.append(FindingListItem(
            id=f.id, key=r.key, kind=f.kind, severity=f.severity, object_type=f.object_type,
            object_name=f.object_name, object_uuid=f.object_uuid, field=f.field, polarity=f.polarity,
            in_table=f.in_table, shape=f.shape, table_name=f.table_name,
            status=r.status, status_title=STATUS_TITLES[r.status], assignee=r.assignee,
            assignee_name=names.get(r.assignee, r.assignee) if r.assignee else None,
            due_date=st.due_date if st is not None else None, overdue=r.overdue,
            risk_until=st.risk_until if st is not None else None,
            first_seen_at=first, age_days=(now - first).days if first else None, gone=r.gone,
            has_value=f.has_value,
        ))
    return items


class FindingDetail(BaseModel):
    value: str
    body_excerpt: str | None = None
    table_name: str | None = None
    affected_rules: list[str]


@router.get("", response_model=FindingListResponse)
def list_findings(
    snapshot_id: int = Query(...),
    kind: str | None = None,
    polarity: str | None = None,
    object_type: str | None = None,
    in_table: bool | None = None,
    shape: str | None = None,
    status_: str | None = Query(default=None, alias="status"),
    assignee: str | None = Query(default=None, max_length=255),
    overdue: bool = False,
    risk_expiring: bool = False,
    key: str | None = Query(default=None, max_length=128),
    field: str | None = None,
    object_uuid: str | None = None,
    q: str | None = None,
    sort: str = "kind",
    order: str = "asc",
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> FindingListResponse:
    """По умолчанию — открытые статусы; `status` — коды через запятую или `all`;
    `assignee` — `me`, `none` или логин. Фасеты `kind, polarity, object_type, shape, field,
    assignee` — значения через запятую, внутри фасета «или»."""
    who = multi(assignee)
    filters = FindingFilters(
        snapshot_id=snapshot_id,
        kind=multi_int(kind),
        polarity=multi(polarity),
        object_type=multi(object_type),
        in_table=in_table,
        shape=multi(shape),
        statuses=_statuses(status_, risk_expiring),
        field=multi(field),
        object_uuid=object_uuid,
        key=key,
        assignee=frozenset(user.login if a == "me" else a for a in who) if who else None,
        overdue=overdue,
        risk_expiring=risk_expiring,
        q=q,
    )
    query = FindingQuery(db, filters)
    rows = query.page(sort=sort, order=order, limit=limit, offset=offset)
    return FindingListResponse(total=query.total(), items=_items(db, rows), facets=query.facets(),
                               is_latest=query.is_latest, status_keys_broken=query.keys_broken)


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
