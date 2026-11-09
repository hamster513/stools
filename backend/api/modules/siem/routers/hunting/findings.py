"""Находки Threat Hunting: очередь ночных находок, карточка, события с выгрузкой.

Статус, исполнитель, срок, комментарии и массовые действия — общие ручки
платформы (`/api/findings/*`, модуль `siem_th`, область 1, ключ `th:<id>`);
здесь статус только отбирается и показывается — из строки платформы тем же
запросом, что и находки. События отдаются страницами по `position`: у
большого ханта их сотни тысяч, и ни список, ни карточка не тянут их целиком;
выгрузка читает их партиями, пока ответ уходит.
"""
from __future__ import annotations

import datetime as dt
import json
from collections.abc import Iterator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.siem.hunting.findings_adapter import (
    STATUS,
    ListFilter,
    base_query,
    conditions,
    facets,
    parse_statuses,
)
from api.modules.siem.hunting.models import ThDeepHunt, ThEvent, ThFinding, ThHunt, ThRun
from api.modules.siem.hunting.nightly import TH_MODULE, TH_SCOPE, finding_key
from api.platform.export import Column, export_response
from api.platform.filters import QueryList, QueryStatus, multi
from api.platform.findings.core import STATUS_TITLES, is_overdue
from api.platform.findings.models import FindingState
from api.platform.findings.service import effective_status, state_map, today

router = APIRouter(prefix="/findings", tags=["siem"])

#: Сортировки списка; при равенстве — по id в том же направлении.
SORTS: dict[str, Any] = {
    "created_at": ThFinding.created_at,
    "night": ThRun.target_date,
    "hunt": ThFinding.hunt_code,
    "query": ThFinding.query_id,
    "events": ThFinding.event_count,
    "status": STATUS,
}
EVENTS_PAGE_MAX = 1000
#: Выгрузка событий читает их партиями по столько строк.
EVENTS_BATCH = 500


class FindingItem(BaseModel):
    id: int
    hunt_code: str
    hunt_name: str
    query_id: str
    target_date: dt.date | None
    period_from: dt.datetime
    period_to: dt.datetime
    event_count: int
    limit_hit: bool
    created_at: dt.datetime
    status: str
    assignee: str | None
    due_date: dt.date | None
    overdue: bool


class FindingList(BaseModel):
    total: int
    items: list[FindingItem]
    facets: dict[str, dict[str, int]]


class ColumnView(BaseModel):
    field: str
    label: str


class StateBrief(BaseModel):
    """Статус платформы для шапки карточки; история и комментарии — `GET /api/findings/state`."""

    status: str
    status_title: str
    assignee: str | None = None
    due_date: dt.date | None = None
    overdue: bool = False
    risk_until: dt.date | None = None
    updated_by: str = ""
    updated_at: dt.datetime | None = None


class FindingDetail(FindingItem):
    saved_filter: dict | None = None
    key: str
    kind: str
    columns: list[ColumnView]
    events_purged: bool
    run_id: int | None
    deep_id: int | None
    partial: bool
    #: Только у находки большого ханта: окна, где запрос упёрся в предел.
    limit_hit_slices: int | None = None
    state: StateBrief


class EventsPage(BaseModel):
    total: int
    rows: list[list[Any]]


def _filter(
    status_: list[str] | None, hunt: list[str] | None, date_from: dt.date | None, date_to: dt.date | None,
    limit_hit: bool | None,
) -> ListFilter:
    try:
        statuses = parse_statuses(status_)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from None
    return ListFilter(statuses=statuses, hunts=multi(hunt), date_from=date_from, date_to=date_to, limit_hit=limit_hit)


_ROW = (ThFinding, ThHunt.name, ThRun.target_date, STATUS.label("status"), FindingState.assignee, FindingState.due_date)


def _ordered(f: ListFilter, sort: str, order: str) -> Any:
    column = SORTS.get(sort)
    if column is None or order not in ("asc", "desc"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            detail=f"сортировка: {', '.join(SORTS)}; порядок: asc или desc")
    keys = (column, ThFinding.id)
    by = [k.desc() for k in keys] if order == "desc" else [k.asc() for k in keys]
    return base_query(*_ROW).where(*conditions(f)).order_by(*by)


def _item(row: Any, on: dt.date) -> FindingItem:
    f, hunt_name, target_date, st, assignee, due = row
    return FindingItem(
        id=f.id, hunt_code=f.hunt_code, hunt_name=hunt_name or "", query_id=f.query_id, target_date=target_date,
        period_from=f.period_from, period_to=f.period_to, event_count=f.event_count, limit_hit=f.limit_hit,
        created_at=f.created_at, status=st, assignee=assignee, due_date=due, overdue=is_overdue(st, due, on),
    )


@router.get("", response_model=FindingList)
def list_findings(
    status_: QueryStatus = None,
    hunt: QueryList = None,
    date_from: dt.date | None = None,
    date_to: dt.date | None = None,
    limit_hit: bool | None = None,
    sort: str = "created_at",
    order: str = "desc",
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> FindingList:
    """Только ночные находки. `status` — коды повтором ключа (или через запятую), по умолчанию
    открытые, `all` — любые; `hunt` — коды хантов; `date_from`/`date_to` — дата ночи."""
    f = _filter(status_, hunt, date_from, date_to, limit_hit)
    query = _ordered(f, sort, order)
    total = db.scalar(base_query(func.count()).where(*conditions(f))) or 0
    on = today()
    items = [_item(row, on) for row in db.execute(query.limit(limit).offset(offset))]
    return FindingList(total=total, items=items, facets=facets(db, f))


EXPORT_COLUMNS = [
    Column("status", "Статус"), Column("hunt", "Хант"), Column("hunt_name", "Название"), Column("query_id", "Запрос"),
    Column("night", "Ночь"), Column("events", "Событий"), Column("limit_hit", "Достигнут лимит"),
    Column("created_at", "Найдено"), Column("assignee", "Исполнитель"), Column("due_date", "Срок"),
]


@router.get("/export")
def export_findings(
    status_: QueryStatus = None,
    hunt: QueryList = None,
    date_from: dt.date | None = None,
    date_to: dt.date | None = None,
    limit_hit: bool | None = None,
    sort: str = "created_at",
    order: str = "desc",
    fmt: str = Query(default="csv", alias="format"),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """Список под теми же фильтрами и в том же порядке, без страниц (объявлена до `/{finding_id}`)."""
    query = _ordered(_filter(status_, hunt, date_from, date_to, limit_hit), sort, order)

    def rows() -> Iterator[dict[str, Any]]:
        on = today()
        for row in db.execute(query).yield_per(EVENTS_BATCH):
            i = _item(row, on)
            yield {"status": STATUS_TITLES[i.status], "hunt": i.hunt_code, "hunt_name": i.hunt_name,
                   "query_id": i.query_id, "night": i.target_date, "events": i.event_count,
                   "limit_hit": "да" if i.limit_hit else "нет", "created_at": i.created_at,
                   "assignee": i.assignee, "due_date": i.due_date}

    return export_response(fmt, EXPORT_COLUMNS, rows(), module="siem", name="th-findings")


def get_finding(db: Session, finding_id: int) -> ThFinding:
    finding = db.get(ThFinding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="находка не найдена")
    return finding


def columns_of(finding: ThFinding) -> list[ColumnView]:
    return [ColumnView(**c) for c in json.loads(finding.columns_json)]


def finding_detail(db: Session, finding: ThFinding) -> FindingDetail:
    """Карточка находки — и ночной, и большого ханта (его страница встраивает её)."""
    from api.modules.siem.hunting.saved_filters import catalog, finding_filter
    catalog(db, commit=True)
    key = finding_key(finding.id)
    row = state_map(db, TH_MODULE, TH_SCOPE, [key]).get(key)
    st = effective_status(row)
    on = today()
    due = row.due_date if row is not None else None
    hunt = db.get(ThHunt, finding.hunt_id) if finding.hunt_id is not None else None
    run = db.get(ThRun, finding.run_id) if finding.run_id is not None else None
    deep = db.get(ThDeepHunt, finding.deep_id) if finding.deep_id is not None else None
    return FindingDetail(
        saved_filter=finding_filter(db, finding),
        id=finding.id, key=key, kind=finding.kind, hunt_code=finding.hunt_code, hunt_name=hunt.name if hunt else "",
        query_id=finding.query_id, target_date=run.target_date if run else None, period_from=finding.period_from,
        period_to=finding.period_to, event_count=finding.event_count, limit_hit=finding.limit_hit,
        created_at=finding.created_at, status=st, assignee=row.assignee if row else None, due_date=due,
        overdue=is_overdue(st, due, on), columns=columns_of(finding), events_purged=finding.events_purged,
        run_id=finding.run_id, deep_id=finding.deep_id, partial=finding.partial,
        limit_hit_slices=deep.limit_hit_slices if deep else None,
        state=StateBrief(
            status=st, status_title=STATUS_TITLES[st], assignee=row.assignee if row else None, due_date=due,
            overdue=is_overdue(st, due, on), risk_until=row.risk_until if row else None,
            updated_by=row.updated_by if row else "", updated_at=row.updated_at if row else None,
        ),
    )


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding_detail(
    finding_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> FindingDetail:
    return finding_detail(db, get_finding(db, finding_id))


def _values(data_json: str, fields: list[str]) -> list[Any]:
    data = json.loads(data_json)
    return [data.get(f, "") for f in fields]


@router.get("/{finding_id}/events", response_model=EventsPage)
def list_events(
    finding_id: int,
    limit: int = Query(default=100, ge=1, le=EVENTS_PAGE_MAX),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> EventsPage:
    """Страница событий по `position`; строка — значения в порядке колонок находки."""
    finding = get_finding(db, finding_id)
    fields = [c.field for c in columns_of(finding)]
    total = db.scalar(select(func.count()).select_from(ThEvent).where(ThEvent.finding_id == finding.id)) or 0
    rows = db.scalars(
        select(ThEvent.data_json).where(ThEvent.finding_id == finding.id)
        .order_by(ThEvent.position).limit(limit).offset(offset)
    )
    return EventsPage(total=total, rows=[_values(r, fields) for r in rows])


@router.get("/{finding_id}/events/export")
def export_events(
    finding_id: int,
    fmt: str = Query(default="csv", alias="format"),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """Все события находки по `position`, заголовки — подписи колонок; читаются партиями."""
    finding = get_finding(db, finding_id)
    cols = columns_of(finding)
    # Ключи колонок — по номеру: поле может повториться, подпись — тем более.
    columns = [Column(f"c{i}", c.label) for i, c in enumerate(cols)]
    fields = [c.field for c in cols]
    query = select(ThEvent.data_json).where(ThEvent.finding_id == finding.id).order_by(ThEvent.position)

    def rows() -> Iterator[dict[str, Any]]:
        for data_json in db.scalars(query).yield_per(EVENTS_BATCH):
            yield {f"c{i}": v for i, v in enumerate(_values(data_json, fields))}

    # В имени файла — только id: код ханта задаёт человек, и кавычка в нём сломала бы заголовок.
    return export_response(fmt, columns, rows(), module="siem", name=f"th-finding-{finding.id}-events")
