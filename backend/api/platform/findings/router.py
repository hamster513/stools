"""Ручки статусов находок (спека §5): /api/findings/*, справочник исполнителей, настройки.

Права — общим правилом api/rbac.py по методу и пути: чтение всем, запись в
/api/findings — аналитику, запись /api/settings/findings — администратору.
Внутри ручек остаётся одна проверка роли — `risk_accept_role`, она зависит
от настроек, а не от пути.

В PUT отличаются «поле не передано» (не трогать) и `null` (очистить) — по
`model_fields_set` тела.
"""
from __future__ import annotations

import datetime as dt
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.audit import changes_summary
from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.platform.findings import service as svc
from api.platform.findings.adapters import FindingAdapter, get_adapter, get_bulk_filter
from api.platform.findings.core import (
    OPEN,
    STATUS_TITLES,
    STATUSES,
    FindingSettings,
    RoleRequired,
    TransitionError,
    is_overdue,
)
from api.platform.findings.models import FindingState

router = APIRouter(tags=["findings"])

MAX_BULK_KEYS = 5000
Key = Annotated[str, Field(min_length=1, max_length=128)]


class ChangeBody(BaseModel):
    status: str | None = Field(default=None, max_length=16)
    assignee: str | None = Field(default=None, max_length=255)
    due_date: dt.date | None = None
    risk_until: dt.date | None = None
    comment: str = Field(default="", max_length=4000)

    def to_change(self) -> svc.Change:
        sent = self.model_fields_set
        return svc.Change(
            status=self.status,
            assignee=self.assignee if "assignee" in sent else svc.UNSET,
            due_date=self.due_date if "due_date" in sent else svc.UNSET,
            risk_until=self.risk_until if "risk_until" in sent else svc.UNSET,
            comment=self.comment,
        )

    def describe(self) -> str:
        sent = self.model_fields_set
        parts = [f"статус {self.status}"] if self.status else []
        parts += [title for field, title in (("assignee", "исполнитель"), ("due_date", "срок"),
                                             ("risk_until", "риск до")) if field in sent]
        if not parts and self.comment.strip():
            parts.append("комментарий")
        return ", ".join(parts)


class StateChange(ChangeBody):
    module: str = Field(max_length=16)
    scope_id: int = Field(ge=0)
    key: Key
    #: Подпись для «Моих находок», пока строку не обновила сверка с данными модуля.
    title: str = Field(default="", max_length=512)
    severity: str = Field(default="", max_length=16)


class CommentBody(BaseModel):
    module: str = Field(max_length=16)
    scope_id: int = Field(ge=0)
    key: Key
    text: str = Field(min_length=1, max_length=4000)


class BulkBody(BaseModel):
    module: str = Field(max_length=16)
    scope_id: int = Field(ge=0)
    keys: list[Key] | None = Field(default=None, min_length=1, max_length=MAX_BULK_KEYS)
    filter: dict[str, Any] | None = None
    change: ChangeBody


class EventView(BaseModel):
    at: dt.datetime
    actor: str
    kind: str
    from_status: str | None
    to_status: str | None
    comment: str
    details: dict[str, Any]


class StateView(BaseModel):
    module: str
    scope_id: int
    key: str
    status: str
    status_title: str
    assignee: str | None = None
    assignee_name: str | None = None
    due_date: dt.date | None = None
    overdue: bool = False
    risk_until: dt.date | None = None
    reason: str = ""
    present: bool = True
    first_seen_at: dt.datetime | None = None
    updated_by: str = ""
    updated_at: dt.datetime | None = None
    events: list[EventView] = []


class MineItem(BaseModel):
    module: str
    scope_id: int
    key: str
    title: str
    severity: str
    status: str
    status_title: str
    due_date: dt.date | None
    overdue: bool
    risk_until: dt.date | None
    present: bool
    first_seen_at: dt.datetime | None
    updated_at: dt.datetime
    link: str


class DirectoryUser(BaseModel):
    login: str
    display_name: str | None


def _adapter(module: str) -> FindingAdapter:
    try:
        return get_adapter(module)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from None


def _refused(exc: TransitionError) -> HTTPException:
    code = status.HTTP_403_FORBIDDEN if isinstance(exc, RoleRequired) else status.HTTP_422_UNPROCESSABLE_CONTENT
    return HTTPException(code, detail=str(exc))


def _view(db: Session, module: str, scope_id: int, key: str) -> StateView:
    row = svc.state_map(db, module, scope_id, [key]).get(key)
    if row is None:
        return StateView(module=module, scope_id=scope_id, key=key, status="new", status_title=STATUS_TITLES["new"],
                         first_seen_at=_adapter(module).first_seen(db, scope_id, key))
    name = None
    if row.assignee:
        user = db.scalars(select(AppUser).where(AppUser.login == row.assignee)).first()
        name = (user.display_name if user else None) or row.assignee
    return StateView(
        module=module, scope_id=scope_id, key=key, status=row.status, status_title=STATUS_TITLES[row.status],
        assignee=row.assignee, assignee_name=name, due_date=row.due_date,
        overdue=is_overdue(row.status, row.due_date, svc.today()), risk_until=row.risk_until, reason=row.reason,
        present=row.present, first_seen_at=row.first_seen_at, updated_by=row.updated_by, updated_at=row.updated_at,
        events=[EventView(at=e.at, actor=e.actor, kind=e.kind, from_status=e.from_status, to_status=e.to_status,
                          comment=e.comment, details=e.details) for e in svc.events_of(db, row)],
    )


@router.get("/api/findings/state", response_model=StateView)
def get_state(
    module: str = Query(max_length=16), scope_id: int = Query(ge=0), key: str = Query(min_length=1, max_length=128),
    db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> StateView:
    _adapter(module)
    return _view(db, module, scope_id, key)


@router.put("/api/findings/state", response_model=StateView)
def put_state(payload: StateChange, request: Request, db: Session = Depends(get_db),
              user: AppUser = Depends(get_current_user)) -> StateView:
    _adapter(payload.module)
    request.state.audit_summary = f"{payload.module}: находок 1; {payload.describe()}"
    try:
        svc.change(db, module=payload.module, scope_id=payload.scope_id, key=payload.key,
                   change=payload.to_change(), actor=user, title=payload.title, severity=payload.severity)
    except TransitionError as exc:
        raise _refused(exc) from None
    return _view(db, payload.module, payload.scope_id, payload.key)


@router.post("/api/findings/comment", response_model=StateView)
def post_comment(payload: CommentBody, request: Request, db: Session = Depends(get_db),
                 user: AppUser = Depends(get_current_user)) -> StateView:
    _adapter(payload.module)
    request.state.audit_summary = f"{payload.module}: находок 1; комментарий"
    try:
        svc.comment(db, module=payload.module, scope_id=payload.scope_id, key=payload.key, text=payload.text, actor=user)
    except TransitionError as exc:
        raise _refused(exc) from None
    return _view(db, payload.module, payload.scope_id, payload.key)


@router.post("/api/findings/bulk")
def post_bulk(payload: BulkBody, request: Request, db: Session = Depends(get_db),
              user: AppUser = Depends(get_current_user)) -> dict[str, int]:
    """Смена по списку ключей. Выбор «всё по фильтру» — только у модулей, которые
    зарегистрировали разбор своего фильтра (`register_bulk_filter`)."""
    _adapter(payload.module)
    if (payload.keys is None) == (payload.filter is None):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="нужны либо ключи, либо фильтр")
    keys = payload.keys
    if keys is None:
        select_by_filter = get_bulk_filter(payload.module)
        if select_by_filter is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="выбор по фильтру не поддерживается этим модулем")
        keys = select_by_filter(db, payload.scope_id, payload.filter or {})
    request.state.audit_summary = f"{payload.module}: находок {len(keys)}; {payload.change.describe()}"
    try:
        changed = svc.bulk_change(db, module=payload.module, scope_id=payload.scope_id, keys=keys,
                                  change=payload.change.to_change(), actor=user)
    except TransitionError as exc:
        raise _refused(exc) from None
    return {"changed": changed}


@router.get("/api/findings/mine", response_model=list[MineItem])
def get_mine(
    status_: str = Query(default="", alias="status"), module: str = Query(default="", max_length=16),
    db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> list[MineItem]:
    wanted = [s for s in status_.split(",") if s] or sorted(OPEN)
    unknown = set(wanted) - set(STATUSES)
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"неизвестные статусы: {', '.join(sorted(unknown))}")
    query = select(FindingState).where(FindingState.assignee == user.login, FindingState.status.in_(wanted))
    if module:
        query = query.where(FindingState.module == module)
    rows = db.scalars(query.order_by(FindingState.due_date.asc().nulls_last(), FindingState.updated_at.desc()))
    on = svc.today()
    items = []
    for row in rows:
        try:
            link = get_adapter(row.module).link(row.scope_id, row.key)
        except LookupError:
            link = ""
        items.append(MineItem(
            module=row.module, scope_id=row.scope_id, key=row.key, title=row.title, severity=row.severity,
            status=row.status, status_title=STATUS_TITLES[row.status], due_date=row.due_date,
            overdue=is_overdue(row.status, row.due_date, on), risk_until=row.risk_until, present=row.present,
            first_seen_at=row.first_seen_at, updated_at=row.updated_at, link=link,
        ))
    return items


@router.get("/api/findings/summary")
def get_summary(
    module: str = Query(max_length=16), scope_id: int = Query(ge=0),
    db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    adapter = _adapter(module)
    keys_present = len({f.key for f in adapter.current(db, scope_id)})
    return svc.summary(db, module, scope_id, keys_present=keys_present)


@router.get("/api/users/directory", response_model=list[DirectoryUser])
def get_directory(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[DirectoryUser]:
    return [DirectoryUser(login=u.login, display_name=u.display_name) for u in svc.directory(db)]


@router.get("/api/settings/findings", response_model=FindingSettings)
def get_finding_settings(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> FindingSettings:
    return svc.load_settings(db)


@router.put("/api/settings/findings", response_model=FindingSettings)
def put_finding_settings(payload: FindingSettings, request: Request, db: Session = Depends(get_db),
                 user: AppUser = Depends(get_current_user)) -> FindingSettings:
    """Поля, которых нет в теле, остаются прежними."""
    current = svc.load_settings(db)
    merged = FindingSettings.model_validate({**current.model_dump(), **payload.model_dump(exclude_unset=True)})
    request.state.audit_summary = changes_summary(
        [f for f in FindingSettings.model_fields if getattr(merged, f) != getattr(current, f)]
    )
    return svc.save_settings(db, merged, updated_by=user.login)
