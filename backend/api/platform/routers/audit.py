"""Просмотр журнала действий: /api/settings/audit."""
from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser, AuditEvent
from api.deps import get_current_user
from api.platform.export import Column, csv_safe, export_response
from api.platform.filters import QueryInts, multi_int

router = APIRouter(prefix="/audit", tags=["settings"])

#: Колонки выгрузки — прежние, по полю на колонку (метод и путь порознь, роль отдельно):
#: выгрузку разбирают фильтрами Excel, а не читают глазами.
EXPORT_COLUMNS = [
    Column("at", "время"),
    Column("login", "пользователь"),
    Column("role", "роль"),
    Column("method", "метод"),
    Column("path", "путь"),
    Column("status", "код"),
    Column("ip", "ip"),
    Column("summary", "сводка"),
]
CSV_HEADER = [c.title for c in EXPORT_COLUMNS]


def _query(user_id: list[int] | None, since: dt.datetime | None, until: dt.datetime | None, denied_only: bool) -> Any:
    """`user_id` — id пользователей повтором ключа: внутри фильтра «или» (спека фильтров §1.1)."""
    stmt = select(AuditEvent)
    user_ids = multi_int(user_id)
    if user_ids is not None:
        stmt = stmt.where(AuditEvent.user_id.in_(sorted(user_ids)))
    if since is not None:
        stmt = stmt.where(AuditEvent.at >= since)
    if until is not None:
        stmt = stmt.where(AuditEvent.at <= until)
    if denied_only:
        stmt = stmt.where(AuditEvent.status == 403)
    return stmt


#: Перенесён в api/platform/export.py; старое имя — на один релиз, для чужих импортов.
_csv_safe = csv_safe


def _item(e: AuditEvent) -> dict[str, Any]:
    return {
        "id": e.id, "at": e.at.isoformat(), "user_id": e.user_id, "login": e.login, "role": e.role,
        "method": e.method, "path": e.path, "status": e.status, "ip": e.ip, "summary": e.summary,
    }


@router.get("")
def list_events(
    user_id: QueryInts = None,
    since: dt.datetime | None = None,
    until: dt.datetime | None = None,
    denied_only: bool = False,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    stmt = _query(user_id, since, until, denied_only)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(AuditEvent.id.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    return {"total": total, "items": [_item(e) for e in rows]}


def _export_rows(stmt: Any, db: Session) -> Iterator[dict[str, Any]]:
    for e in db.scalars(stmt).yield_per(500):
        yield {
            "at": e.at, "login": e.login, "role": e.role, "method": e.method,
            "path": e.path, "status": e.status, "ip": e.ip, "summary": e.summary,
        }


@router.get("/export")
def export(
    fmt: str = Query(default="csv", alias="format"),
    user_id: QueryInts = None,
    since: dt.datetime | None = None,
    until: dt.datetime | None = None,
    denied_only: bool = False,
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """Журнал за год — это сотни тысяч строк, и собирать их целиком в памяти процесса ради
    одной выгрузки CSV незачем: события вычитываются партиями, пока ответ уходит."""
    stmt = _query(user_id, since, until, denied_only).order_by(AuditEvent.id.desc())
    return export_response(fmt, EXPORT_COLUMNS, _export_rows(stmt, db), module="settings", name="audit")


@router.get("/export.csv")
def export_csv(
    user_id: QueryInts = None,
    since: dt.datetime | None = None,
    until: dt.datetime | None = None,
    denied_only: bool = False,
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """Старый путь (ссылки и закладки) — тот же CSV, что `/export?format=csv`."""
    return export("csv", user_id, since, until, denied_only, db, _user)
