"""Просмотр журнала действий: /api/settings/audit."""
from __future__ import annotations

import csv
import datetime as dt
import io
from collections.abc import Iterator
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser, AuditEvent
from api.deps import get_current_user

router = APIRouter(prefix="/audit", tags=["settings"])

CSV_HEADER = ["время", "пользователь", "роль", "метод", "путь", "код", "ip", "сводка"]


def _query(user_id: int | None, since: dt.datetime | None, until: dt.datetime | None, denied_only: bool) -> Any:
    stmt = select(AuditEvent)
    if user_id is not None:
        stmt = stmt.where(AuditEvent.user_id == user_id)
    if since is not None:
        stmt = stmt.where(AuditEvent.at >= since)
    if until is not None:
        stmt = stmt.where(AuditEvent.at <= until)
    if denied_only:
        stmt = stmt.where(AuditEvent.status == 403)
    return stmt


def _csv_safe(value: object) -> str:
    """Excel исполняет ячейки, начинающиеся с =, +, -, @: логин из
    неудачного входа и строка запроса — чужой ввод, экранируем."""
    text = "" if value is None else str(value)
    if text and text[0] in "=+-@\t\r":
        return "'" + text
    return text


def _item(e: AuditEvent) -> dict[str, Any]:
    return {
        "id": e.id, "at": e.at.isoformat(), "user_id": e.user_id, "login": e.login, "role": e.role,
        "method": e.method, "path": e.path, "status": e.status, "ip": e.ip, "summary": e.summary,
    }


@router.get("")
def list_events(
    user_id: int | None = None,
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


@router.get("/export.csv")
def export_csv(
    user_id: int | None = None,
    since: dt.datetime | None = None,
    until: dt.datetime | None = None,
    denied_only: bool = False,
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> Response:
    """CSV для Excel в русской локали: точка с запятой и BOM.

    Журнал за год — это сотни тысяч строк, и собирать их целиком в
    памяти процесса ради одной выгрузки незачем: отдаём потоком,
    вычитывая события партиями.
    """
    stmt = _query(user_id, since, until, denied_only).order_by(AuditEvent.id.desc())

    def lines() -> Iterator[bytes]:
        buf = io.StringIO()
        writer = csv.writer(buf, delimiter=";", lineterminator="\r\n")
        writer.writerow(CSV_HEADER)
        yield ("﻿" + buf.getvalue()).encode("utf-8")
        for e in db.scalars(stmt).yield_per(500):
            buf.seek(0)
            buf.truncate()
            writer.writerow([
                _csv_safe(e.at.isoformat()),
                _csv_safe(e.login),
                _csv_safe(e.role or ""),
                _csv_safe(e.method),
                _csv_safe(e.path),
                _csv_safe(e.status),
                _csv_safe(e.ip or ""),
                _csv_safe(e.summary or ""),
            ])
            yield buf.getvalue().encode("utf-8")

    return StreamingResponse(
        lines(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="audit.csv"'},
    )
