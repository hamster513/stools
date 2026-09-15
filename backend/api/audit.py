"""Журнал действий.

Пишется после ответа, из ASGI-middleware: зависимость не знает код
ответа, а он и есть главное — прошло действие или нет. Пользователь
берётся из `request.state.user`, который кладёт api/rbac.require_access;
для неудачного входа `auth.login` кладёт `request.state.audit_login`.
Тело запроса не читается никогда.
"""
from __future__ import annotations

import datetime as dt
import logging
from typing import Any
from typing import cast as typing_cast

from sqlalchemy import delete
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from api.db.base import get_sessionmaker
from api.db.models import AppUser, AuditEvent

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
#: Вход через провайдера: строка запроса этих ручек в журнал не попадает.
OIDC_PREFIX = "/api/auth/oidc/"
SESSION_PATHS = frozenset({
    "/api/auth/login",
    "/api/auth/logout",
    OIDC_PREFIX + "start",
    OIDC_PREFIX + "callback",
})
MAX_SUMMARY = 200

logger = logging.getLogger(__name__)


def record(
    db: Session,
    *,
    user: AppUser | None,
    login: str,
    method: str,
    path: str,
    status: int,
    ip: str | None,
    summary: str | None,
) -> None:
    db.add(
        AuditEvent(
            user_id=user.id if user else None,
            login=login,
            role=user.role if user else None,
            method=method,
            path=path,
            status=status,
            ip=ip,
            summary=summary,
        )
    )
    db.commit()


def purge_old(db: Session, days: int) -> int:
    cutoff = dt.datetime.now(dt.UTC) - dt.timedelta(days=days)
    result = typing_cast(CursorResult[Any], db.execute(delete(AuditEvent).where(AuditEvent.at < cutoff)))
    db.commit()
    return int(result.rowcount or 0)


def _should_record(method: str, path: str, status: int, summary: str) -> bool:
    if not path.startswith("/api/"):
        return False
    #: Удавшийся /start — не действие, а всего лишь редирект к провайдеру:
    #: он случается на каждое нажатие кнопки входа и на каждый возврат по
    #: «назад», и в журнале от него один шум. Отказ там тоже 302, но у него
    #: обработчик оставил сводку с кодом — по ней они и различаются.
    if path == OIDC_PREFIX + "start" and status == 302 and not summary:
        return False
    if status == 403:
        return True
    return method in WRITE_METHODS or path in SESSION_PATHS


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        path = request.url.path
        #: Обработчик может сам сказать, что писать в сводку. У ручек входа
        #: через провайдера строка запроса не годится в неё никогда: там код
        #: авторизации и state, а до обработчика дело доходит не всегда.
        #: Сводка нужна до отбора: по ней /start отличает отказ от успеха.
        own_summary = getattr(request.state, "audit_summary", None)
        if own_summary is not None:
            summary = str(own_summary)
        elif path.startswith(OIDC_PREFIX):
            summary = ""
        else:
            summary = request.url.query
        if not _should_record(request.method, path, response.status_code, summary):
            return response
        user: AppUser | None = getattr(request.state, "user", None)
        login = user.login if user else str(getattr(request.state, "audit_login", "") or "")
        if not login and response.status_code == 401:
            return response  # анонимный запрос без сессии — не действие
        try:
            with get_sessionmaker()() as db:
                record(
                    db,
                    user=user,
                    #: Колонка String(255): Postgres иначе отвергнет
                    #: вставку, и попытка входа с длинным логином
                    #: исчезнет из журнала целиком.
                    login=(login or "—")[:255],
                    method=request.method,
                    path=path,
                    status=response.status_code,
                    ip=request.client.host if request.client else None,
                    summary=summary[:MAX_SUMMARY] or None,
                )
        except Exception:
            #: Уже готовый ответ клиенту важнее сбоя записи в журнал —
            #: обрыв соединения с базой не должен превращать успешный
            #: запрос в 500.
            logger.exception("не удалось записать событие в журнал действий")
        return response
