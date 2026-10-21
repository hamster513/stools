"""Пользователи как активы: список с фасетами и выгрузкой, карточка, ручные поля (заметка, теги).
Права — общее правило платформы (`api.rbac`): чтение всем, запись аналитику."""
from __future__ import annotations

import datetime as dt
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.assets.core.users import USER_CODES
from api.modules.assets.routers.assets import EXPORT_ALL, MAX_LIMIT, SOURCE_TITLES, _check
from api.modules.assets.services.assets import ANY_CODE
from api.modules.assets.services.user_views import (
    SESSIONS,
    STATES,
    USER_SOURCES,
    YES_NO,
    UserConflict,
    UserNotFound,
    list_users,
    update_user,
    user_detail,
)
from api.platform.export import Column, export_response
from api.platform.filters import QueryInts, QueryList, multi, multi_int

router = APIRouter(tags=["assets"])

#: Подписи расхождений пользователей в выгрузке.
CODE_TITLES = {
    "disabled_session": "сеанс отключённой учётки",
    "not_in_ad": "нет в AD",
    "privileged_on_workstation": "привилегированная на рабочей станции",
    "owner_without_session": "владелец без сеанса",
}
STATE_TITLES = {True: "включена", False: "отключена", None: "неизвестно"}

EXPORT_COLUMNS = [
    Column("sam", "Учётка"), Column("display_name", "Имя"), Column("upn", "UPN"), Column("domain", "Домен"),
    Column("local", "Локальная"), Column("state", "Состояние"), Column("privileged", "Привилегированная"),
    Column("sources", "Источники"), Column("hosts_active", "В системе"), Column("hosts_total", "Хостов"),
    Column("last_seen", "Виден"), Column("codes", "Расхождения"),
]


class UserPatch(BaseModel):
    """Только ручные поля; не переданное поле не меняется."""

    tags: list[Annotated[str, Field(max_length=100)]] | None = Field(default=None, max_length=50)
    note: str | None = Field(default=None, max_length=4000)


def _filters(
    q: str | None = Query(default=None, max_length=200),
    source: QueryList = None,
    state: QueryList = None,
    session: QueryList = None,
    local: QueryList = None,
    privileged: QueryList = None,
    code: QueryList = None,
    host_id: QueryInts = None,
) -> dict[str, Any]:
    """Фильтры списка и выгрузки; многозначные — повтором ключа, внутри оси «или», между осями «и»."""
    picked = {"source": multi(source), "state": multi(state), "session": multi(session), "local": multi(local),
              "privileged": multi(privileged), "code": multi(code)}
    _check(picked["source"], USER_SOURCES)
    _check(picked["state"], STATES)
    _check(picked["session"], SESSIONS)
    _check(picked["local"], YES_NO)
    _check(picked["privileged"], YES_NO)
    _check(picked["code"], (*USER_CODES, ANY_CODE))
    return {"q": q, **picked, "host_id": multi_int(host_id)}


def _errors(fn: Any, *args: Any) -> Any:
    try:
        return fn(*args)
    except UserNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from None
    except UserConflict as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None


@router.get("/users")
def get_users(
    filters: dict[str, Any] = Depends(_filters),
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    items, total, facets = list_users(db, **filters, limit=limit, offset=offset)
    return {"total": total, "items": items, "facets": facets if offset == 0 else None}


@router.get("/users/export")
def export_users(
    filters: dict[str, Any] = Depends(_filters),
    fmt: str = Query(default="csv", alias="format"),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """Пользователи под фильтрами списка, в его порядке; колонки — как в таблице."""
    items, _total, _facets = list_users(db, **filters, limit=EXPORT_ALL, offset=0)
    rows = [
        {"sam": u["sam"], "display_name": u["display_name"], "upn": u["upn"], "domain": u["domain"],
         "local": "да" if u["local"] else "нет", "state": STATE_TITLES[u["enabled"]], "privileged": "да" if u["privileged"] else "нет",
         "sources": ", ".join(SOURCE_TITLES.get(s["source"], s["source"]) for s in u["sources"]),
         "hosts_active": u["hosts_active"], "hosts_total": u["hosts_total"],
         "last_seen": dt.datetime.fromisoformat(u["last_seen"]) if u["last_seen"] else None,
         "codes": ", ".join(CODE_TITLES.get(c, c) for c in u["codes"])}
        for u in items
    ]
    return export_response(fmt, EXPORT_COLUMNS, rows, module="assets", name="users")


@router.get("/users/{user_id}")
def get_user(user_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    return dict(_errors(user_detail, db, user_id))


@router.patch("/users/{user_id}")
def patch_user(user_id: int, payload: UserPatch, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    _errors(update_user, db, user_id, payload.model_dump(include=payload.model_fields_set))
    db.commit()
    return dict(user_detail(db, user_id))
