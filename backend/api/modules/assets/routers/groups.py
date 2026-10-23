"""Группы как активы: список с фасетами и выгрузкой, карточка, полный состав. Только чтение — всем ролям."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.assets.routers.assets import EXPORT_ALL, MAX_LIMIT, SOURCE_TITLES, _check
from api.modules.assets.services.group_views import (
    GROUP_SOURCES,
    KINDS,
    MEMBERS,
    STATES,
    GroupNotFound,
    group_detail,
    group_expanded,
    list_groups,
)
from api.platform.export import Column, export_response
from api.platform.filters import QueryInts, QueryList, multi, multi_int

router = APIRouter(tags=["assets"])

EXPORT_COLUMNS = [
    Column("name", "Имя"), Column("domain_label", "Домен / компьютер"), Column("kind", "Вид"),
    Column("members_direct", "Участников"), Column("sources", "Источники"), Column("sid", "SID"),
    Column("description", "Описание"),
]


def _filters(
    q: str | None = Query(default=None, max_length=200),
    kind: QueryList = None,
    source: QueryList = None,
    state: QueryList = None,
    members: QueryList = None,
    domain: QueryList = None,
    host_id: QueryInts = None,
) -> dict[str, Any]:
    """Фильтры списка и выгрузки; многозначные — повтором ключа. `state` не задан — живые, `all` — все."""
    picked = {"kind": multi(kind), "source": multi(source), "state": frozenset({"live"}) if state is None else multi(state),
              "members": multi(members)}
    _check(picked["kind"], KINDS)
    _check(picked["source"], GROUP_SOURCES)
    _check(picked["state"], STATES)
    _check(picked["members"], MEMBERS)
    return {"q": q, **picked, "domain": multi(domain), "host_id": multi_int(host_id)}


def _errors(fn: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return fn(*args, **kwargs)
    except GroupNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from None


@router.get("/groups")
def get_groups(
    filters: dict[str, Any] = Depends(_filters),
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    items, total, facets = list_groups(db, **filters, limit=limit, offset=offset)
    return {"total": total, "items": items, "facets": facets if offset == 0 else None}


@router.get("/groups/export")
def export_groups(
    filters: dict[str, Any] = Depends(_filters),
    fmt: str = Query(default="csv", alias="format"),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """Группы под фильтрами списка, в его порядке; колонки — как в таблице."""
    items, _total, _facets = list_groups(db, **filters, limit=EXPORT_ALL, offset=0)
    rows = [
        {"name": g["name"], "domain_label": g["domain_label"], "kind": "локальная" if g["local"] else "доменная",
         "members_direct": g["members_direct"], "sources": ", ".join(SOURCE_TITLES.get(s, s) for s in g["sources"]),
         "sid": g["sid"], "description": g["description"]}
        for g in items
    ]
    return export_response(fmt, EXPORT_COLUMNS, rows, module="assets", name="groups")


@router.get("/groups/{group_id}")
def get_group(group_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    return dict(_errors(group_detail, db, group_id))


@router.get("/groups/{group_id}/expanded")
def get_group_expanded(
    group_id: int,
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    return dict(_errors(group_expanded, db, group_id, limit=limit, offset=offset))
