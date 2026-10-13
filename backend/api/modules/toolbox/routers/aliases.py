"""Таблица соответствий (спека §2, §6): просмотр и выгрузка — аналитику, «забыть» — администратору."""
from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db.base import get_db, get_sessionmaker
from api.db.models import ROLE_ADMIN, AppUser
from api.deps import get_current_user
from api.modules.toolbox.routers.scrub import require_analyst
from api.modules.toolbox.services.aliases import export_rows, forget_alias, list_aliases
from api.platform.export import Column, export_response
from api.rbac import allows

router = APIRouter(prefix="/aliases", tags=["toolbox"])


class AliasView(BaseModel):
    id: int
    kind: str
    real: str
    alias: str
    created_at: dt.datetime
    created_by: str
    first_job_id: int | None


class AliasPage(BaseModel):
    items: list[AliasView]
    total: int


@router.get("", response_model=AliasPage)
def get_aliases(
    request: Request,
    q: str = "",
    kind: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> AliasPage:
    # Сводка — до проверки роли: отказ попадает в журнал, а без своей сводки туда ушла бы строка
    # запроса с настоящим значением из поиска.
    request.state.audit_summary = "таблица соответствий: просмотр"
    require_analyst(user)
    rows, total = list_aliases(db, q=q, kind=kind, limit=limit, offset=offset)
    return AliasPage(items=[AliasView.model_validate(r, from_attributes=True) for r in rows], total=total)


#: Подписи — как в таблице на экране; вид — кодом (host, ip4): по нему выгрузку фильтруют.
EXPORT_COLUMNS = [
    Column("kind", "Вид"),
    Column("real", "Настоящее"),
    Column("alias", "Псевдоним"),
    Column("created_at", "Когда"),
    Column("created_by", "Кто"),
    Column("first_job_id", "Задание"),
]


@router.get("/export")
def export(
    request: Request,
    fmt: str = Query(default="csv", alias="format"),
    q: str = "",
    kind: str | None = None,
    user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    # Сводка — до проверки роли, как у списка: иначе отказ ушёл бы в журнал со строкой запроса,
    # а в `q` — настоящее значение.
    request.state.audit_summary = "таблица соответствий: выгрузка"
    require_analyst(user)

    def rows() -> Iterator[dict[str, Any]]:
        # CSV читается после выхода из ручки: у потока своя сессия, сессия запроса к этому времени закрыта.
        with get_sessionmaker()() as session:
            yield from export_rows(session, q=q, kind=kind)

    return export_response(fmt, EXPORT_COLUMNS, rows(), module="toolbox", name="aliases")


@router.get("/export.csv")
def export_csv(request: Request, user: AppUser = Depends(get_current_user)) -> StreamingResponse:
    """Старый путь — тот же CSV, что `/export?format=csv` без фильтров."""
    return export(request, "csv", "", None, user)


@router.delete("/{alias_id}", status_code=status.HTTP_204_NO_CONTENT)
def forget(alias_id: int, request: Request, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> Response:
    # Забытый псевдоним может достаться другому значению — старые файлы с ним переведутся иначе.
    if not allows(user.role, ROLE_ADMIN):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="нужна роль: администратор")
    try:
        forget_alias(db, alias_id)
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc)) from None
    request.state.audit_summary = f"псевдоним #{alias_id} забыт"
    return Response(status_code=status.HTTP_204_NO_CONTENT)
