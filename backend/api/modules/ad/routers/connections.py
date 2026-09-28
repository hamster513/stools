"""Профили онлайн-подключения: CRUD, проверка, сбор."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.collector_routes import add_connection, edit_connection, run_connection_test, start_collect
from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.hosts import validate_host
from api.modules.ad.models import AdConnection, AdJob
from api.modules.ad.routers.snapshots import JobStarted
from api.modules.ad.services import connections as svc
from api.modules.ad.services.settings import load_config
from api.settings import Settings, get_settings

router = APIRouter(prefix="/connections", tags=["ad"])

#: Поля, от которых зависит, куда и как уйдёт сохранённый пароль: смена имени
#: вида DOMAIN\user на UPN переводит вход с NTLM на SIMPLE, открытым текстом.
ADDRESS_FIELDS = frozenset({"host", "port", "use_ssl", "verify_tls", "username"})


class ConnectionIn(BaseModel):
    title: str = ""
    host: str
    port: int = Field(default=636, ge=1, le=65535)
    use_ssl: bool = True
    #: Безопасное умолчание; отключение — осознанный выбор в форме.
    verify_tls: bool = True
    username: str = ""
    #: Пусто при обновлении — оставить прежний.
    password: str = ""
    base_dn: str = ""
    collect_sysvol: bool = True

    @field_validator("host")
    @classmethod
    def check_host(cls, value: str) -> str:
        return validate_host(value)


class ConnectionView(BaseModel):
    id: int
    title: str
    host: str
    port: int
    use_ssl: bool
    verify_tls: bool
    username: str
    password_set: bool
    base_dn: str
    collect_sysvol: bool
    domain_id: int | None = None


def _view(c: AdConnection) -> ConnectionView:
    return ConnectionView(
        id=c.id, title=c.title, host=c.host, port=c.port, use_ssl=c.use_ssl, verify_tls=c.verify_tls,
        username=c.username, password_set=bool(c.password), base_dn=c.base_dn, collect_sysvol=c.collect_sysvol, domain_id=c.domain_id,
    )


def _get(db: Session, connection_id: int) -> AdConnection:
    c = db.get(AdConnection, connection_id)
    if c is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="подключение не найдено")
    return c


@router.get("", response_model=list[ConnectionView])
def list_connections(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[ConnectionView]:
    return [_view(c) for c in db.execute(select(AdConnection).order_by(AdConnection.id)).scalars()]


@router.post("", response_model=ConnectionView, status_code=status.HTTP_201_CREATED)
def create_connection(payload: ConnectionIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ConnectionView:
    return _view(add_connection(db, AdConnection, payload))


@router.put("/{connection_id}", response_model=ConnectionView)
def update_connection(
    connection_id: int, payload: ConnectionIn, request: Request, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> ConnectionView:
    c = _get(db, connection_id)
    edit_connection(db, c, payload, request, ADDRESS_FIELDS)
    return _view(c)


@router.delete("/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_connection(connection_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> None:
    db.delete(_get(db, connection_id))
    db.commit()


@router.post("/{connection_id}/test")
def test_connection(connection_id: int, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    c = _get(db, connection_id)
    return run_connection_test("ad", user.id, lambda: svc.test_connection(c), svc.public_error)


@router.post("/{connection_id}/collect", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
def collect(
    connection_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: AppUser = Depends(get_current_user),
) -> JobStarted:
    c = _get(db, connection_id)
    data_dir = settings.data_dir
    job_id = start_collect(
        background_tasks, db, user, c, module="ad", job_model=AdJob,
        collect=lambda session, handle, conn: svc.collect_snapshot(session, handle, conn, load_config(session), data_dir),
    )
    return JobStarted(job_id=job_id)
