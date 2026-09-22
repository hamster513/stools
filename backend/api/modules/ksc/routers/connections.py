"""Профили онлайн-подключения к KSC: CRUD, проверка, сбор."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.jobs import JobHandle
from api.modules.ksc.models import KscConnection
from api.modules.ksc.routers.snapshots import JobStarted
from api.modules.ksc.services import connections as svc
from api.modules.ksc.services.jobs import active_job, run_job, start_job
from api.modules.ksc.services.settings import load_config
from api.settings import Settings, get_settings

router = APIRouter(prefix="/connections", tags=["ksc"])


class ConnectionIn(BaseModel):
    title: str = ""
    host: str
    port: int = Field(default=13299, ge=1, le=65535)
    username: str = ""
    #: Пусто при обновлении — оставить прежний.
    password: str = ""
    verify_tls: bool = True
    #: Внутренняя учётка KSC (internal="1") или доменная с именем домена.
    internal: bool = True
    domain: str = ""
    #: Не собирать содержимое политик (секция policy_contents) — файл заметно больше.
    skip_policy_contents: bool = False


class ConnectionView(BaseModel):
    id: int
    title: str
    host: str
    port: int
    username: str
    password_set: bool
    verify_tls: bool
    internal: bool
    domain: str
    server_id: int | None
    skip_policy_contents: bool


def _view(c: KscConnection) -> ConnectionView:
    return ConnectionView(
        id=c.id, title=c.title, host=c.host, port=c.port, username=c.username, password_set=bool(c.password),
        verify_tls=c.verify_tls, internal=c.internal, domain=c.domain, server_id=c.server_id,
        skip_policy_contents=c.skip_policy_contents,
    )


def _get(db: Session, connection_id: int) -> KscConnection:
    c = db.get(KscConnection, connection_id)
    if c is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="подключение не найдено")
    return c


@router.get("", response_model=list[ConnectionView])
def list_connections(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[ConnectionView]:
    return [_view(c) for c in db.execute(select(KscConnection).order_by(KscConnection.id)).scalars()]


@router.post("", response_model=ConnectionView, status_code=status.HTTP_201_CREATED)
def create_connection(payload: ConnectionIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ConnectionView:
    c = KscConnection(**payload.model_dump())
    db.add(c)
    db.commit()
    return _view(c)


@router.put("/{connection_id}", response_model=ConnectionView)
def update_connection(connection_id: int, payload: ConnectionIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ConnectionView:
    c = _get(db, connection_id)
    data = payload.model_dump()
    if not data["password"]:
        data.pop("password")
    for k, v in data.items():
        setattr(c, k, v)
    db.commit()
    return _view(c)


@router.delete("/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_connection(connection_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> None:
    db.delete(_get(db, connection_id))
    db.commit()


@router.post("/{connection_id}/test")
def test_connection(connection_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    c = _get(db, connection_id)
    try:
        return svc.test_connection(c)
    except Exception as exc:  # noqa: BLE001 — любая причина отказа должна дойти до человека текстом
        return {"ok": False, "message": str(exc)[:200]}


@router.post("/{connection_id}/collect", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
def collect(
    connection_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: AppUser = Depends(get_current_user),
) -> JobStarted:
    c = _get(db, connection_id)
    if not c.username or not c.password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="у подключения нет логина или пароля")
    running = active_job(db, ["import_file", "collect", "reanalyze"])
    if running is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"идёт задача #{running.id}, дождитесь её")
    job_id = start_job(db, "collect", user.login, message=c.host)
    data_dir = settings.data_dir

    def work(session: Session, handle: JobHandle) -> None:
        conn = session.get(KscConnection, connection_id)
        if conn is None:
            raise ValueError("подключение удалено")
        snap = svc.collect_snapshot(session, handle, conn, load_config(session), data_dir)
        handle.stage("done", message=f"снапшот #{snap.id}: находок {snap.findings}")

    background_tasks.add_task(run_job, job_id, work)
    return JobStarted(job_id=job_id)
