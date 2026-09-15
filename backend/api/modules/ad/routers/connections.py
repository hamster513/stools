"""Профили онлайн-подключения: CRUD, проверка, сбор."""
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
from api.modules.ad.models import AdConnection
from api.modules.ad.routers.snapshots import JobStarted
from api.modules.ad.services import connections as svc
from api.modules.ad.services.jobs import active_job, run_job, start_job
from api.modules.ad.services.settings import load_config
from api.settings import Settings, get_settings

router = APIRouter(prefix="/connections", tags=["ad"])


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
    domain_id: int | None


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
    c = AdConnection(**payload.model_dump())
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
        return {"ok": False, "message": f"{exc.__class__.__name__}: {str(exc)[:200]}"}


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
        conn = session.get(AdConnection, connection_id)
        if conn is None:
            raise ValueError("подключение удалено")
        snap = svc.collect_snapshot(session, handle, conn, load_config(session), data_dir)
        handle.stage("done", message=f"снапшот #{snap.id}: находок {snap.findings}")

    background_tasks.add_task(run_job, job_id, work)
    return JobStarted(job_id=job_id)
