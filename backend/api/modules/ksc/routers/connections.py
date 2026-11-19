"""Профили онлайн-подключения к KSC: CRUD, проверка, сбор, расписание сбора."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute

from api.crypto import PREFIX, encrypt, reseal
from api.modules.ksc.core.totp import normalize_secret
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.collector_routes import (
    add_connection,
    add_schedule_routes,
    collect_schedule,
    collect_schedules,
    delete_collect_schedule,
    edit_connection,
    run_connection_test,
    start_collect,
)
from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.hosts import validate_host
from api.jobs import JobHandle
from api.modules.ksc.models import KscConnection, KscJob, KscSnapshot
from api.modules.ksc.routers.snapshots import JobStarted
from api.modules.ksc.services import connections as svc
from api.modules.ksc.services.settings import load_config
from api.platform.schedule_views import ScheduleView, schedule_view
from api.platform.scheduler import PlatformSchedule
from api.settings import get_settings

class ConnectionRoute(APIRoute):
    def get_route_handler(self):
        original = super().get_route_handler()

        async def handler(request):
            try:
                return await original(request)
            except RequestValidationError as exc:
                # Validation errors must not echo credentials or the whole form.
                errors = [{key: error[key] for key in ("loc", "msg", "type")} for error in exc.errors()]
                raise HTTPException(422, errors) from None
        return handler


router = APIRouter(prefix="/connections", tags=["ksc"], route_class=ConnectionRoute)

#: Поля, от которых зависит, куда и под чьим именем уйдёт сохранённый пароль.
ADDRESS_FIELDS = frozenset({"host", "port", "verify_tls", "username", "internal", "domain"})


class ConnectionIn(BaseModel):
    title: str = ""
    host: str
    port: int = Field(default=13299, ge=1, le=65535)
    username: str = ""
    #: Пусто при обновлении — оставить прежний.
    password: str = ""
    totp_secret: str = Field(default="", max_length=512, repr=False)
    clear_totp_secret: bool = Field(default=False, exclude=True)
    verify_tls: bool = True
    #: Внутренняя учётка KSC (internal="1") или доменная с именем домена.
    internal: bool = True
    domain: str = ""
    #: Не собирать содержимое политик (секция policy_contents) — файл заметно больше.
    skip_policy_contents: bool = False

    @field_validator("totp_secret")
    @classmethod
    def check_totp_secret(cls, value: str) -> str:
        return normalize_secret(value)

    @field_validator("host")
    @classmethod
    def check_host(cls, value: str) -> str:
        return validate_host(value)


class ConnectionView(BaseModel):
    id: int
    title: str
    host: str
    port: int
    username: str
    password_set: bool
    totp_secret_set: bool
    verify_tls: bool
    internal: bool
    domain: str
    server_id: int | None = None
    skip_policy_contents: bool
    #: Расписание сбора по этому подключению; None — не задано.
    schedule: ScheduleView | None = None


def _view(c: KscConnection, sched: PlatformSchedule | None) -> ConnectionView:
    return ConnectionView(
        id=c.id, title=c.title, host=c.host, port=c.port, username=c.username, password_set=bool(c.password), totp_secret_set=bool(c.totp_secret),
        verify_tls=c.verify_tls, internal=c.internal, domain=c.domain, server_id=c.server_id,
        skip_policy_contents=c.skip_policy_contents, schedule=schedule_view(sched) if sched is not None else None,
    )


def _with_totp(payload: ConnectionIn, current: KscConnection | None = None) -> ConnectionIn:
    if payload.clear_totp_secret and payload.totp_secret:
        raise HTTPException(422, "Нельзя одновременно задать и удалить секрет TOTP")
    if payload.clear_totp_secret:
        sealed = ""
    elif payload.totp_secret:
        sealed = encrypt(payload.totp_secret)
    else:
        previous = (current.totp_secret or "") if current is not None else ""
        if previous and any(getattr(payload, key) != getattr(current, key) for key in ADDRESS_FIELDS):
            raise HTTPException(422, "При смене адреса, учётной записи или TLS введите секрет TOTP заново либо явно удалите его")
        sealed = reseal(previous)
    if sealed and not sealed.startswith(PREFIX):
        raise HTTPException(422, "Для сохранения секрета TOTP нужен настроенный ключ шифрования STools")
    return payload.model_copy(update={"totp_secret": sealed})


def _get(db: Session, connection_id: int) -> KscConnection:
    c = db.get(KscConnection, connection_id)
    if c is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="подключение не найдено")
    return c


def collect_snapshot_job(session: Session, handle: JobHandle, conn: KscConnection) -> KscSnapshot:
    """Сбор по подключению — один и тот же у кнопки «собрать» и у расписания."""
    return svc.collect_snapshot(session, handle, conn, load_config(session), get_settings().data_dir)


@router.get("", response_model=list[ConnectionView])
def list_connections(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[ConnectionView]:
    rows = list(db.execute(select(KscConnection).order_by(KscConnection.id)).scalars())
    schedules = collect_schedules(db, "ksc", [c.id for c in rows])
    return [_view(c, schedules.get(c.id)) for c in rows]


@router.post("", response_model=ConnectionView, status_code=status.HTTP_201_CREATED)
def create_connection(payload: ConnectionIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ConnectionView:
    return _view(add_connection(db, KscConnection, _with_totp(payload)), None)


@router.put("/{connection_id}", response_model=ConnectionView)
def update_connection(
    connection_id: int, payload: ConnectionIn, request: Request, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> ConnectionView:
    c = _get(db, connection_id)
    edit_connection(db, c, _with_totp(payload, c), request, ADDRESS_FIELDS)
    return _view(c, collect_schedule(db, "ksc", c.id))


@router.delete("/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_connection(connection_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> None:
    c = _get(db, connection_id)
    delete_collect_schedule(db, "ksc", c.id)
    db.delete(c)
    db.commit()


@router.post("/{connection_id}/test")
def test_connection(connection_id: int, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    c = _get(db, connection_id)
    return run_connection_test("ksc", user.id, lambda: svc.test_connection(c), svc.public_error)


@router.post("/{connection_id}/collect", response_model=JobStarted, status_code=status.HTTP_202_ACCEPTED)
def collect(
    connection_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> JobStarted:
    c = _get(db, connection_id)
    job_id = start_collect(background_tasks, db, user, c, module="ksc", job_model=KscJob, collect=collect_snapshot_job)
    return JobStarted(job_id=job_id)


add_schedule_routes(router, module="ksc", connection_model=KscConnection)
