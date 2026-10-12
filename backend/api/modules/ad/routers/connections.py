"""Профили онлайн-подключения: CRUD, проверка, сбор, расписание сбора."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
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
from api.modules.ad.core.ldap_collector import PAGE_SIZE_DEFAULT, PAUSE_MS_DEFAULT
from api.modules.ad.models import AdConnection, AdJob, AdSnapshot
from api.modules.ad.routers.snapshots import JobStarted
from api.modules.ad.services import connections as svc
from api.modules.ad.services.settings import load_config
from api.platform.schedule_views import ScheduleView, schedule_view
from api.platform.scheduler import PlatformSchedule
from api.settings import get_settings

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
    page_size: int = PAGE_SIZE_DEFAULT
    pause_ms: int = PAUSE_MS_DEFAULT

    @field_validator("host")
    @classmethod
    def check_host(cls, value: str) -> str:
        return validate_host(value)

    # mode="before": пустое поле формы (null) и дробь получают тот же русский текст, что и выход за границы.
    @field_validator("page_size", mode="before")
    @classmethod
    def check_page_size(cls, value: Any) -> int:
        return _whole_in_range(value, 50, 1000, "размер страницы LDAP: от 50 до 1000")

    @field_validator("pause_ms", mode="before")
    @classmethod
    def check_pause(cls, value: Any) -> int:
        return _whole_in_range(value, 0, 10000, "пауза между запросами к контроллеру: от 0 до 10000 мс")


class ConnectionUpdate(ConnectionIn):
    """PUT: поле страницы или паузы, которого нет в запросе, оставляет прежнее значение, а не
    умолчание. Явный null по-прежнему отвергается проверкой диапазона."""

    page_size: int | None = None  # type: ignore[assignment]
    pause_ms: int | None = None  # type: ignore[assignment]


def _whole_in_range(value: Any, low: int, high: int, text: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(text)
    return value


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
    page_size: int
    pause_ms: int
    domain_id: int | None = None
    #: Расписание сбора по этому подключению; None — не задано.
    schedule: ScheduleView | None = None


def _view(c: AdConnection, sched: PlatformSchedule | None) -> ConnectionView:
    return ConnectionView(
        id=c.id, title=c.title, host=c.host, port=c.port, use_ssl=c.use_ssl, verify_tls=c.verify_tls,
        username=c.username, password_set=bool(c.password), base_dn=c.base_dn, collect_sysvol=c.collect_sysvol,
        page_size=c.page_size, pause_ms=c.pause_ms, domain_id=c.domain_id,
        schedule=schedule_view(sched) if sched is not None else None,
    )


def _get(db: Session, connection_id: int) -> AdConnection:
    c = db.get(AdConnection, connection_id)
    if c is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="подключение не найдено")
    return c


def collect_snapshot_job(session: Session, handle: JobHandle, conn: AdConnection) -> AdSnapshot:
    """Сбор по подключению — один и тот же у кнопки «собрать» и у расписания."""
    return svc.collect_snapshot(session, handle, conn, load_config(session), get_settings().data_dir)


@router.get("", response_model=list[ConnectionView])
def list_connections(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[ConnectionView]:
    rows = list(db.execute(select(AdConnection).order_by(AdConnection.id)).scalars())
    schedules = collect_schedules(db, "ad", [c.id for c in rows])
    return [_view(c, schedules.get(c.id)) for c in rows]


@router.post("", response_model=ConnectionView, status_code=status.HTTP_201_CREATED)
def create_connection(payload: ConnectionIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ConnectionView:
    return _view(add_connection(db, AdConnection, payload), None)


@router.put("/{connection_id}", response_model=ConnectionView)
def update_connection(
    connection_id: int, payload: ConnectionUpdate, request: Request, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> ConnectionView:
    c = _get(db, connection_id)
    edit_connection(db, c, payload, request, ADDRESS_FIELDS)
    return _view(c, collect_schedule(db, "ad", c.id))


@router.delete("/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_connection(connection_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> None:
    c = _get(db, connection_id)
    delete_collect_schedule(db, "ad", c.id)
    db.delete(c)
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
    user: AppUser = Depends(get_current_user),
) -> JobStarted:
    c = _get(db, connection_id)
    job_id = start_collect(background_tasks, db, user, c, module="ad", job_model=AdJob, collect=collect_snapshot_job)
    return JobStarted(job_id=job_id)


add_schedule_routes(router, module="ad", connection_model=AdConnection)
