"""Подключения RackTables: JSON API заказчика, проверка `getAPIVersion`, запуск вручную и расписание."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.crypto import encrypt
from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.assets.core.racktables import RtError
from api.modules.assets.models import AssetRacktables
from api.modules.assets.services.racktables import RtBusy, RtDisabled, client, start_rt
from api.platform.schedule_views import ScheduleIn, ScheduleView, schedule_view
from api.platform.scheduler import PlatformSchedule, delete_schedule, upsert_schedule

router = APIRouter(prefix="/racktables", tags=["assets"])


class RtIn(BaseModel):
    title: str = Field(default="", max_length=255)
    url: str = Field(max_length=512)
    username: str = Field(default="", max_length=255)
    #: Пусто при обновлении — оставить прежний.
    password: str = ""
    verify_tls: bool = True
    rate_per_s: int = Field(default=10, ge=1, le=100)
    timeout_ms: int = Field(default=30000, ge=1000, le=120000)
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def check_url(cls, value: str) -> str:
        url = value.strip()
        if not url.startswith(("http://", "https://")):
            raise ValueError("адрес API — http:// или https://, например https://racktables.example.local/json_api.php")
        return url


class RtView(BaseModel):
    id: int
    title: str
    url: str
    username: str
    password_set: bool
    verify_tls: bool
    rate_per_s: int
    timeout_ms: int
    enabled: bool
    schedule_id: int | None
    last_run_at: dt.datetime | None
    schedule: ScheduleView | None


class RtStarted(BaseModel):
    job_id: int


class RtCheck(BaseModel):
    version: str


def _view(row: AssetRacktables, sched: PlatformSchedule | None) -> RtView:
    return RtView(
        id=row.id, title=row.title, url=row.url, username=row.username, password_set=bool(row.password), verify_tls=row.verify_tls,
        rate_per_s=row.rate_per_s, timeout_ms=row.timeout_ms, enabled=row.enabled, schedule_id=row.schedule_id,
        last_run_at=row.last_run_at, schedule=schedule_view(sched) if sched is not None else None,
    )


def _one(db: Session, row: AssetRacktables) -> RtView:
    return _view(row, db.get(PlatformSchedule, row.schedule_id) if row.schedule_id is not None else None)


def _row(db: Session, rt_id: int) -> AssetRacktables:
    row = db.get(AssetRacktables, rt_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="подключение RackTables не найдено")
    return row


def _fill(row: AssetRacktables, payload: RtIn) -> None:
    """Смена адреса или учётки без нового пароля отклоняется: иначе сохранённый пароль учётки AD
    ушёл бы по Basic на любой адрес, который впишут в форму."""
    if row.password and not payload.password and (row.url != payload.url or row.username != payload.username):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="при смене адреса или учётной записи введите пароль заново")
    for name, value in payload.model_dump(exclude={"password"}).items():
        setattr(row, name, value)
    if payload.password:
        row.password = encrypt(payload.password)


@router.get("", response_model=list[RtView])
def list_rt(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[RtView]:
    rows = list(db.execute(select(AssetRacktables).order_by(AssetRacktables.id)).scalars())
    ids = [r.schedule_id for r in rows if r.schedule_id is not None]
    schedules = {s.id: s for s in db.execute(select(PlatformSchedule).where(PlatformSchedule.id.in_(ids))).scalars()} if ids else {}
    return [_view(r, schedules.get(r.schedule_id) if r.schedule_id is not None else None) for r in rows]


@router.post("", response_model=RtView, status_code=status.HTTP_201_CREATED)
def post_rt(payload: RtIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> RtView:
    row = AssetRacktables()
    _fill(row, payload)
    db.add(row)
    db.commit()
    return _one(db, row)


@router.put("/{rt_id}", response_model=RtView)
def put_rt(rt_id: int, payload: RtIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> RtView:
    row = _row(db, rt_id)
    _fill(row, payload)
    db.commit()
    return _one(db, row)


def _drop_schedule(db: Session, row: AssetRacktables) -> None:
    ids = set(db.execute(
        select(PlatformSchedule.id).where(PlatformSchedule.module == "assets", PlatformSchedule.kind == "rt", PlatformSchedule.target_id == row.id)
    ).scalars())
    if row.schedule_id is not None:
        ids.add(row.schedule_id)
    row.schedule_id = None
    db.flush()
    for schedule_id in ids:
        delete_schedule(db, schedule_id)


@router.delete("/{rt_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_rt(rt_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> Response:
    row = _row(db, rt_id)
    _drop_schedule(db, row)
    db.delete(row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{rt_id}/check", response_model=RtCheck)
def check(rt_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> RtCheck:
    """`getAPIVersion` сохранёнными учётными данными: 502 с текстом ошибки API."""
    row = _row(db, rt_id)
    try:
        with client(row) as api:
            return RtCheck(version=api.version())
    except RtError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from None


@router.post("/{rt_id}/run", response_model=RtStarted, status_code=status.HTTP_202_ACCEPTED)
def run_now(rt_id: int, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> RtStarted:
    row = _row(db, rt_id)
    try:
        return RtStarted(job_id=start_rt(db, row, user.login))
    except (RtBusy, RtDisabled) as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None


@router.put("/{rt_id}/schedule", response_model=ScheduleView)
def put_schedule(rt_id: int, payload: ScheduleIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ScheduleView:
    row = _row(db, rt_id)
    try:
        sched = upsert_schedule(
            db, module="assets", kind="rt", target_id=row.id, interval_hours=payload.interval_hours,
            window_from=payload.window_from or None, window_to=payload.window_to or None, enabled=payload.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from None
    row.schedule_id = sched.id
    db.commit()
    return schedule_view(sched)


@router.delete("/{rt_id}/schedule", status_code=status.HTTP_204_NO_CONTENT)
def remove_schedule(rt_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> Response:
    row = _row(db, rt_id)
    _drop_schedule(db, row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
