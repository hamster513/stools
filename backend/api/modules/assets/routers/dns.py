"""DNS-серверы Assets: прямые и обратные запросы (`direct`) или чтение зон AD (`ad`), запуск
вручную и расписание (спека §4, §6)."""
from __future__ import annotations

import datetime as dt
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.hosts import validate_host
from api.modules.ad.models import AdConnection
from api.modules.assets.models import AssetDns
from api.modules.assets.services.dns import DnsBusy, DnsDisabled, start_dns
from api.platform.schedule_views import ScheduleIn, ScheduleView, schedule_view
from api.platform.scheduler import PlatformSchedule, delete_schedule, upsert_schedule

router = APIRouter(prefix="/dns", tags=["assets"])


def _zone(value: str) -> str:
    zone = value.strip().rstrip(".").lower()
    try:
        return validate_host(zone)
    except ValueError:
        raise ValueError(f"зона «{value}» — не DNS-имя") from None


class DnsIn(BaseModel):
    title: str = Field(default="", max_length=255)
    mode: Literal["direct", "ad"] = "direct"
    #: Имя или адрес сервера для direct; пусто — системный резолвер.
    server: str = Field(default="", max_length=255)
    ad_connection_id: int | None = None
    zones: list[str] = Field(default_factory=list, max_length=100)
    forward: bool = True
    reverse: bool = True
    zone_read: bool = False
    rate_per_s: int = Field(default=50, ge=1, le=1000)
    timeout_ms: int = Field(default=3000, ge=100, le=30000)
    enabled: bool = True

    @field_validator("server")
    @classmethod
    def check_server(cls, value: str) -> str:
        return validate_host(value) if value.strip() else ""

    @field_validator("zones")
    @classmethod
    def check_zones(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(_zone(v) for v in value if v.strip()))

    @model_validator(mode="after")
    def check_mode(self) -> DnsIn:
        if self.mode == "direct" and not (self.forward or self.reverse):
            raise ValueError("включите прямые или обратные запросы")
        if self.mode == "ad":
            if self.ad_connection_id is None:
                raise ValueError("для зон AD выберите подключение AD")
            if not self.zones:
                raise ValueError("укажите хотя бы одну зону")
            if not self.zone_read:
                raise ValueError("для режима AD включите чтение зон")
        return self


class DnsView(BaseModel):
    id: int
    title: str
    mode: str
    server: str
    ad_connection_id: int | None
    zones: list[str]
    forward: bool
    reverse: bool
    zone_read: bool
    rate_per_s: int
    timeout_ms: int
    enabled: bool
    schedule_id: int | None
    last_run_at: dt.datetime | None
    schedule: ScheduleView | None


class DnsStarted(BaseModel):
    job_id: int


def _view(row: AssetDns, sched: PlatformSchedule | None) -> DnsView:
    return DnsView(
        id=row.id, title=row.title, mode=row.mode, server=row.server, ad_connection_id=row.ad_connection_id, zones=list(row.zones or []),
        forward=row.forward, reverse=row.reverse, zone_read=row.zone_read, rate_per_s=row.rate_per_s, timeout_ms=row.timeout_ms,
        enabled=row.enabled, schedule_id=row.schedule_id, last_run_at=row.last_run_at,
        schedule=schedule_view(sched) if sched is not None else None,
    )


def _one(db: Session, row: AssetDns) -> DnsView:
    return _view(row, db.get(PlatformSchedule, row.schedule_id) if row.schedule_id is not None else None)


def _row(db: Session, dns_id: int) -> AssetDns:
    row = db.get(AssetDns, dns_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="DNS-сервер не найден")
    return row


def _fill(db: Session, row: AssetDns, payload: DnsIn) -> None:
    if payload.ad_connection_id is not None and db.get(AdConnection, payload.ad_connection_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="подключение AD не найдено")
    for name, value in payload.model_dump().items():
        setattr(row, name, value)


@router.get("", response_model=list[DnsView])
def list_dns(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> list[DnsView]:
    rows = list(db.execute(select(AssetDns).order_by(AssetDns.id)).scalars())
    ids = [r.schedule_id for r in rows if r.schedule_id is not None]
    schedules = {s.id: s for s in db.execute(select(PlatformSchedule).where(PlatformSchedule.id.in_(ids))).scalars()} if ids else {}
    return [_view(r, schedules.get(r.schedule_id) if r.schedule_id is not None else None) for r in rows]


@router.post("", response_model=DnsView, status_code=status.HTTP_201_CREATED)
def post_dns(payload: DnsIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> DnsView:
    row = AssetDns()
    _fill(db, row, payload)
    db.add(row)
    db.commit()
    return _one(db, row)


@router.put("/{dns_id}", response_model=DnsView)
def put_dns(dns_id: int, payload: DnsIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> DnsView:
    row = _row(db, dns_id)
    _fill(db, row, payload)
    db.commit()
    return _one(db, row)


def _drop_schedule(db: Session, row: AssetDns) -> None:
    ids = set(db.execute(
        select(PlatformSchedule.id).where(PlatformSchedule.module == "assets", PlatformSchedule.kind == "dns", PlatformSchedule.target_id == row.id)
    ).scalars())
    if row.schedule_id is not None:
        ids.add(row.schedule_id)
    row.schedule_id = None
    db.flush()
    for schedule_id in ids:
        delete_schedule(db, schedule_id)


@router.delete("/{dns_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_dns(dns_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> Response:
    row = _row(db, dns_id)
    _drop_schedule(db, row)
    db.delete(row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{dns_id}/run", response_model=DnsStarted, status_code=status.HTTP_202_ACCEPTED)
def run_now(dns_id: int, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> DnsStarted:
    row = _row(db, dns_id)
    try:
        return DnsStarted(job_id=start_dns(db, row, user.login))
    except (DnsBusy, DnsDisabled) as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None


@router.put("/{dns_id}/schedule", response_model=ScheduleView)
def put_schedule(dns_id: int, payload: ScheduleIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ScheduleView:
    row = _row(db, dns_id)
    try:
        sched = upsert_schedule(
            db, module="assets", kind="dns", target_id=row.id, interval_hours=payload.interval_hours,
            window_from=payload.window_from or None, window_to=payload.window_to or None, enabled=payload.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from None
    row.schedule_id = sched.id
    db.commit()
    return schedule_view(sched)


@router.delete("/{dns_id}/schedule", status_code=status.HTTP_204_NO_CONTENT)
def remove_schedule(dns_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> Response:
    row = _row(db, dns_id)
    _drop_schedule(db, row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
