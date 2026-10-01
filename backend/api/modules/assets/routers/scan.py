"""Скан сети вручную и расписание сканов сети."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.assets.core import scanner
from api.modules.assets.models import Network
from api.modules.assets.services.scan import ScanBusy, ScanDisabled, start_scan
from api.platform.scheduler import PlatformSchedule, delete_schedule, upsert_schedule
from api.settings import get_settings

router = APIRouter(prefix="/networks", tags=["assets"])


class ScanStarted(BaseModel):
    job_id: int
    #: False — ICMP-сокет не открывается, скан идёт в режиме «только порты».
    icmp: bool


class ScheduleIn(BaseModel):
    interval_hours: int = Field(ge=1, le=720)
    #: HH:MM в поясе STOOLS_TZ; оба пустые — без окна.
    window_from: str | None = None
    window_to: str | None = None
    enabled: bool = True


class ScheduleView(BaseModel):
    id: int
    interval_hours: int
    window_from: str | None
    window_to: str | None
    enabled: bool
    next_run_at: dt.datetime | None
    last_run_at: dt.datetime | None
    last_job_id: int | None
    #: Пояс окна — STOOLS_TZ.
    tz: str


def _network(db: Session, network_id: int) -> Network:
    network = db.get(Network, network_id)
    if network is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="сеть не найдена")
    return network


def schedule_view(s: PlatformSchedule) -> ScheduleView:
    return ScheduleView(
        id=s.id, interval_hours=s.interval_hours, window_from=s.window_from, window_to=s.window_to, enabled=s.enabled,
        next_run_at=s.next_run_at, last_run_at=s.last_run_at, last_job_id=s.last_job_id, tz=get_settings().tz,
    )


@router.post("/{network_id}/scan", response_model=ScanStarted, status_code=status.HTTP_202_ACCEPTED)
def scan_now(network_id: int, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> ScanStarted:
    network = _network(db, network_id)
    icmp = scanner.icmp_available()
    try:
        job_id = start_scan(db, network, user.login)
    except (ScanBusy, ScanDisabled) as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None
    return ScanStarted(job_id=job_id, icmp=icmp)


@router.get("/{network_id}/schedule", response_model=ScheduleView | None)
def get_schedule(network_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ScheduleView | None:
    network = _network(db, network_id)
    sched = db.get(PlatformSchedule, network.schedule_id) if network.schedule_id is not None else None
    return schedule_view(sched) if sched is not None else None


@router.put("/{network_id}/schedule", response_model=ScheduleView)
def put_schedule(network_id: int, payload: ScheduleIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ScheduleView:
    network = _network(db, network_id)
    try:
        sched = upsert_schedule(
            db, module="assets", kind="scan", target_id=network.id, interval_hours=payload.interval_hours,
            window_from=payload.window_from or None, window_to=payload.window_to or None, enabled=payload.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from None
    network.schedule_id = sched.id
    db.commit()
    return schedule_view(sched)


@router.delete("/{network_id}/schedule", status_code=status.HTTP_204_NO_CONTENT)
def remove_schedule(network_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> Response:
    network = _network(db, network_id)
    if network.schedule_id is not None:
        schedule_id = network.schedule_id
        network.schedule_id = None
        db.flush()
        delete_schedule(db, schedule_id)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
