"""Схемы расписания платформы в API модулей: вход формы и вид строки `platform_schedule`.

Одни на все цели — сети и DNS-серверы Assets, подключения KSC и AD: блок расписания
на фронте тоже один.
"""
from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, Field

from api.platform.scheduler import PlatformSchedule
from api.settings import get_settings


class ScheduleIn(BaseModel):
    interval_hours: int = Field(ge=1, le=720)
    #: HH:MM в поясе STOOLS_TZ; оба пустые — без окна.
    window_from: str | None = None
    window_to: str | None = None
    enabled: bool = True


class ScheduleView(BaseModel):
    weekdays: list[int] = []
    run_time: str | None = None
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


def schedule_view(s: PlatformSchedule) -> ScheduleView:
    return ScheduleView(
        weekdays=[int(day) for day in s.weekdays or ""], run_time=s.run_time, id=s.id, interval_hours=s.interval_hours, window_from=s.window_from, window_to=s.window_to, enabled=s.enabled,
        next_run_at=s.next_run_at, last_run_at=s.last_run_at, last_job_id=s.last_job_id, tz=get_settings().tz,
    )
