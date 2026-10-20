"""Планировщик Threat Hunting: расписание ночного прогона и очередь хантов на одном экране.

Расписание хранится в настройках раздела (`hunting.settings`), порядок — в `ThHunt.position`.
Здесь только HTTP: оба экранных куска собираются в один ответ, чтобы страница обновлялась одним запросом.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from api.audit import changes_summary
from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.siem.hunting import library as lib
from api.modules.siem.hunting.models import ThRunQuery
from api.modules.siem.hunting.settings import (
    ThSettings,
    nightly_schedule,
    save_th_settings,
)
from api.modules.siem.routers.hunting.library import _last_run, _latest_runs, _query_counts
from api.modules.siem.routers.hunting.settings import _load
from api.platform.schedule_views import schedule_view
from api.settings import get_settings

router = APIRouter(prefix="/scheduler", tags=["siem"])

ORDER_MISMATCH = "набор хантов не совпадает"


class SchedulerIn(BaseModel):
    nightly_enabled: bool
    window_from: str
    hunt_pause_s: int = Field(ge=1)

    @field_validator("window_from")
    @classmethod
    def check_time(cls, value: str) -> str:
        # Формат времени один с настройками раздела: правило не дублируем.
        return ThSettings.check_time(value)


class OrderIn(BaseModel):
    ids: list[int]


class QueueRow(BaseModel):
    id: int
    code: str
    name: str
    technique_id: str | None
    enabled: bool
    queries: int
    last_run: dict[str, Any] | None
    position: int


class SchedulerOut(BaseModel):
    nightly_enabled: bool
    window_from: str
    hunt_pause_s: int
    next_run_at: dt.datetime | None
    tz: str
    hunts: list[QueueRow]


def _out(db: Session, data: ThSettings) -> SchedulerOut:
    hunts = lib.list_hunts(db)
    counts = _query_counts(db, [h.id for h in hunts])
    last = _latest_runs(db, ThRunQuery.hunt_code, [h.code for h in hunts])
    schedule = nightly_schedule(db)
    # Строки расписания может не быть, пока настройки ни разу не сохранялись: тогда срока нет.
    view = None if schedule is None else schedule_view(schedule)
    return SchedulerOut(
        nightly_enabled=data.nightly_enabled, window_from=data.window_from, hunt_pause_s=data.hunt_pause_s,
        next_run_at=None if view is None else view.next_run_at, tz=get_settings().tz,
        hunts=[
            QueueRow(
                id=h.id, code=h.code, name=h.name, technique_id=h.technique_id, enabled=h.enabled,
                queries=counts.get(h.id, 0), last_run=_last_run(last.get(h.code)), position=h.position,
            )
            for h in hunts
        ],
    )


@router.get("", response_model=SchedulerOut)
def get_scheduler(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> SchedulerOut:
    return _out(db, _load(db))


@router.put("", response_model=SchedulerOut)
def put_scheduler(
    payload: SchedulerIn, request: Request, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> SchedulerOut:
    # Испорченные настройки в базе не закрывают страницу: как в разделе настроек, берём умолчания.
    current = _load(db)
    # Остальные настройки раздела (повторы, срок хранения, срезы) страница не показывает и не трогает.
    new = current.model_copy(update=payload.model_dump())
    request.state.audit_summary = changes_summary(
        [name for name in SchedulerIn.model_fields if getattr(new, name) != getattr(current, name)],
    )
    return _out(db, save_th_settings(db, new, user.login))


@router.put("/order", response_model=SchedulerOut)
def put_order(
    payload: OrderIn, request: Request, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> SchedulerOut:
    hunts = {h.id: h for h in lib.list_hunts(db)}
    # Дубль id оставил бы чей-то хант без позиции: длина списка должна совпасть с числом хантов, а не только набор.
    if len(payload.ids) != len(hunts) or set(payload.ids) != set(hunts):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=ORDER_MISMATCH)
    for index, hunt_id in enumerate(payload.ids):
        hunts[hunt_id].position = index
    db.commit()
    request.state.audit_summary = "порядок очереди хантов изменён"
    return _out(db, _load(db))
