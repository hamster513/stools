"""Настройки Threat Hunting: окно ночного прогона, паузы, повторы, срок хранения."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from pydantic import ValidationError
from sqlalchemy.orm import Session

from api.audit import changes_summary
from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.siem.hunting.settings import (
    ThSettings,
    load_th_settings,
    nightly_schedule,
    save_th_settings,
)
from api.platform.schedule_views import ScheduleView, schedule_view

router = APIRouter(prefix="/settings", tags=["siem"])
log = logging.getLogger(__name__)


class ThSettingsView(ThSettings):
    schedule: ScheduleView | None = None


def _load(db: Session) -> ThSettings:
    """Испорченный JSON в базе не должен закрывать страницу настроек: показываем умолчания, и человек пересохранит."""
    try:
        return load_th_settings(db)
    except ValidationError:
        log.warning("настройки Threat Hunting в базе не читаются, показаны умолчания")
        return ThSettings()


def _view(db: Session, data: ThSettings) -> ThSettingsView:
    schedule = nightly_schedule(db)
    return ThSettingsView(**data.model_dump(), schedule=schedule_view(schedule) if schedule is not None else None)


@router.get("", response_model=ThSettingsView)
def get_settings(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> ThSettingsView:
    return _view(db, _load(db))


@router.put("", response_model=ThSettingsView)
def put_settings(
    payload: ThSettings, request: Request, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user),
) -> ThSettingsView:
    current = _load(db)
    request.state.audit_summary = changes_summary(
        [name for name in ThSettings.model_fields if getattr(payload, name) != getattr(current, name)],
    )
    return _view(db, save_th_settings(db, payload, user.login))
