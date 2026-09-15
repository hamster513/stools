"""Настройки безопасности: срок сессии, таймаут бездействия, хранение журнала.

В базе, как и остальные настройки: их меняет администратор из интерфейса.
Пока настройку ни разу не сохраняли, действуют дефолты самой модели
`SecuritySettings` (12 часов и т.д.) — `Settings.session_ttl_hours` из
окружения (`api/settings.py`) с этой задачи не читается.
"""
from __future__ import annotations

import json

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.db.models import AppSetting
from api.llm_settings import read_setting

SECURITY_KEY = "security"


class SecuritySettings(BaseModel):
    session_ttl_hours: int = Field(default=12, ge=1, le=24 * 30)
    #: 0 — таймаута нет.
    idle_timeout_minutes: int = Field(default=0, ge=0, le=24 * 60)
    audit_retention_days: int = Field(default=90, ge=1, le=3650)


class SecuritySettingsIn(BaseModel):
    """PUT: любое поле можно опустить — остальные сохраняют значение."""

    session_ttl_hours: int | None = Field(default=None, ge=1, le=24 * 30)
    idle_timeout_minutes: int | None = Field(default=None, ge=0, le=24 * 60)
    audit_retention_days: int | None = Field(default=None, ge=1, le=3650)


def load_security(db: Session) -> SecuritySettings:
    return SecuritySettings.model_validate_json(read_setting(db, SECURITY_KEY) or "{}")


def save_security(db: Session, payload: SecuritySettingsIn, login: str | None) -> SecuritySettings:
    merged = load_security(db).model_copy(update=payload.model_dump(exclude_none=True))
    row = db.get(AppSetting, SECURITY_KEY) or AppSetting(key=SECURITY_KEY)
    row.value_json = json.dumps(merged.model_dump())
    row.updated_by = login
    db.add(row)
    db.commit()
    return merged
