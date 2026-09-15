"""Настройки сервиса.

Настройки модели переехали в /api/settings/llm — они общие для платформы,
а не только для SIEM. Здесь остаётся только своё: параметры разметки ATT&CK.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.attack.services.attack_bundle import current as current_bundle
from api.modules.siem.services.appsettings import AppSettingsPayload, load_all, save_all

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("")
def get_settings_(
    db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)
) -> dict[str, Any]:
    payload = load_all(db)
    out = payload.model_dump()
    # Версия бандла — не настройка, а факт о вложенных данных; показывается
    # рядом, потому что подтверждённая разметка привязана именно к ней.
    out["attack"]["attack_version"] = current_bundle(db).version
    return out


@router.put("", status_code=status.HTTP_204_NO_CONTENT)
def put_settings(
    payload: AppSettingsPayload,
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> None:
    save_all(db, payload, user.login)
