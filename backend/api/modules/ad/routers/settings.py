"""Правила проверок модуля AD."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.ad.core.checks import CHECKS
from api.modules.ad.core.config import AdConfig
from api.modules.ad.services.settings import load_config, save_config

router = APIRouter(prefix="/settings", tags=["ad"])


@router.get("")
def get_settings_(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    return {
        "config": load_config(db).model_dump(),
        "defaults": AdConfig().model_dump(),
        "checks": [{"code": c.code, "title": c.title, "description": c.description} for c in CHECKS],
    }


@router.put("")
def put_settings(payload: AdConfig, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    return {"config": save_config(db, payload, user.login).model_dump()}
