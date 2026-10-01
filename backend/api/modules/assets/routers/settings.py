"""Пороги расхождений и синхронизация после импорта модулей (спека §1 `asset_settings`)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.assets.services.assets import DEFAULT_SETTINGS, load_settings, save_settings

router = APIRouter(prefix="/settings", tags=["assets"])


class AssetSettingsIn(BaseModel):
    #: Компьютер AD без входа и без других источников дольше — «неактивный».
    inactive_days: int = Field(ge=1, le=3650)
    #: Наблюдение старше опорного на столько дней — «данные устарели», моложе — «источники расходятся».
    stale_days: int = Field(ge=0, le=3650)
    #: Синхронизация с модулями сама после каждого импорта VM, KSC и AD.
    sync_after_import: bool


@router.get("", response_model=AssetSettingsIn)
def get_settings(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> AssetSettingsIn:
    data = load_settings(db)
    return AssetSettingsIn(**{k: data[k] for k in DEFAULT_SETTINGS})


@router.put("", response_model=AssetSettingsIn)
def put_settings(payload: AssetSettingsIn, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> AssetSettingsIn:
    saved = save_settings(db, payload.model_dump())
    db.commit()
    return AssetSettingsIn(**saved)
