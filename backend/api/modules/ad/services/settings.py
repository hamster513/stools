"""Настройки проверок модуля AD в `app_setting['ad']`."""
from __future__ import annotations

import datetime as dt

from sqlalchemy.orm import Session

from api.db.models import AppSetting
from api.modules.ad.core.config import AdConfig

AD_KEY = "ad"


def load_config(db: Session) -> AdConfig:
    row = db.get(AppSetting, AD_KEY)
    if row is None or not row.value_json or row.value_json == "{}":
        return AdConfig()
    return AdConfig.model_validate_json(row.value_json)


def save_config(db: Session, cfg: AdConfig, login: str | None) -> AdConfig:
    row = db.get(AppSetting, AD_KEY)
    if row is None:
        row = AppSetting(key=AD_KEY)
        db.add(row)
    row.value_json = cfg.model_dump_json()
    row.updated_at = dt.datetime.now(dt.UTC)
    row.updated_by = login
    db.commit()
    return cfg
