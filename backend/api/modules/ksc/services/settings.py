"""Настройки проверок модуля KSC в `app_setting['ksc']`."""
from __future__ import annotations

import datetime as dt

from sqlalchemy.orm import Session

from api.db.models import AppSetting
from api.modules.ksc.core.config import KscConfig

KSC_KEY = "ksc"


def load_config(db: Session) -> KscConfig:
    row = db.get(AppSetting, KSC_KEY)
    if row is None or not row.value_json or row.value_json == "{}":
        return KscConfig()
    return KscConfig.model_validate_json(row.value_json)


def save_config(db: Session, cfg: KscConfig, login: str | None) -> KscConfig:
    row = db.get(AppSetting, KSC_KEY)
    if row is None:
        row = AppSetting(key=KSC_KEY)
        db.add(row)
    row.value_json = cfg.model_dump_json()
    row.updated_at = dt.datetime.now(dt.UTC)
    row.updated_by = login
    db.commit()
    return cfg
