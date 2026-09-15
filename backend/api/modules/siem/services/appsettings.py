"""Настройки сервиса, хранимые в базе.

В базе, а не в переменных окружения, по одной причине: адрес модели задаёт
человек через интерфейс. Настройка, которую меняют пересборкой контейнера,
настройкой не является.

Пустой `base_url` — законное состояние, а не ошибка. Без модели работает
всё, кроме предложений по разметке: разбор, анализ и отбор кандидатов
детерминированы. Исходящих обращений по умолчанию нет.
"""
from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.db.models import AppSetting
from api.llm_settings import LLM_KEY, LlmSettings, load_llm, read_setting
from kbaudit.attack.candidates import DEFAULT_TOP_K

__all__ = [
    "ATTACK_KEY",
    "LLM_KEY",
    "AppSettingsPayload",
    "AttackSettings",
    "LlmSettings",
    "load_all",
    "load_attack",
    "load_llm",
    "save_all",
]

ATTACK_KEY = "attack"


class AttackSettings(BaseModel):
    #: Сколько техник класть в промпт. Значение подобрано измерением полноты
    #: на эталонной разметке: от 15 до 40 полнота не растёт.
    top_k: int = Field(default=DEFAULT_TOP_K, ge=3, le=50)


class AppSettingsPayload(BaseModel):
    attack: AttackSettings = Field(default_factory=AttackSettings)


def _read(db: Session, key: str, model: type[BaseModel]) -> BaseModel:
    raw = read_setting(db, key)
    return model() if raw is None else model.model_validate_json(raw)


def load_attack(db: Session) -> AttackSettings:
    return AttackSettings.model_validate(_read(db, ATTACK_KEY, AttackSettings).model_dump())


def load_all(db: Session) -> AppSettingsPayload:
    return AppSettingsPayload(attack=load_attack(db))


def save_all(db: Session, payload: AppSettingsPayload, login: str | None) -> None:
    now = dt.datetime.now(dt.UTC)
    row = db.get(AppSetting, ATTACK_KEY)
    if row is None:
        row = AppSetting(key=ATTACK_KEY)
        db.add(row)
    row.value_json = payload.attack.model_dump_json()
    row.updated_at = now
    row.updated_by = login
    db.commit()
