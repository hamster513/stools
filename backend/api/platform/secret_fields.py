"""Общее для настроек с секретами в `app_setting`: когда секрет нужно ввести заново,
как запечатать секреты при записи и как записать строку настройки.

Чистые функции, без знания о конкретном модуле: модуль говорит, какие поля задают
адрес, а какие — секреты.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy.orm import Session

from api.crypto import encrypt, reseal
from api.db.models import AppSetting


def secrets_again(old: Any, new: Any, address_fields: tuple[str, ...], secret_fields: tuple[str, ...]) -> bool:
    """Смена адреса не должна унести прежний секрет на новый адрес.

    Истина, когда в `new` задан адрес (первое из `address_fields`), хоть одно из
    `address_fields` изменилось, а какой-то секрет, бывший в `old`, пришёл пустым.
    """
    if not getattr(new, address_fields[0]):
        return False
    if all(getattr(new, f) == getattr(old, f) for f in address_fields):
        return False
    return any(getattr(old, f) and not getattr(new, f) for f in secret_fields)


def seal_secrets(current: Any, new: Any, secret_fields: tuple[str, ...]) -> dict[str, str]:
    """Значения секретных полей для записи: новый шифруется, а пустой («не трогать»)
    заменяется прежним, который тоже шифруется, если лежал открытым."""
    out: dict[str, str] = {}
    for f in secret_fields:
        value = getattr(new, f)
        out[f] = encrypt(value) if value else reseal(getattr(current, f))
    return out


def put_setting(db: Session, key: str, value_json: str, updated_by: str | None) -> None:
    """Записать (создать или заменить) настройку `key` и зафиксировать транзакцию."""
    row = db.get(AppSetting, key)
    if row is None:
        row = AppSetting(key=key)
        db.add(row)
    row.value_json = value_json
    row.updated_at = dt.datetime.now(dt.UTC)
    row.updated_by = updated_by
    db.commit()
