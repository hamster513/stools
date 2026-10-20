"""Подключение к MaxPatrol (PT KB и события) — в `app_setting['siem_mp']`.

Одно на инсталляцию, по образцу модуля VM: персональный API-токен
MaxPatrol шифруется (api/crypto.py) и расшифровывается только в момент
обращения к KB (`KbConnection.unsealed`). Наружу отдаётся только признак
«задан».
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from api.crypto import decrypt, encrypt, reseal
from api.db.models import AppSetting
from api.hosts import validate_host
from api.llm_settings import read_setting

MP_KEY = "siem_mp"
SECRET_FIELDS = ("api_token",)
#: Поля, от которых зависит, куда уйдёт токен.
ADDRESS_FIELDS = ("host", "kb_port", "verify_tls")
SECRETS_AGAIN = "при смене адреса API-токен нужно ввести заново"


class KbConnection(BaseModel):
    host: str = ""
    kb_port: int = Field(default=8091, ge=1, le=65535)
    #: Персональный токен доступа (pat_…), выпускается в консоли управления MaxPatrol.
    api_token: str = ""
    #: Как у VM: MaxPatrol обычно стоит на самоподписанном сертификате.
    verify_tls: bool = False

    @property
    def configured(self) -> bool:
        return bool(self.host.strip() and self.api_token)

    def unsealed(self) -> KbConnection:
        """Копия с расшифрованными секретами — для обращения к KB, не для записи."""
        return self.model_copy(update={f: decrypt(getattr(self, f)) for f in SECRET_FIELDS})


class KbConnectionIn(KbConnection):
    """Подключение из формы: адрес проверяется, пустой — «не настроено»."""

    @field_validator("host")
    @classmethod
    def check_host(cls, value: str) -> str:
        return validate_host(value) if value.strip() else ""

    @field_validator("api_token")
    @classmethod
    def check_token(cls, value: str) -> str:
        """Токен — печатная латиница: пробелы по краям срезаются, прочее не уходит в заголовок
        (не-ASCII символ ронял бы запрос с текстом, в котором виден сам токен)."""
        token = value.strip()
        if not token.isascii() or not token.isprintable():
            raise ValueError("API-токен: только латинские буквы, цифры и знаки")
        return token


class SecretsRequired(ValueError):
    pass


def load_connection(db: Session) -> KbConnection:
    raw = read_setting(db, MP_KEY)
    return KbConnection() if raw is None else KbConnection.model_validate_json(raw)


def changed_fields(current: KbConnection, incoming: KbConnectionIn) -> list[str]:
    """Имена изменённых полей для журнала; пустой секрет — «не трогать»."""
    return [
        name
        for name in KbConnection.model_fields
        if getattr(incoming, name) != getattr(current, name) and (name not in SECRET_FIELDS or getattr(incoming, name))
    ]


def save_connection(db: Session, incoming: KbConnectionIn, login: str | None) -> KbConnection:
    """Сохранить, оставив прежние секреты, если новые пришли пустыми: форма их
    не показывает, а значит, и не присылает. Смена адреса или учётной записи
    без новых секретов отклоняется: прежние на новый адрес не уходят."""
    current = load_connection(db)
    address_changed = any(getattr(incoming, f) != getattr(current, f) for f in ADDRESS_FIELDS)
    secrets_kept = any(getattr(current, f) and not getattr(incoming, f) for f in SECRET_FIELDS)
    if incoming.host and address_changed and secrets_kept:
        raise SecretsRequired(SECRETS_AGAIN)
    merged = KbConnection(**incoming.model_dump())
    for f in SECRET_FIELDS:
        new_value = getattr(merged, f)
        setattr(merged, f, encrypt(new_value) if new_value else reseal(getattr(current, f)))
    row = db.get(AppSetting, MP_KEY)
    if row is None:
        row = AppSetting(key=MP_KEY)
        db.add(row)
    row.value_json = merged.model_dump_json()
    row.updated_at = dt.datetime.now(dt.UTC)
    row.updated_by = login
    db.commit()
    return merged


def view(conn: KbConnection) -> dict[str, Any]:
    out = conn.model_dump(exclude=set(SECRET_FIELDS))
    out["api_token_set"] = bool(conn.api_token)
    out["configured"] = conn.configured
    return out
