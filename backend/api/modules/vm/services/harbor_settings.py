"""Подключение к Harbor в `app_setting['vm_harbor']`.

Секрет робота хранится зашифрованным (api/crypto.py); расшифровывается только для
обращения к Harbor (`HarborConnection.unsealed`). Наружу он не отдаётся никогда —
только признак «задан». Шаблон тот же, что у `vm/services/settings.py`.
"""
from __future__ import annotations

import datetime as dt
import re

from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from api.crypto import decrypt, encrypt, reseal
from api.db.models import AppSetting

SETTING_KEY = "vm_harbor"

#: Поля, от которых зависит, куда уйдёт секрет.
ADDRESS_FIELDS = ("url", "robot_name", "verify_tls")
SECRET_FIELDS = ("robot_secret",)
SECRETS_AGAIN = "при смене адреса секрет робота нужно ввести заново"

DEFAULT_TAGS_PER_REPO = 10
#: Имя проекта Harbor: строчные буквы, цифры, точка, дефис, подчёркивание.
_PROJECT = re.compile(r"[a-z0-9._-]{1,255}")


class SecretsRequired(ValueError):
    pass


class HarborConnection(BaseModel):
    url: str = ""
    #: Имя робота Harbor, например `robot$reader`.
    robot_name: str = ""
    robot_secret: str = ""
    verify_tls: bool = True
    #: Проекты для сбора; пусто — все, к которым у робота есть доступ.
    projects: list[str] = Field(default_factory=list)
    #: Сколько последних тегов репозитория брать в образы.
    tags_per_repo: int = DEFAULT_TAGS_PER_REPO

    @property
    def configured(self) -> bool:
        return bool(self.url.strip() and self.robot_name.strip() and self.robot_secret)

    def unsealed(self) -> HarborConnection:
        """Копия с расшифрованным секретом — для обращения к Harbor, не для записи."""
        return self.model_copy(update={f: decrypt(getattr(self, f)) for f in SECRET_FIELDS})


class HarborConnectionIn(HarborConnection):
    """Подключение из формы: адрес проверяется, пустой — «не настроено»."""

    url: str = Field(default="", max_length=512)
    robot_name: str = Field(default="", max_length=128)
    tags_per_repo: int = Field(default=DEFAULT_TAGS_PER_REPO, ge=1, le=100)

    @field_validator("url")
    @classmethod
    def check_url(cls, value: str) -> str:
        url = value.strip()
        if not url:
            return ""
        if not url.startswith(("http://", "https://")):
            raise ValueError("адрес Harbor — http:// или https://, например https://harbor.example.local")
        if url.endswith("/"):
            raise ValueError("адрес Harbor — без завершающего «/»")
        return url

    @field_validator("robot_name")
    @classmethod
    def check_robot(cls, value: str) -> str:
        return value.strip()

    @field_validator("robot_secret")
    @classmethod
    def check_secret(cls, value: str) -> str:
        """Секрет — печатная латиница: прочее не уходит в заголовок Basic."""
        secret = value.strip()
        if not secret.isascii() or not secret.isprintable():
            raise ValueError("секрет робота: только латинские буквы, цифры и знаки")
        return secret

    @field_validator("projects")
    @classmethod
    def check_projects(cls, value: list[str]) -> list[str]:
        out: list[str] = []
        for raw in value:
            name = raw.strip()
            if not _PROJECT.fullmatch(name):
                raise ValueError("проект Harbor: строчные латинские буквы, цифры, «.», «_», «-»")
            if name not in out:
                out.append(name)
        return out


def load_harbor(db: Session) -> HarborConnection:
    row = db.get(AppSetting, SETTING_KEY)
    if row is None or not row.value_json or row.value_json == "{}":
        return HarborConnection()
    return HarborConnection.model_validate_json(row.value_json)


def changed_fields(current: HarborConnection, incoming: HarborConnectionIn) -> list[str]:
    """Имена изменённых полей для журнала; пустой секрет — «не трогать»."""
    changed = []
    for name in HarborConnection.model_fields:
        new = getattr(incoming, name)
        if new != getattr(current, name) and (name not in SECRET_FIELDS or new):
            changed.append(name)
    return changed


def save_harbor(db: Session, incoming: HarborConnectionIn, updated_by: str | None) -> HarborConnection:
    """Сохранить, оставив прежний секрет, если новый пришёл пустым: форма его не показывает.

    Исключение — смена адреса или робота: прежний секрет на новый адрес не уходит,
    его нужно ввести заново (`SecretsRequired`)."""
    old = load_harbor(db)
    if incoming.url and any(getattr(incoming, f) != getattr(old, f) for f in ADDRESS_FIELDS) and any(
        getattr(old, f) and not getattr(incoming, f) for f in SECRET_FIELDS
    ):
        raise SecretsRequired(SECRETS_AGAIN)
    merged = HarborConnection(**incoming.model_dump())
    #: Новый секрет шифруется; прежний — тоже, если лежал открытым.
    for f in SECRET_FIELDS:
        new_value = getattr(merged, f)
        setattr(merged, f, encrypt(new_value) if new_value else reseal(getattr(old, f)))
    row = db.get(AppSetting, SETTING_KEY)
    if row is None:
        row = AppSetting(key=SETTING_KEY)
        db.add(row)
    row.value_json = merged.model_dump_json()
    row.updated_at = dt.datetime.now(dt.UTC)
    row.updated_by = updated_by
    db.commit()
    return merged
