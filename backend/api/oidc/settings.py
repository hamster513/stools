"""Настройки входа через OIDC.

Секрет клиента наружу не отдаётся: в ответах он заменён маской, а PUT с
маской или пустым значением оставляет сохранённый — иначе любая правка
формы стирала бы секрет. В базе он зашифрован (api/crypto.py) и
расшифровывается только для обмена кода на токены.

Права вошедшим дают группы `source='oidc'` (api/platform/services/access.py),
а не поле настроек: включить вход можно, только когда такая группа есть."""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from fastapi import HTTPException, status
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.crypto import encrypt, reseal
from api.db.models import AccessGroup, AppSetting
from api.llm_settings import read_setting

OIDC_KEY = "oidc"
SECRET_MASK = "••••"
CALLBACK_PATH = "/api/auth/oidc/callback"
#: По http пускаем только разработку на своей машине: по этим адресам ходят
#: id_token, код авторизации и сессионная кука.
LOCAL_HOSTS = ("localhost", "127.0.0.1")
NO_OIDC_GROUPS = "нет ни одной группы из OIDC"


def require_secure_url(value: str) -> str:
    """Адрес должен быть https (http:// — только для localhost).

    Общая проверка для полей настроек и для `POST /api/settings/oidc/test`:
    проверка связи не должна пускать по http то, что настройки бы отвергли.
    """
    if not value:
        return value
    parsed = urlsplit(value)
    if parsed.scheme == "https" or (parsed.scheme == "http" and parsed.hostname in LOCAL_HOSTS):
        return value
    raise ValueError("адрес должен начинаться с https:// (http:// — только для localhost)")


class OidcSettings(BaseModel):
    #: Лишние ключи отбрасываются: прежняя форма присылает `group_roles`.
    model_config = ConfigDict(extra="ignore")

    enabled: bool = False
    display_name: str = "Avanpost"
    public_url: str = ""
    issuer_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    scopes: str = "openid profile email groups"
    groups_claim: str = "groups"
    login_claim: str = "preferred_username"
    name_claim: str = "name"

    @field_validator("public_url", "issuer_url")
    @classmethod
    def _secure_url(cls, value: str) -> str:
        return require_secure_url(value)

    @property
    def redirect_uri(self) -> str:
        return self.public_url.rstrip("/") + CALLBACK_PATH

    @property
    def configured(self) -> bool:
        return bool(self.public_url and self.issuer_url and self.client_id and self.client_secret)

    def missing(self, has_groups: bool) -> list[str]:
        """Чего не хватает для включения: незаполненные поля и группы из OIDC."""
        out = [name for name in ("public_url", "issuer_url", "client_id", "client_secret") if not getattr(self, name)]
        if not has_groups:
            out.append(NO_OIDC_GROUPS)
        return out


def has_oidc_groups(db: Session) -> bool:
    return db.scalar(select(AccessGroup.id).where(AccessGroup.source == "oidc").limit(1)) is not None


class OidcSettingsIn(OidcSettings):
    """PUT: секрет может быть пустым или маской — тогда остаётся прежний."""


def load_oidc(db: Session) -> OidcSettings:
    return OidcSettings.model_validate_json(read_setting(db, OIDC_KEY) or "{}")


def public_view(settings: OidcSettings) -> dict[str, object]:
    out = settings.model_dump()
    out["has_secret"] = bool(settings.client_secret)
    out["client_secret"] = SECRET_MASK if settings.client_secret else ""
    out["redirect_uri"] = settings.redirect_uri
    return out


def save_oidc(db: Session, payload: OidcSettingsIn, login: str | None) -> OidcSettings:
    current = load_oidc(db)
    merged = OidcSettings.model_validate(payload.model_dump())
    if payload.client_secret in ("", SECRET_MASK):
        #: Секрет, сохранённый до шифрования, шифруется при этой записи.
        merged.client_secret = reseal(current.client_secret)
    else:
        merged.client_secret = encrypt(merged.client_secret)
    missing = merged.missing(has_oidc_groups(db)) if merged.enabled else []
    if missing:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="нельзя включить OIDC: " + ", ".join(missing))
    row = db.get(AppSetting, OIDC_KEY) or AppSetting(key=OIDC_KEY)
    row.value_json = json.dumps(merged.model_dump(), ensure_ascii=False)
    row.updated_by = login
    db.add(row)
    db.commit()
    #: Локальный импорт: api.oidc.provider сам импортирует этот модуль —
    #: на верхнем уровне вышел бы цикл импортов.
    from api.oidc.provider import invalidate_cache

    invalidate_cache()
    return merged
