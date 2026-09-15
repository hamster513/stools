"""Настройки входа через OIDC.

Секрет клиента наружу не отдаётся: в ответах он заменён маской, а PUT с
маской или пустым значением оставляет сохранённый — иначе любая правка
формы стирала бы секрет."""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from fastapi import HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from api.db.models import ROLES, AppSetting
from api.llm_settings import read_setting

OIDC_KEY = "oidc"
SECRET_MASK = "••••"
CALLBACK_PATH = "/api/auth/oidc/callback"
#: По http пускаем только разработку на своей машине: по этим адресам ходят
#: id_token, код авторизации и сессионная кука.
LOCAL_HOSTS = ("localhost", "127.0.0.1")


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


class GroupRole(BaseModel):
    group: str = Field(min_length=1, max_length=255)
    role: str

    @field_validator("role")
    @classmethod
    def _role(cls, value: str) -> str:
        if value not in ROLES:
            raise ValueError(f"роль должна быть одной из: {', '.join(ROLES)}")
        return value


class OidcSettings(BaseModel):
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
    group_roles: list[GroupRole] = Field(default_factory=list)

    @field_validator("public_url", "issuer_url")
    @classmethod
    def _secure_url(cls, value: str) -> str:
        return require_secure_url(value)

    @property
    def redirect_uri(self) -> str:
        return self.public_url.rstrip("/") + CALLBACK_PATH

    @property
    def configured(self) -> bool:
        return bool(self.public_url and self.issuer_url and self.client_id and self.client_secret and self.group_roles)

    def missing(self) -> list[str]:
        out = [name for name in ("public_url", "issuer_url", "client_id", "client_secret") if not getattr(self, name)]
        if not self.group_roles:
            out.append("group_roles")
        return out


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
        merged.client_secret = current.client_secret
    if merged.enabled and merged.missing():
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="нельзя включить OIDC без полей: " + ", ".join(merged.missing()),
        )
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
