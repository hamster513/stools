import json
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session

from api.crypto import decrypt
from api.db.models import AppSetting
from api.platform.secret_fields import put_setting, seal_secrets, secrets_again

SETTING_KEY = "vm_trends_connection"
SECRET_FIELDS = ("token", "proxy_password")


class TrendConnectionIn(BaseModel):
    url: str = Field(default="", max_length=512)
    token: str = Field(default="", max_length=2048)
    ca_pem: str = Field(default="", max_length=65536)
    proxy_enabled: bool = False
    proxy_scheme: Literal["http", "https"] = "http"
    proxy_host: str = Field(default="", max_length=255)
    proxy_port: int = Field(default=3128, ge=1, le=65535)
    proxy_username: str = Field(default="", max_length=255)
    proxy_password: str = Field(default="", max_length=2048)
    proxy_ca_pem: str = Field(default="", max_length=65536)
    clear_token: bool = False
    clear_proxy_password: bool = False

    @model_validator(mode="after")
    def validate_connection(self) -> Any:
        if self.url:
            parts = urlsplit(self.url)
            if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
                    or parts.query or parts.fragment or parts.path not in ("", "/")):
                raise ValueError("нужен HTTPS-адрес сборщика без логина, пароля и пути")
            if parts.port is not None and not 1 <= parts.port <= 65535:
                raise ValueError("неверный порт сборщика")
            self.url = self.url.rstrip("/")
        if self.proxy_enabled and not self.proxy_host:
            raise ValueError("укажите адрес прокси")
        if any(char in self.proxy_host for char in "/@?# \t\r\n"):
            raise ValueError("адрес прокси задаётся отдельно от порта и учётных данных")
        return self

    @property
    def configured(self) -> Any:
        return bool(self.url and self.token)

    def unsealed(self) -> Any:
        return self.model_copy(update={field: decrypt(getattr(self, field)) for field in SECRET_FIELDS})


TrendConnection = TrendConnectionIn


def load_connection(db: Session) -> TrendConnection:
    row = db.get(AppSetting, SETTING_KEY)
    return TrendConnection.model_validate_json(row.value_json) if row else TrendConnection()


def public_connection(connection: Any) -> Any:
    data = connection.model_dump(exclude=set(SECRET_FIELDS) | {"clear_token", "clear_proxy_password"})
    return {**data, "token_set": bool(connection.token), "proxy_password_set": bool(connection.proxy_password),
            "configured": connection.configured}


def merge_connection(old: Any, new: Any) -> Any:
    if secrets_again(old, new, ("url",), ("token",)) and not new.clear_token:
        raise ValueError("при смене адреса сборщика введите токен заново")
    if secrets_again(old, new, ("proxy_host", "proxy_scheme", "proxy_port", "proxy_username"), ("proxy_password",)) and not new.clear_proxy_password:
        raise ValueError("при смене прокси введите его пароль заново")
    secrets = seal_secrets(old, new, SECRET_FIELDS)
    if new.clear_token:
        secrets["token"] = ""
    if new.clear_proxy_password:
        secrets["proxy_password"] = ""
    return new.model_copy(update={**secrets, "clear_token": False, "clear_proxy_password": False})


def save_connection(db: Session, value: Any, actor: Any) -> Any:
    connection = merge_connection(load_connection(db), value)
    put_setting(db, SETTING_KEY, json.dumps(connection.model_dump()), actor)
    return connection
