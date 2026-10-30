"""Настройки модуля VM в `app_setting['vm']` (спека §7).

Персональный API-токен MaxPatrol хранится здесь же, зашифрованным
(api/crypto.py); расшифровывается только для обращения к VM
(`Connection.unsealed`). Наружу он не отдаётся никогда — только признак
«задан». Логин, пароль и client secret больше не нужны: MaxPatrol принимает
токен как Bearer напрямую.
"""
from __future__ import annotations

import json
import logging

from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from api.crypto import decrypt
from api.db.models import AppSetting
from api.hosts import validate_host
from api.modules.vm.core.weights import DEFAULT_THRESHOLD, Weights
from api.platform.secret_fields import put_setting, seal_secrets, secrets_again

VM_KEY = "vm"

log = logging.getLogger(__name__)
#: Предупреждение о старой схеме весов — один раз на процесс, а не на каждый запрос.
_old_weights_warned = False

#: Ниже этого риска пара не считается экспозицией в матрице ATT&CK.
DEFAULT_ATTACK_MIN_RISK = 40

#: Исключения по ОС из первой итерации: сетевое железо и рабочие станции,
#: которые VM видит, но которыми занимаются другие процессы.
DEFAULT_OS_EXCLUDE = ["Windows 7", "Windows 10", "ESXi", "IOS", "NX-OS", "IOS XE", "FreeBSD"]


class Connection(BaseModel):
    host: str = ""
    #: Персональный токен доступа (pat_…), выпускается в консоли управления MaxPatrol.
    api_token: str = ""
    #: MaxPatrol обычно стоит на самоподписанном сертификате; проверка
    #: выключена по умолчанию, но явно — флагом, который человек видит.
    verify_tls: bool = False
    os_exclude: list[str] = Field(default_factory=lambda: list(DEFAULT_OS_EXCLUDE))
    pdql_extra: str = ""
    limit: int = Field(default=0, ge=0)

    @property
    def configured(self) -> bool:
        return bool(self.host.strip() and self.api_token)

    def unsealed(self) -> Connection:
        """Копия с расшифрованными секретами — для обращения к VM, не для записи."""
        return self.model_copy(update={f: decrypt(getattr(self, f)) for f in SECRET_FIELDS})


class ConnectionIn(Connection):
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


#: Поля, от которых зависит, куда уйдёт токен.
ADDRESS_FIELDS = ("host", "verify_tls")
SECRET_FIELDS = ("api_token",)
SECRETS_AGAIN = "при смене адреса API-токен нужно ввести заново"


class SecretsRequired(ValueError):
    pass


class VmSettings(BaseModel):
    connection: Connection = Field(default_factory=Connection)
    weights: Weights = Field(default_factory=Weights)
    threshold: int = Field(default=DEFAULT_THRESHOLD, ge=0, le=100)
    #: Порог слоя ATT&CK: пары ниже него в матрицу не попадают. Отдельный
    #: от `threshold`: матрица про способ атаки, а не про очередь работ.
    attack_min_risk: int = Field(default=DEFAULT_ATTACK_MIN_RISK, ge=0, le=100)


class VmSettingsIn(BaseModel):
    """Тело PUT: то же, что `VmSettings`, но порог матрицы необязателен.

    Формы подключения и весов собирают тело по полям и про порог не знают:
    без этого сохранение любой из них молча возвращало бы его в умолчание.
    """

    connection: ConnectionIn = Field(default_factory=ConnectionIn)
    weights: Weights = Field(default_factory=Weights)
    threshold: int = Field(default=DEFAULT_THRESHOLD, ge=0, le=100)
    attack_min_risk: int | None = Field(default=None, ge=0, le=100)


def load_settings(db: Session) -> VmSettings:
    row = db.get(AppSetting, VM_KEY)
    if row is None or not row.value_json or row.value_json == "{}":
        return VmSettings()
    data = json.loads(row.value_json)
    weights = data.get("weights")
    if isinstance(weights, dict) and "levels" not in weights:
        # Веса первой итерации (impact, cvss_v3, exploitdb, msf…) в новую формулу не
        # переводятся: другие члены и шкалы (спека 2026-10-21 §9). Действуют умолчания,
        # пока веса не сохранят заново; в базе старый JSON не трогается.
        global _old_weights_warned
        if not _old_weights_warned:
            _old_weights_warned = True
            log.warning("VM: веса формулы риска в старой схеме — действуют умолчания новой формулы")
        data["weights"] = {}
    return VmSettings.model_validate(data)


def changed_fields(current: VmSettings, incoming: VmSettingsIn) -> list[str]:
    """Имена изменённых полей для журнала; пустой секрет — «не трогать»."""
    changed = []
    for name in Connection.model_fields:
        new = getattr(incoming.connection, name)
        if new != getattr(current.connection, name) and (name not in SECRET_FIELDS or new):
            changed.append(name)
    if incoming.weights != current.weights:
        changed.append("weights")
    if incoming.threshold != current.threshold:
        changed.append("threshold")
    if incoming.attack_min_risk is not None and incoming.attack_min_risk != current.attack_min_risk:
        changed.append("attack_min_risk")
    return changed


def save_settings(db: Session, incoming: VmSettingsIn, login: str | None) -> VmSettings:
    """Сохранить, оставив прежние секреты, если новые пришли пустыми:
    форма их не показывает, а значит, и не присылает. Порог матрицы —
    так же: отсутствие поля значит «не трогать», а не «сбросить».

    Исключение — смена адреса или учётной записи: прежние секреты на новый
    адрес не уходят, их нужно ввести заново (`SecretsRequired`)."""
    current = load_settings(db)
    if secrets_again(current.connection, incoming.connection, ADDRESS_FIELDS, SECRET_FIELDS):
        raise SecretsRequired(SECRETS_AGAIN)
    merged = VmSettings(
        connection=Connection(**incoming.connection.model_dump()),
        weights=incoming.weights.model_copy(deep=True),
        threshold=incoming.threshold,
        attack_min_risk=current.attack_min_risk if incoming.attack_min_risk is None else incoming.attack_min_risk,
    )
    #: Новые секреты шифруются; прежние — тоже, если лежали открытыми.
    for f, value in seal_secrets(current.connection, merged.connection, SECRET_FIELDS).items():
        setattr(merged.connection, f, value)
    put_setting(db, VM_KEY, merged.model_dump_json(), login)
    return merged
