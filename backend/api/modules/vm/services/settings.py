"""Настройки модуля VM в `app_setting['vm']` (спека §7).

Пароль и client secret MaxPatrol хранятся здесь же: база и так внутри
периметра, модель доступа к ней не слабее, чем к самому VM. Наружу они
не отдаются никогда — только признак «задан».
"""
from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.db.models import AppSetting
from api.modules.vm.core.weights import DEFAULT_THRESHOLD, Weights

VM_KEY = "vm"

#: Ниже этого риска пара не считается экспозицией в матрице ATT&CK.
DEFAULT_ATTACK_MIN_RISK = 40

#: Исключения по ОС из первой итерации: сетевое железо и рабочие станции,
#: которые VM видит, но которыми занимаются другие процессы.
DEFAULT_OS_EXCLUDE = ["Windows 7", "Windows 10", "ESXi", "IOS", "NX-OS", "IOS XE", "FreeBSD"]


class Connection(BaseModel):
    host: str = ""
    username: str = ""
    password: str = ""
    client_secret: str = ""
    #: MaxPatrol обычно стоит на самоподписанном сертификате; проверка
    #: выключена по умолчанию, но явно — флагом, который человек видит.
    verify_tls: bool = False
    os_exclude: list[str] = Field(default_factory=lambda: list(DEFAULT_OS_EXCLUDE))
    pdql_extra: str = ""
    limit: int = Field(default=0, ge=0)

    @property
    def configured(self) -> bool:
        return bool(self.host.strip() and self.username.strip() and self.password)


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

    connection: Connection = Field(default_factory=Connection)
    weights: Weights = Field(default_factory=Weights)
    threshold: int = Field(default=DEFAULT_THRESHOLD, ge=0, le=100)
    attack_min_risk: int | None = Field(default=None, ge=0, le=100)


def load_settings(db: Session) -> VmSettings:
    row = db.get(AppSetting, VM_KEY)
    if row is None or not row.value_json or row.value_json == "{}":
        return VmSettings()
    return VmSettings.model_validate_json(row.value_json)


def save_settings(db: Session, incoming: VmSettingsIn, login: str | None) -> VmSettings:
    """Сохранить, оставив прежние секреты, если новые пришли пустыми:
    форма их не показывает, а значит, и не присылает. Порог матрицы —
    так же: отсутствие поля значит «не трогать», а не «сбросить»."""
    current = load_settings(db)
    merged = VmSettings(
        connection=incoming.connection.model_copy(deep=True),
        weights=incoming.weights.model_copy(deep=True),
        threshold=incoming.threshold,
        attack_min_risk=current.attack_min_risk if incoming.attack_min_risk is None else incoming.attack_min_risk,
    )
    if not merged.connection.password:
        merged.connection.password = current.connection.password
    if not merged.connection.client_secret:
        merged.connection.client_secret = current.connection.client_secret
    row = db.get(AppSetting, VM_KEY)
    if row is None:
        row = AppSetting(key=VM_KEY)
        db.add(row)
    row.value_json = merged.model_dump_json()
    row.updated_at = dt.datetime.now(dt.UTC)
    row.updated_by = login
    db.commit()
    return merged
