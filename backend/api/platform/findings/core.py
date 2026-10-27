"""Статусы находок: коды, переходы, проверки (спека §1). Чистые функции, без базы.

`resolved` и `reopened` ставит только система по сравнению с данными;
человек выбирает из `MANUAL`. `fixed` — «исправлено, ждём подтверждения
данными»: пока ключ в данных, статус держится, исчезновение даёт `resolved`,
а `reopened` бывает только после исчезновения — в том числе когда «исправлено»
поставили находке, которой в данных уже не было, а она вернулась.
"""
from __future__ import annotations

import datetime as dt
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

STATUSES = ("new", "in_work", "risk_accepted", "false_positive", "fixed", "resolved", "reopened")
MANUAL = ("new", "in_work", "risk_accepted", "false_positive", "fixed")
OPEN = frozenset({"new", "in_work", "fixed", "reopened"})
NEEDS_REASON = frozenset({"risk_accepted", "false_positive"})
STATUS_TITLES: dict[str, str] = {
    "new": "Новая",
    "in_work": "В работе",
    "risk_accepted": "Принят риск",
    "false_positive": "Ложное срабатывание",
    "fixed": "Исправлено",
    "resolved": "Устранена",
    "reopened": "Переоткрыта",
}
#: Закрывающие решения людей и подтверждённое данными устранение по умолчанию в подсчёты не идут.
DEFAULT_COUNTED: dict[str, bool] = {s: s not in {"risk_accepted", "false_positive", "resolved"} for s in STATUSES}

#: Своя шкала уровней в модуле (как api.db.models.LEVELS), а не api.platform.services.access:
#: ядро не тянет за собой базу и HTTP-слой.
_RANK = {"deny": 0, "read": 1, "write": 2, "admin": 3}
_LEVEL_TITLES = {"write": "аналитик модуля", "admin": "администратор модуля"}
#: Значения `risk_accept_role`, сохранённые до ролей по уровням.
_OLD_RISK_ACCEPT_ROLE = {"analyst": "write", "admin": "admin"}


class TransitionError(ValueError):
    """Ручная смена не допускается правилами §1 или настройками."""


class RoleRequired(TransitionError):
    """Переход разрешён только уровню выше, чем у автора в модуле находки (`risk_accept_role`)."""


class FindingSettings(BaseModel):
    counted: dict[str, bool] = Field(default_factory=lambda: dict(DEFAULT_COUNTED))
    #: Предел срока принятия риска в днях; None — срок не обязателен и не ограничен.
    risk_max_days: int | None = Field(default=None, ge=1, le=3650)
    #: Какой уровень в модуле находки нужен, чтобы принять риск: `write` — аналитик, `admin` — администратор.
    risk_accept_role: Literal["write", "admin"] = "write"

    @model_validator(mode="before")
    @classmethod
    def _old_risk_accept_role(cls, data: Any) -> Any:
        if isinstance(data, dict) and data.get("risk_accept_role") in _OLD_RISK_ACCEPT_ROLE:
            return {**data, "risk_accept_role": _OLD_RISK_ACCEPT_ROLE[data["risk_accept_role"]]}
        return data

    @field_validator("counted")
    @classmethod
    def _full_counted(cls, value: dict[str, bool]) -> dict[str, bool]:
        unknown = set(value) - set(STATUSES)
        if unknown:
            raise ValueError(f"неизвестные статусы: {', '.join(sorted(unknown))}")
        return {**DEFAULT_COUNTED, **value}


def check_manual(
    status: str, *, reason: str, level: str, settings: FindingSettings, risk_until: dt.date | None, today: dt.date,
) -> None:
    if status not in STATUSES:
        raise TransitionError(f"неизвестный статус «{status}»")
    if status not in MANUAL:
        raise TransitionError(f"статус «{STATUS_TITLES.get(status, status)}» ставит только система")
    if status in NEEDS_REASON and not reason.strip():
        raise TransitionError(f"для статуса «{STATUS_TITLES[status]}» нужно обоснование")
    if status != "risk_accepted":
        return
    needed = settings.risk_accept_role
    if _RANK.get(level, -1) < _RANK[needed]:
        raise RoleRequired(f"принять риск может только: {_LEVEL_TITLES[needed]}")
    if risk_until is not None and risk_until < today:
        raise TransitionError("срок принятия риска уже прошёл")
    if settings.risk_max_days is not None:
        if risk_until is None:
            raise TransitionError("нужен срок принятия риска")
        if risk_until > today + dt.timedelta(days=settings.risk_max_days):
            raise TransitionError(f"риск принимается не дольше чем на {settings.risk_max_days} дн.")


def on_absent(status: str) -> str | None:
    """Ключа нет в свежих данных области: открытая находка устранена, решения людей не трогаются."""
    return "resolved" if status in OPEN else None


def on_present(status: str, was_present: bool) -> str | None:
    """Ключ в свежих данных области. Переоткрывается то, что система закрыла, и
    «исправлено», поставленное, пока ключа в данных не было (`was_present` —
    флаг строки до этой сверки): исправление не подтвердилось."""
    if status == "resolved" or (status == "fixed" and not was_present):
        return "reopened"
    return None


def is_overdue(status: str, due: dt.date | None, today: dt.date) -> bool:
    return status in OPEN and due is not None and due < today
