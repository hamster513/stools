"""Общее для проверок: подпись, форматирование дат, ACE → identity."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from dataclasses import dataclass

from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import AdObject, ExportIndex, filetime_to_datetime
from api.modules.ad.core.findings import Finding, finalize

CheckFunc = Callable[[ExportIndex, AdConfig], list[Finding]]

#: Категории проверок в порядке показа на обзоре.
CATEGORIES: dict[str, str] = {
    "accounts": "Учётные записи",
    "privileged": "Привилегированные учётные записи",
    "kerberos": "Kerberos и делегирование",
    "acl": "Права на объекты",
    "gpo": "Групповые политики",
    "dc": "Контроллеры домена",
    "domain": "Настройки домена и леса",
    "trust": "Доверие",
    "pki": "AD CS и сертификаты",
}


@dataclass(frozen=True)
class CheckSpec:
    code: str
    title: str
    description: str
    func: CheckFunc
    #: Техники ATT&CK, которые открывает находка проверки (спека, раздел «AD»).
    techniques: tuple[str, ...] = ()
    #: Категория, «Как исправить» и ссылки (название, URL) — из catalog.py.
    category: str = ""
    remediation: str = ""
    references: tuple[tuple[str, str], ...] = ()


def date_str(filetime: int | None) -> str:
    value = filetime_to_datetime(filetime)
    return value.strftime("%Y-%m-%d") if value else ""


def days_between(filetime: int | None, now: dt.datetime) -> int | None:
    value = filetime_to_datetime(filetime)
    return (now - value).days if value else None


def account_details(obj: AdObject) -> dict[str, object]:
    return {
        "sam": obj.sam or "",
        "object_type": obj.cls,
        "enabled": obj.enabled,
        "last_logon": date_str(obj.lastLogonTimestamp),
        "pwd_last_set": date_str(obj.pwdLastSet),
    }


def account_finding(idx: ExportIndex, cfg: AdConfig, check: str, severity: str, obj: AdObject, **details: object) -> Finding:
    f = Finding(
        check=check,
        severity=severity,
        identity=idx.principal_name(obj.sid) or obj.label,
        identity_sid=obj.sid or "",
        target=obj.dn,
        details={**account_details(obj), **details},
    )
    return finalize(f, cfg)
