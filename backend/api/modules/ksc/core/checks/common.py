"""Общее для проверок: подпись, дни между датами, подпись находки хоста."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.export import ExportIndex, HostRecord
from api.modules.ksc.core.findings import Finding, finalize

CheckFunc = Callable[[ExportIndex, KscConfig], list[Finding]]


@dataclass(frozen=True)
class CheckSpec:
    code: str
    title: str
    #: Что означает находка и где это смотреть в консоли KSC.
    description: str
    func: CheckFunc


def date_str(value: dt.datetime | None) -> str:
    return value.strftime("%Y-%m-%d") if value else "никогда"


def days_since(value: dt.datetime | None, now: dt.datetime) -> int | None:
    return (now - value).days if value else None


def host_details(h: HostRecord) -> dict[str, Any]:
    return {"group": h.group_path, "os": h.os, "ip": h.ip, "product": h.product, "product_version": h.product_version, "last_seen": date_str(h.last_seen_at)}


def host_finding(cfg: KscConfig, check: str, severity: str, h: HostRecord, *, key_extra: str = "", **details: Any) -> Finding:
    return finalize(Finding(check=check, severity=severity, host=h.name, host_key=h.fqdn or h.name.lower(), target=h.group_path, details={**host_details(h), **details}, key_extra=key_extra), cfg)
