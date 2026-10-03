"""Проверки компьютеров и контроллеров домена: неактивные, старые пароли, устаревшие ОС, число контроллеров, делегация, владелец."""
from __future__ import annotations

import datetime as dt
import re

from api.modules.ad.core.checks import principals
from api.modules.ad.core.checks.common import account_finding, days_between
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import AdObject, ExportIndex
from api.modules.ad.core.findings import Finding, finalize

#: Контроллер уже получает пароль и входы чаще обычных компьютеров: порог смены пароля и «недавнего» входа.
RECENT_LOGON_DAYS = 45

_STEP_UP = {"Low": "Medium", "Medium": "High", "High": "Critical"}

# Подстроки имени ОС без учёта регистра. «windows nt » с пробелом — старые NT 4.0/3.x.
_OS_HIGH = ("windows nt ", "windows 2000", "windows xp", "server 2003")
_OS_MEDIUM = ("vista", "windows 7", "windows 8", "server 2008", "server 2012")
_OS_WIN10_EXEMPT = ("ltsc", "ltsb", "iot")
_BUILD = re.compile(r"\((\d+)\)")


def step_up(severity: str) -> str:
    """Low→Medium→High→Critical→Critical: контроллер опаснее рядового компьютера."""
    return _STEP_UP.get(severity, severity)


def obsolete_os(name: str, version: str, builds: dict[str, dt.date], today: dt.date) -> tuple[str, str] | None:
    """(серьёзность, причина) для ОС вне поддержки или None."""
    # AD отдаёт «Windows Server® 2008», «Windows Vista™»: знаки и двойные пробелы мешают подстрокам.
    low = " ".join((name or "").lower().replace("®", "").replace("™", "").split())
    if not low:
        return None
    if any(s in low for s in _OS_HIGH):
        return "High", f"{name}: давно снята с поддержки"
    if any(s in low for s in _OS_MEDIUM):
        return "Medium", f"{name}: снята с поддержки"
    if "windows 10" in low and not any(s in low for s in _OS_WIN10_EXEMPT):
        return "Medium", f"{name}: Windows 10 вышла из поддержки (кроме LTSC и IoT)"
    m = _BUILD.search(version or "")
    if m and (end := builds.get(m.group(1))) is not None and end < today:
        return "Low", f"{name} (сборка {m.group(1)}): поддержка закончилась {end.isoformat()}"
    return None


def _computers(idx: ExportIndex) -> list[AdObject]:
    return [c for c in idx.objects("computer") if c.enabled]


def _logon_age(idx: ExportIndex, c: AdObject) -> int | None:
    return days_between(c.lastLogonTimestamp, idx.export.collected_at)


def check_inactive_computers(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out = []
    for c in _computers(idx):
        idle = _logon_age(idx, c)
        if idle is not None and idle > cfg.computer_inactivity_days:
            out.append(
                account_finding(
                    idx, cfg, "InactiveComputers", "High" if idx.is_dc(c) else "Low", c,
                    details=f"Нет входа больше {cfg.computer_inactivity_days} дн.",
                    idle_days=idle,
                )
            )
    return out


def check_computer_password_age(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out = []
    for c in _computers(idx):
        idle = _logon_age(idx, c)
        if idle is None or idle > RECENT_LOGON_DAYS:
            continue
        # Пароль компьютера меняется сам раз в 30 дней: у работающего он старше порога только при отключённой смене.
        limit = RECENT_LOGON_DAYS if idx.is_dc(c) else cfg.computer_password_max_age_days
        age = days_between(c.pwdLastSet, idx.export.collected_at)
        if age is not None and age > limit:
            out.append(
                account_finding(
                    idx, cfg, "ComputerPasswordAge", "Medium" if idx.is_dc(c) else "Low", c,
                    details=f"Пароль компьютерной учётки не менялся {age} дн. (порог {limit})",
                    password_age_days=age,
                )
            )
    return out


def check_obsolete_os(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    today = idx.export.collected_at.date()
    out = []
    for c in _computers(idx):
        idle = _logon_age(idx, c)
        if idle is None or idle > cfg.computer_inactivity_days:
            continue
        verdict = obsolete_os(c.operatingSystem or "", c.operatingSystemVersion or "", cfg.obsolete_os_builds, today)
        if verdict is None:
            continue
        severity, reason = verdict
        out.append(
            account_finding(
                idx, cfg, "ObsoleteOs", step_up(severity) if idx.is_dc(c) else severity, c,
                details=reason,
                operating_system=c.operatingSystem or "",
                operating_system_version=c.operatingSystemVersion or "",
            )
        )
    return out


def check_dc_count(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    names = [c.name or c.label for c in idx.dcs]
    # Нет контроллеров в выгрузке — скорее всего, компьютеры не собраны: это пробел покрытия, а не находка.
    if len(names) != 1:
        return []
    f = Finding(
        check="DcCount", severity="Low", target=idx.export.domain.dn,
        details={"details": "В домене один контроллер: при его отказе домен останавливается", "count": len(names), "controllers": names},
    )
    return [finalize(f, cfg, allowlist=False)]


def check_dc_delegation(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out = []
    for c in idx.dcs:
        kinds = []
        if c.protocol_transition:
            kinds.append("Constrained (S4U)")
        if c.allowedToDelegateTo:
            kinds.append("Constrained (Services)")
        if kinds:
            out.append(
                account_finding(
                    idx, cfg, "DcDelegation", "High", c,
                    details="У контроллера домена настроена ограниченная делегация: захват контроллера открывает доступ к перечисленным службам",
                    delegation_type="; ".join(kinds),
                    allowed_to_delegate_to="; ".join(c.allowedToDelegateTo),
                )
            )
    return out


def check_dc_owner(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out = []
    for c in idx.dcs:
        desc = idx.sd_of(c)
        owner = desc.owner if desc else None
        if not owner or principals.tier0_kind(idx, cfg, owner) == "safe":
            continue
        f = Finding(
            check="DcOwner", severity="Medium", identity=idx.principal_name(owner), identity_sid=owner, target=c.dn,
            details={"details": f"Владелец объекта контроллера — {idx.principal_name(owner)}: владелец вправе менять права на объект", "dc": c.label},
        )
        out.append(finalize(f, cfg))
    return out
