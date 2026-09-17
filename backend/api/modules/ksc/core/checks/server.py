"""Проверки уровня сервера KSC: 2FA, административные роли, сертификаты, подчинённые серверы.

Находки не привязаны к хосту: `target` — учётка, сертификат или подчинённый
сервер. Отсутствующая секция выгрузки (старый файл, нет прав) — проверка молчит.
"""
from __future__ import annotations

from api.modules.ksc.core.certs import parse_cert
from api.modules.ksc.core.checks.common import date_str, days_since
from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.export import ExportIndex, _dt, _int, _str, unwrap
from api.modules.ksc.core.findings import Finding, finalize


def check_2fa_off(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    value = unwrap(idx.export.security.get("two_factor_required_for_all"))
    if value is None or value:
        return []
    return [finalize(Finding("KSC_2FA_OFF", "High", target="Двухэтапная проверка", details={"two_factor_required_for_all": False}), cfg)]


def _is_admin_role(role: str, role_display: str, patterns: list[str]) -> bool:
    lowered = {p.lower() for p in patterns}
    return role.lower() in lowered or role_display.lower() in lowered


def check_ksc_internal_admin(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Внутренняя учётка KSC (nInternalUserId > 0) держит административную роль."""
    out = []
    for r in idx.export.role_assignments:
        if _int(r.get("nInternalUserId")) <= 0:
            continue
        role, role_display = _str(r.get("wstrRoleName")), _str(r.get("wstrRoleDisplayName"))
        if not _is_admin_role(role, role_display, cfg.admin_role_patterns):
            continue
        account, group = _str(r.get("wstrTrusteeDisplayName")), _str(r.get("wstrGroupName"))
        out.append(finalize(Finding("KSC_INTERNAL_ADMIN", "Medium", target=account, details={"role": role, "group": group}, key_extra=f"{role}|{group}"), cfg))
    return out


def check_ksc_admins(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Справочно: все держатели административных ролей (внутренние и доменные учётки)."""
    out = []
    for r in idx.export.role_assignments:
        role, role_display = _str(r.get("wstrRoleName")), _str(r.get("wstrRoleDisplayName"))
        if not _is_admin_role(role, role_display, cfg.admin_role_patterns):
            continue
        account, group = _str(r.get("wstrTrusteeDisplayName")), _str(r.get("wstrGroupName"))
        internal = _int(r.get("nInternalUserId")) > 0
        out.append(finalize(Finding("KSC_ADMINS", "Info", target=account, details={"role": role, "group": group, "internal": internal}, key_extra=f"{role}|{group}"), cfg))
    return out


def check_server_cert(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Сертификат сервера (`CertPoolCtrl.GetCertificateInfo`, функции 1..4) истёк или истекает."""
    out = []
    for fn, entry in idx.export.server_certs.items():
        if not isinstance(entry, dict):
            continue
        info = parse_cert(entry.get("CPublic"))
        if info is None:
            continue
        days_left = (info.not_after - idx.now).days
        if days_left < 0:
            severity = "Critical"
        elif days_left <= cfg.cert_days:
            severity = "High"
        else:
            continue
        out.append(finalize(Finding(
            "SERVER_CERT", severity, target=f"сертификат {fn}: {info.subject}",
            details={"function": fn, "subject": info.subject, "not_after": date_str(info.not_after), "days_left": days_left},
        ), cfg))
    return out


def check_secondary_server_stale(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Подчинённый сервер (`ServerHierarchy.GetChildServers`) не выходил на связь дольше `agent_silent_days`."""
    out = []
    for s in idx.export.secondary_servers:
        name = _str(s.get("KLSRVH_SRV_DN")) or _str(s.get("KLSRVH_SRV_ADDR"))
        last_connected = _dt(s.get("KLSRVH_SRV_LAST_CONNECTED"))
        age = days_since(last_connected, idx.now)
        if age is None or age > cfg.agent_silent_days:
            out.append(finalize(Finding(
                "SECONDARY_SERVER_STALE", "Medium", target=name,
                details={"address": _str(s.get("KLSRVH_SRV_ADDR")), "last_connected": date_str(last_connected), "age_days": age, "threshold_days": cfg.agent_silent_days},
            ), cfg))
    return out
