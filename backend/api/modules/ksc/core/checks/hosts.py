"""Проверки состояния защиты на хостах (спека, таблица проверок)."""
from __future__ import annotations

from api.modules.ksc.core.checks.common import date_str, days_since, host_finding
from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.export import RTP_NO_LICENSE, RTP_OFF, ExportIndex, version_tuple
from api.modules.ksc.core.findings import Finding

RTP_STATE_TEXT = {0: "неизвестно", 1: "остановлена", 2: "приостановлена", 3: "запускается", 9: "сбой", 10: "не установлена", 11: "не поддерживается лицензией"}
COMPONENT_STATUS_TEXT = {0: "неизвестно", 1: "остановлен", 2: "приостановлен", 3: "запускается", 4: "работает", 9: "сбой", 10: "не установлен", 11: "нет лицензии"}
COMPONENT_OFF_STATES = {1, 2, 9, 10, 11}


def check_unassigned(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    return [host_finding(cfg, "UNASSIGNED", "Medium", h) for h in idx.hosts if h.unassigned]


def check_no_agent(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    return [host_finding(cfg, "NO_AGENT", "High", h, last_visible=date_str(h.last_seen_at)) for h in idx.hosts if h.visible and not h.agent_installed]


def check_agent_silent(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    out = []
    for h in idx.hosts:
        if not h.agent_installed:
            continue
        age = days_since(h.last_seen_at, idx.now)
        if age is None or age > cfg.agent_silent_days:
            out.append(host_finding(cfg, "AGENT_SILENT", "Medium", h, age_days=age, threshold_days=cfg.agent_silent_days))
    return out


def check_no_protection(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    return [host_finding(cfg, "NO_PROTECTION", "Critical", h, agent_version=h.agent_version) for h in idx.hosts if h.agent_alive and not h.protection_installed]


def check_rtp_off(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    return [
        host_finding(cfg, "RTP_OFF", "Critical", h, rtp_state=RTP_STATE_TEXT.get(h.rtp_state, str(h.rtp_state)))
        for h in idx.hosts
        if h.protection_installed and (h.rtp_state in RTP_OFF or h.rtp_state == RTP_NO_LICENSE)
    ]


def check_bases_old(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    out = []
    for h in idx.hosts:
        if not h.protection_installed:
            continue
        age = days_since(h.bases_at, idx.now)
        if age is not None and age > cfg.bases_old_days:
            out.append(host_finding(cfg, "BASES_OLD", "High", h, bases_at=date_str(h.bases_at), age_days=age, threshold_days=cfg.bases_old_days))
    return out


def check_no_fullscan(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    out = []
    for h in idx.hosts:
        if not h.protection_installed:
            continue
        age = days_since(h.last_fullscan_at, idx.now)
        if age is None or age > cfg.fullscan_days:
            out.append(host_finding(cfg, "NO_FULLSCAN", "Low", h, last_fullscan=date_str(h.last_fullscan_at), age_days=age, threshold_days=cfg.fullscan_days))
    return out


def check_component_off(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    out = []
    for h in idx.hosts:
        seen: set[str] = set()  # английское и русское название одного компонента (или две версии продукта) — одна находка
        for name, status in h.components:
            if status not in COMPONENT_OFF_STATES:
                continue
            lowered = name.lower()
            code = next((c for c, patterns in cfg.key_components.items() if any(p.lower() in lowered for p in patterns)), None)
            if code is None or code in seen:
                continue
            seen.add(code)
            out.append(host_finding(cfg, "COMPONENT_OFF", "Medium", h, key_extra=code, component=name, status=COMPONENT_STATUS_TEXT.get(status, str(status)), code=code))
    return out


def check_product_outdated(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    newest_product: dict[str, tuple[int, ...]] = {}
    newest_agent: tuple[int, ...] = ()
    for h in idx.hosts:
        if h.product and h.product_version:
            newest_product[h.product] = max(newest_product.get(h.product, ()), version_tuple(h.product_version))
        if h.agent_version:
            newest_agent = max(newest_agent, version_tuple(h.agent_version))
    out = []
    for h in idx.hosts:
        if h.product and h.product_version and version_tuple(h.product_version) < newest_product[h.product]:
            out.append(host_finding(cfg, "PRODUCT_OUTDATED", "Low", h, key_extra="product", what=h.product, version=h.product_version, newest=".".join(map(str, newest_product[h.product]))))
        if h.agent_version and version_tuple(h.agent_version) < newest_agent:
            out.append(host_finding(cfg, "PRODUCT_OUTDATED", "Low", h, key_extra="agent", what="agent", version=h.agent_version, newest=".".join(map(str, newest_agent))))
    return out


def check_threats_active(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    return [host_finding(cfg, "THREATS_ACTIVE", "High", h, uncured=h.threats) for h in idx.hosts if h.threats > 0]


def check_host_critical(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    return [host_finding(cfg, "HOST_CRITICAL", "Medium", h, reasons=h.status_reasons) for h in idx.hosts if h.status == "critical"]


def check_host_warning(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    return [host_finding(cfg, "HOST_WARNING", "Low", h, reasons=h.status_reasons) for h in idx.hosts if h.status == "warning"]


def check_reboot_pending(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    out = []
    for h in idx.hosts:
        if not h.reboot_required:
            continue
        age = days_since(h.reboot_requested_at, idx.now)
        if age is None or age > cfg.reboot_pending_days:
            out.append(host_finding(cfg, "REBOOT_PENDING", "Low", h, requested_at=date_str(h.reboot_requested_at), age_days=age, reason=h.reboot_reason, threshold_days=cfg.reboot_pending_days))
    return out
