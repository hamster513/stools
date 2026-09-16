"""Покрытие относительно AD: есть в AD — нет в KSC, и наоборот."""
from __future__ import annotations

from api.modules.ksc.core.checks.common import host_finding
from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.export import ExportIndex
from api.modules.ksc.core.findings import Finding, finalize


def check_cover_ad_missing(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    cov = idx.coverage
    if cov is None:
        return []
    return [finalize(Finding("COVER_AD_MISSING", "High", host=c.name, host_key=c.fqdn, target=c.domain, details={"fqdn": c.fqdn, "os": c.os, "last_logon": c.last_logon}), cfg) for c in cov.ad_only]


def check_cover_ksc_only(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    cov = idx.coverage
    if cov is None:
        return []
    return [host_finding(cfg, "COVER_KSC_ONLY", "Info", h, windomain=h.windomain) for h in idx.hosts if h.host_id in cov.ksc_only]
