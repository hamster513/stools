"""Центр сертификации: ESC5 по снапшоту (права на объекты PKI в разделе конфигурации)."""
from __future__ import annotations

from api.modules.ad.core.checks.adcs_rules import unsafe_writers, writers_details
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex
from api.modules.ad.core.findings import Finding, finalize

PKI_OBJECT_CLASSES = ("pkiContainer", "pKIEnrollmentService")


def _finding(cfg: AdConfig, code: str, severity: str, target: str, details: dict[str, object]) -> Finding:
    return finalize(Finding(check="ADCS_CA", severity=severity, target=target, key_extra=code, details={"esc": code, **details}), cfg)


def _esc5(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out: list[Finding] = []
    for cls in PKI_OBJECT_CLASSES:
        for obj in idx.objects(cls):
            desc = idx.sd_of(obj)
            writers = unsafe_writers(idx, cfg, obj, desc) if desc else []
            if not writers:
                continue
            severity, common = writers_details(idx, writers, "право записи на объект PKI (контейнер или объект ЦС)", "High")
            out.append(_finding(cfg, "ESC5", severity, obj.dn, {**common, "object_class": obj.cls}))
    return out


def check_adcs_ca(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    return _esc5(idx, cfg)
