"""Привязка сертификатов к учётным записям: ESC14 по снапшоту (слабые altSecurityIdentities)."""
from __future__ import annotations

from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex
from api.modules.ad.core.findings import Finding, finalize

STRONG_MAPPING_PARTS = ("<SR>", "<SKI>", "<SHA1-PUKEY>")


def _finding(cfg: AdConfig, code: str, severity: str, target: str, details: dict[str, object]) -> Finding:
    return finalize(Finding(check="ADCS_MAPPING", severity=severity, target=target, key_extra=code, details={"esc": code, **details}), cfg)


def weak_mapping(entry: str) -> bool:
    """X509:<S>… без серийного номера или ключа и X509:<RFC822>… подделываются выпуском сертификата с тем же субъектом или почтой."""
    upper = entry.upper()
    if not upper.startswith("X509:"):
        return False
    return "<RFC822>" in upper or ("<S>" in upper and not any(p in upper for p in STRONG_MAPPING_PARTS))


def _esc14(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out: list[Finding] = []
    for cls in ("user", "computer"):
        for obj in idx.objects(cls):
            weak = [m for m in obj.altSecurityIdentities if weak_mapping(m)]
            if not weak or not obj.enabled:
                continue
            severity = "High" if obj.adminCount else "Medium"
            details: dict[str, object] = {"details": "слабое явное сопоставление сертификата (altSecurityIdentities)", "mappings": weak, "account_dn": obj.dn, "sam": obj.sam or ""}
            out.append(_finding(cfg, "ESC14", severity, idx.principal_name(obj.sid) or obj.label, details))
    return out


def check_adcs_mapping(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    return _esc14(idx, cfg)
