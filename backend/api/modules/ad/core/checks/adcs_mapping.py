"""Привязка сертификатов к учётным записям: ESC14 по снапшоту (слабые altSecurityIdentities),
ESC10 по реестру контроллеров из данных ЦС."""
from __future__ import annotations

from api.modules.ad.core.checks.adcs_rules import ca_data_details
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex
from api.modules.ad.core.findings import Finding, finalize

STRONG_MAPPING_PARTS = ("<SR>", "<SKI>", "<SHA1-PUKEY>")
#: Schannel: CertificateMappingMethods & 0x4 — сопоставление сертификата по UPN.
UPN_MAPPING = 0x4


def _finding(cfg: AdConfig, code: str, severity: str, target: str, details: dict[str, object], right: str = "") -> Finding:
    return finalize(Finding(check="ADCS_MAPPING", severity=severity, target=target, right=right, key_extra=code, details={"esc": code, **details}), cfg)


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


def _esc10(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    if idx.ca is None:
        return []
    source = ca_data_details(idx, "dc")
    out: list[Finding] = []
    for dc in idx.ca.dcs:
        # (значение реестра, его величина, серьёзность, условие)
        hits: list[tuple[str, int, str, str]] = []
        if dc.strong_binding == 0:
            hits.append(("StrongCertificateBindingEnforcement", 0, "High", "строгая привязка сертификатов в Kerberos: привязка отключена (StrongCertificateBindingEnforcement = 0)"))
        elif dc.strong_binding == 1:
            hits.append(("StrongCertificateBindingEnforcement", 1, "Medium", "строгая привязка сертификатов в Kerberos: режим совместимости (StrongCertificateBindingEnforcement = 1)"))
        if dc.mapping_methods is not None and dc.mapping_methods & UPN_MAPPING:
            hits.append(("CertificateMappingMethods", dc.mapping_methods, "High", f"Schannel: сопоставление по UPN (CertificateMappingMethods = {dc.mapping_methods:#x})"))
        for value_name, value, severity, text in hits:
            out.append(_finding(cfg, "ESC10", severity, dc.host, {"details": text, "value": value, **source}, right=value_name))
    return out


def check_adcs_mapping(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    return _esc14(idx, cfg) + _esc10(idx, cfg)
