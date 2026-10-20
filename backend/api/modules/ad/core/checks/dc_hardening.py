"""Настройки контроллеров домена по разделу dc данных ЦС (сборщик 2.3): NTLM, подпись LDAP и SMB,
SMBv1, службы Spooler и WebClient, давность загрузки, старые протоколы SCHANNEL."""
from __future__ import annotations

from api.modules.ad.core.ca_data import DcBinding
from api.modules.ad.core.checks.adcs_rules import ca_data_details
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex
from api.modules.ad.core.findings import Finding, finalize

OLD_TLS = ("SSL 3.0", "TLS 1.0", "TLS 1.1")

#: (вид, серьёзность, описание, фактическое значение, подставлено ли значение по умолчанию)
Hit = tuple[str, str, str, object, bool]


def _registry(dc: DcBinding, value: int | None, default: int) -> tuple[int, bool] | None:
    """Значение реестра и признак «по умолчанию». None в прочитанном реестре — параметра нет, действует
    значение Windows по умолчанию; в непрочитанном — не известно, вид не проверяется."""
    if value is not None:
        return value, False
    return (default, True) if dc.registry_read is True else None


def _registry_hits(dc: DcBinding) -> list[Hit]:
    hits: list[Hit] = []
    if (lm := _registry(dc, dc.lm_compatibility, 3)) is not None:
        level, default = lm
        if level < 3:
            hits.append(("ntlmv1", "High", f"контроллер отправляет и принимает LM и NTLMv1 (LmCompatibilityLevel = {level})", level, default))
        elif level < 5:
            hits.append(("ntlmv1", "Medium", f"контроллер принимает NTLMv1 (LmCompatibilityLevel = {level})", level, default))
    if dc.no_lm_hash == 0:
        hits.append(("lm_hash", "Medium", "контроллер хранит LM-хеши паролей (NoLMHash = 0)", 0, False))
    if (integrity := _registry(dc, dc.ldap_integrity, 1)) is not None and integrity[0] != 2:
        hits.append(("ldap_signing", "Medium", f"подпись LDAP не обязательна (LDAPServerIntegrity = {integrity[0]})", *integrity))
    if (binding := _registry(dc, dc.ldap_channel_binding, 0)) is not None and binding[0] in (0, 1):
        severity = "Medium" if binding[0] == 0 else "Low"
        text = "привязка канала LDAPS выключена" if binding[0] == 0 else "привязка канала LDAPS только там, где клиент её поддерживает"
        hits.append(("channel_binding", severity, f"{text} (LdapEnforceChannelBinding = {binding[0]})", *binding))
    enabled = [p for p in OLD_TLS if (dc.tls or {}).get(p) not in (None, 0)]
    if enabled:
        hits.append(("tls_old", "Low", f"явно включены старые протоколы SCHANNEL: {', '.join(enabled)}", enabled, False))
    return hits


def _cim_hits(dc: DcBinding, idx: ExportIndex, cfg: AdConfig) -> list[Hit]:
    hits: list[Hit] = []
    if dc.smb1 is True:
        hits.append(("smb1", "High", "включён сервер SMBv1", True, False))
    if dc.smb_require_signing is False:
        hits.append(("smb_signing", "High", "подпись SMB не обязательна (RequireSecuritySignature = false)", False, False))
    if dc.spooler == "running":
        hits.append(("spooler", "Medium", "служба печати (Spooler) запущена: контроллер можно заставить пройти проверку подлинности (PrinterBug)", "running", False))
    if dc.webclient == "running":
        hits.append(("webclient", "Low", "служба WebClient запущена: принуждённая проверка подлинности по HTTP", "running", False))
    if dc.last_boot is not None:
        days = (idx.export.collected_at - dc.last_boot).days
        if days > cfg.dc_max_uptime_days:
            hits.append(("uptime", "Medium", f"контроллер не перезагружался {days} дн. (порог {cfg.dc_max_uptime_days}): обновления, скорее всего, не установлены", days, False))
    return hits


def check_dc_hardening(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    if idx.ca is None:
        return []
    source = ca_data_details(idx, "dc")
    out: list[Finding] = []
    for dc in idx.ca.dcs:
        for kind, severity, text, value, default in _registry_hits(dc) + _cim_hits(dc, idx, cfg):
            details: dict[str, object] = {"details": text, "kind": kind, "value": value, "default": default, **source}
            if kind == "uptime" and dc.last_boot is not None:
                details["last_boot"] = dc.last_boot.isoformat()
            if dc.os_build:
                details["os_build"] = dc.os_build
            out.append(finalize(Finding(check="DcHardening", severity=severity, target=dc.host, key_extra=kind, details=details), cfg, allowlist=False))
    return out
