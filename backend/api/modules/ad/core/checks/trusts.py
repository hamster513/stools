"""Доверия: фильтрация SID, устаревший тип, делегирование TGT, давность, AES (MS-ADTS 6.1.6.7)."""
from __future__ import annotations

from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import TRUST_ATTRIBUTE_WITHIN_FOREST, AdObject, ExportIndex
from api.modules.ad.core.findings import Finding, finalize

#: trustDirection: исходящее (мы доверяем партнёру).
TRUST_DIRECTION_OUTBOUND = 0x2
#: trustType: TRUST_TYPE_DOWNLEVEL — домен Windows NT 4.0 (NTLM, без Kerberos).
TRUST_TYPE_DOWNLEVEL = 1
#: trustAttributes.
TRUST_QUARANTINED = 0x4
TRUST_FOREST_TRANSITIVE = 0x8
TRUST_TREAT_AS_EXTERNAL = 0x40
TRUST_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION = 0x800
#: supportedEncryptionTypes: AES128, AES256.
ENC_AES = 0x18


def _issues(t: AdObject, idx: ExportIndex, cfg: AdConfig) -> list[tuple[str, str, str]]:
    attrs = t.trustAttributes or 0
    forest = bool(attrs & TRUST_FOREST_TRANSITIVE)
    out = []
    # Доверие своего леса: фильтрация SID, делегирование TGT и AES к нему не относятся.
    external = not attrs & TRUST_ATTRIBUTE_WITHIN_FOREST
    if external and (t.trustDirection or 0) & TRUST_DIRECTION_OUTBOUND:
        if not forest and not attrs & TRUST_QUARANTINED:
            out.append(("sid_filtering", "High", "Внешнее доверие без фильтрации SID (карантина): SID из sIDHistory пользователей партнёра принимаются"))
        elif forest and attrs & TRUST_TREAT_AS_EXTERNAL:
            out.append(("sid_filtering", "High", "Лесное доверие с флагом «как внешнее»: фильтрация SID ослаблена, SID с RID ≥ 1000 из sIDHistory принимаются"))
    if t.trustType == TRUST_TYPE_DOWNLEVEL:
        out.append(("downlevel", "High", "Доверие к домену Windows NT 4.0 (downlevel): только NTLM, без Kerberos и современной защиты"))
    if external and forest and attrs & TRUST_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION:
        out.append(("tgt_delegation", "Medium", "Лесное доверие с делегированием TGT: службы партнёра с неограниченной делегацией получают билеты наших пользователей"))
    if t.whenChanged is not None:
        age = (idx.export.collected_at - t.whenChanged).days
        if age > cfg.trust_inactive_days:
            out.append(("inactive", "Medium", f"Объект доверия не менялся {age} дн. (порог {cfg.trust_inactive_days}): пароль доверия не обновляется, доверие, вероятно, не работает"))
    if external and t.trustDirection is not None and not (t.supportedEncryptionTypes or 0) & ENC_AES:
        out.append(("no_aes", "Low", "Для доверия не включён AES: межсферные билеты шифруются RC4"))
    return out


def check_trust_security(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out = []
    for t in idx.objects("trustedDomain"):
        name = t.trustPartner or t.flatName or t.rdn_value
        for kind, severity, text in _issues(t, idx, cfg):
            f = Finding(
                check="TrustSecurity", severity=severity, identity=name, target=t.dn, key_extra=kind,
                details={"details": f"Доверие {name}: {text}", "kind": kind, "trust_attributes": t.trustAttributes, "trust_direction": t.trustDirection,
                         "trust_type": t.trustType, "encryption_types": t.supportedEncryptionTypes},
            )
            out.append(finalize(f, cfg, allowlist=False))
    return out
