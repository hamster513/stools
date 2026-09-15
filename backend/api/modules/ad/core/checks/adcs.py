"""Шаблоны AD CS: ESC1–ESC4 (как в прототипе, только они)."""
from __future__ import annotations

import uuid

from api.modules.ad.core import sd
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex
from api.modules.ad.core.findings import Finding, finalize, is_low_priv

EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_SMARTCARD = "1.3.6.1.4.1.311.20.2.2"
EKU_PKINIT = "1.3.6.1.5.2.3.4"
EKU_ANY = "2.5.29.37.0"
EKU_ENROLL_AGENT = "1.3.6.1.4.1.311.20.2.1"
GUID_ENROLL_DEFAULT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
GUID_AUTOENROLL_DEFAULT = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"


def _esc(cfg: AdConfig, template: str, code: str, text: str, common: dict[str, object]) -> Finding:
    return finalize(
        Finding(check="ADCS_ESC", severity="High", target=template, key_extra=code, details={"esc": code, "details": text, **common}),
        cfg,
    )


def check_adcs_templates(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    enroll = uuid.UUID(idx.extended_right("Enroll") or GUID_ENROLL_DEFAULT)
    autoenroll = uuid.UUID(idx.extended_right("AutoEnroll") or GUID_AUTOENROLL_DEFAULT)
    domain_sid = idx.domain_sid
    out: list[Finding] = []
    for t in idx.objects("pKICertificateTemplate"):
        eku = list(t.pKIExtendedKeyUsage)
        client_auth = not eku or any(e in eku for e in (EKU_CLIENT_AUTH, EKU_SMARTCARD, EKU_PKINIT, EKU_ANY))
        any_purpose = not eku or EKU_ANY in eku
        enroll_agent = EKU_ENROLL_AGENT in eku
        supplies_subject = bool((t.name_flag or 0) & 1)
        desc = idx.sd_of(t)
        if desc is None:
            continue
        low_enroll = low_danger = False
        enrollers: list[str] = []
        for ace in desc.dacl:
            if not ace.allow:
                continue
            identity = idx.principal_name(ace.sid)
            if not is_low_priv(identity, ace.sid, cfg, domain_sid):
                continue
            if ace.has(sd.EXTENDED_RIGHT) and ace.object_type in (enroll, autoenroll):
                low_enroll = True
                enrollers.append(identity)
            if ace.has(sd.GENERIC_ALL):
                low_danger = low_enroll = True
                enrollers.append(identity)
            if ace.has(sd.WRITE_DACL) or ace.has(sd.WRITE_OWNER) or ace.has(sd.WRITE_PROPERTY):
                low_danger = True
        name = t.displayName or t.dn
        common: dict[str, object] = {"template_dn": t.dn, "eku": eku, "low_priv": sorted(set(enrollers))}
        if low_enroll and supplies_subject and client_auth:
            out.append(_esc(cfg, name, "ESC1", "ENROLLEE_SUPPLIES_SUBJECT + ClientAuth", common))
        if low_enroll and any_purpose:
            out.append(_esc(cfg, name, "ESC2", "AnyPurpose / без EKU", common))
        if low_enroll and enroll_agent:
            out.append(_esc(cfg, name, "ESC3", "Enrollment Agent", common))
        if low_danger:
            out.append(_esc(cfg, name, "ESC4", "Опасные права у низкопривилегированных", common))
    return out
