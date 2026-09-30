"""Центр сертификации: ESC5 по снапшоту (права на объекты PKI в разделе конфигурации),
ESC6, 7, 8, 11, 16 по данным ЦС (`stools-ad-ca/1`)."""
from __future__ import annotations

import base64
import struct

from api.modules.ad.core import sd
from api.modules.ad.core.ca_data import CaAuthority, WebEndpoint
from api.modules.ad.core.checks.adcs_rules import (
    Writer,
    ca_data_details,
    denials,
    requester_kind,
    unsafe_writers,
    writers_details,
)
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex
from api.modules.ad.core.findings import Finding, finalize
from api.modules.ad.core.sd import SecurityDescriptor

PKI_OBJECT_CLASSES = ("pkiContainer", "pKIEnrollmentService")

EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
IF_ENFORCEENCRYPTICERTREQUEST = 0x200
SECURITY_EXTENSION_OID = "1.3.6.1.4.1.311.25.2"
#: Права в дескрипторе ЦС (CA\Security) — свои, не права объектов AD.
CA_RIGHTS = (("ManageCA", 0x1), ("ManageCertificates", 0x2))
CA_MANAGE_MASK = 0x1 | 0x2
NTLM_SCHEMES = ("ntlm", "negotiate")


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


def unread(ca: CaAuthority) -> bool:
    """Сборщик не прочитал ЦС: есть ошибка и нет ни одного значения."""
    return bool(ca.error) and ca.edit_flags is None and ca.interface_flags is None and ca.security is None and not ca.disable_extension_list


def ca_descriptor(ca: CaAuthority) -> SecurityDescriptor | None:
    """Дескриптор прав ЦС; нет его или он не разобран (не base64, битые байты) — None."""
    if not ca.security:
        return None
    try:
        return sd.parse_sd(base64.b64decode(ca.security, validate=True))
    except (ValueError, struct.error, IndexError):  # binascii.Error — подкласс ValueError
        return None


def broken_security(ca: CaAuthority) -> bool:
    return bool(ca.security) and ca_descriptor(ca) is None


def _ca_managers(idx: ExportIndex, cfg: AdConfig, desc: SecurityDescriptor) -> list[Writer]:
    """Небезопасные субъекты с ManageCA или ManageCertificates в разрешающих ACE за вычетом запретов того же SID."""
    denied = denials(desc, lambda a: a.mask & CA_MANAGE_MASK)
    rights: dict[str, int] = {}
    for ace in desc.dacl:
        if not ace.allow or ace.inherit_only:
            continue
        granted = ace.mask & CA_MANAGE_MASK & ~denied(ace)
        if granted:
            rights[ace.sid] = rights.get(ace.sid, 0) | granted
    out: list[Writer] = []
    for sid, mask in rights.items():
        kind = requester_kind(idx, cfg, sid)
        if kind != "safe":
            out.append((sid, kind, [name for name, bit in CA_RIGHTS if mask & bit]))
    return out


def _esc_by_ca(idx: ExportIndex, cfg: AdConfig, ca: CaAuthority) -> list[Finding]:
    base = {"host": ca.host, **ca_data_details(idx, "ca")}
    out: list[Finding] = []
    if ca.edit_flags is not None and ca.edit_flags & EDITF_ATTRIBUTESUBJECTALTNAME2:
        text = "EDITF_ATTRIBUTESUBJECTALTNAME2: SAN в запросе; после обновлений мая 2022 эксплуатируется вместе со слабой привязкой (ESC9/ESC10/ESC16)"
        out.append(_finding(cfg, "ESC6", "High", ca.name, {"details": text, **base}))
    desc = ca_descriptor(ca)
    if desc is not None:
        managers = _ca_managers(idx, cfg, desc)
        if managers:
            severity, common = writers_details(idx, managers, "право управлять ЦС (ManageCA) или выдавать и отзывать сертификаты (ManageCertificates)", "High")
            granted = {r for _, _, rights in managers for r in rights}
            common["rights"] = [name for name, _ in CA_RIGHTS if name in granted]
            out.append(_finding(cfg, "ESC7", severity, ca.name, {**common, **base}))
    if ca.interface_flags is not None and not ca.interface_flags & IF_ENFORCEENCRYPTICERTREQUEST:
        text = "IF_ENFORCEENCRYPTICERTREQUEST выключен: ЦС принимает запросы по RPC без шифрования (ретрансляция NTLM)"
        out.append(_finding(cfg, "ESC11", "High", ca.name, {"details": text, **base}))
    if SECURITY_EXTENSION_OID in ca.disable_extension_list:
        text = f"расширение безопасности с SID ({SECURITY_EXTENSION_OID}) отключено на ЦС для всех шаблонов"
        out.append(_finding(cfg, "ESC16", "High", ca.name, {"details": text, **base}))
    return out


def _esc8(idx: ExportIndex, cfg: AdConfig, endpoints: list[WebEndpoint]) -> list[Finding]:
    out: list[Finding] = []
    for web in endpoints:
        schemes = sorted({a for a in web.auth if a.split(" ", 1)[0].lower() in NTLM_SCHEMES})
        if web.status != 401 or not schemes:
            continue
        https = web.url.lower().startswith("https://")
        text = "веб-выдача сертификатов принимает NTLM: ретрансляция NTLM на ЦС"
        if https:
            text += "; проверьте, включена ли расширенная защита (EPA)"
        details = {"details": text, "url": web.url, "status": web.status, "auth": list(web.auth), **ca_data_details(idx, "web")}
        out.append(_finding(cfg, "ESC8", "Medium" if https else "High", web.url, details))
    return out


def check_adcs_ca(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out = _esc5(idx, cfg)
    if idx.ca is None:
        return out
    for ca in idx.ca.cas:
        if not unread(ca):
            out.extend(_esc_by_ca(idx, cfg, ca))
    out.extend(_esc8(idx, cfg, idx.ca.web))
    return out
