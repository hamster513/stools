"""Шаблоны AD CS: ESC1–4, 9, 13, 15 (спека AD CS, §6)."""
from __future__ import annotations

import uuid
from collections import Counter

from api.modules.ad.core import sd
from api.modules.ad.core.checks.adcs_rules import (
    Kind,
    requester_kind,
    requesters_details,
    unsafe_writers,
    writers_details,
)
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import AdObject, ExportIndex
from api.modules.ad.core.findings import Finding, finalize
from api.modules.ad.core.sd import SecurityDescriptor

EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_SMARTCARD = "1.3.6.1.4.1.311.20.2.2"
EKU_PKINIT = "1.3.6.1.5.2.3.4"
EKU_ANY = "2.5.29.37.0"
EKU_ENROLL_AGENT = "1.3.6.1.4.1.311.20.2.1"
LOGON_EKU = (EKU_CLIENT_AUTH, EKU_SMARTCARD, EKU_PKINIT, EKU_ANY)
GUID_ENROLL_DEFAULT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
GUID_AUTOENROLL_DEFAULT = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

PEND_ALL_REQUESTS = 0x2
NO_SECURITY_EXTENSION = 0x80000
ENROLLEE_SUPPLIES_SUBJECT = 0x1

UNPUBLISHED_NOTE = "шаблон не опубликован ни на одном ЦС"
PUBLICATION_UNKNOWN = "неизвестно"


def effective_eku(t: AdObject) -> list[str]:
    """Политики приложений, если заданы, иначе pKIExtendedKeyUsage."""
    return list(t.application_policies or t.pKIExtendedKeyUsage)


def logon_capable(eku: list[str]) -> bool:
    return not eku or any(e in eku for e in LOGON_EKU)


def unobstructed(t: AdObject) -> bool:
    """Нет одобрения менеджера и не нужна подпись агента."""
    return not (t.enrollment_flag or 0) & PEND_ALL_REQUESTS and not t.ra_signature


def _requesters(idx: ExportIndex, cfg: AdConfig, desc: SecurityDescriptor, enroll_rights: tuple[uuid.UUID | None, ...]) -> list[tuple[str, Kind]]:
    out: dict[str, Kind] = {}
    for ace in desc.dacl:
        if not ace.allow or ace.inherit_only or ace.sid in out:
            continue
        # object_type None у EXTENDED_RIGHT — «все расширенные права», Enroll среди них.
        if not (ace.has(sd.GENERIC_ALL) or (ace.has(sd.EXTENDED_RIGHT) and ace.object_type in enroll_rights)):
            continue
        kind = requester_kind(idx, cfg, ace.sid)
        if kind != "safe":
            out[ace.sid] = kind
    return list(out.items())


def _target_names(templates: list[AdObject]) -> dict[str, str]:
    """displayName или cn; у совпавших имён дописывается cn — ключи находок не должны слипнуться."""
    names = {t.dn: t.displayName or t.rdn_value for t in templates}
    seen = Counter(n.lower() for n in names.values())
    return {t.dn: f"{names[t.dn]} ({t.rdn_value})" if seen[names[t.dn].lower()] > 1 else names[t.dn] for t in templates}


def _on_behalf_templates(idx: ExportIndex, templates: list[AdObject]) -> int:
    """Шаблоны, по которым агент регистрации может выпустить сертификат от имени другого."""
    count = 0
    for t in templates:
        if idx.published_on(t) == []:
            continue
        v1_logon = t.schema_version == 1 and logon_capable(effective_eku(t))
        # У шаблонов v4 значение бывает строкой вида «msPKI-RA-Application-Policies`PZPWSTR`<OID>`».
        agent_signed = any(EKU_ENROLL_AGENT in p for p in t.ra_application_policies)
        count += v1_logon or agent_signed
    return count


def _linked_groups(idx: ExportIndex) -> dict[str, str]:
    """OID политики выдачи → DN группы из msDS-OIDToGroupLink."""
    return {o.template_oid: o.oid_group_link for o in idx.objects("msPKI-Enterprise-Oid") if o.template_oid and o.oid_group_link}


def check_adcs_templates(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    enroll_rights = (
        uuid.UUID(idx.extended_right("Enroll") or GUID_ENROLL_DEFAULT),
        uuid.UUID(idx.extended_right("AutoEnroll") or GUID_AUTOENROLL_DEFAULT),
        None,
    )
    templates = idx.objects("pKICertificateTemplate")
    names = _target_names(templates)
    links = _linked_groups(idx)
    on_behalf: int | None = None
    out: list[Finding] = []
    for t in templates:
        desc = idx.sd_of(t)
        if desc is None:
            continue
        eku = effective_eku(t)
        requesters = _requesters(idx, cfg, desc, enroll_rights)
        # (ESC, базовая серьёзность, условие, заявители, доп. детали)
        hits: list[tuple[str, str, str, list[tuple[str, Kind]], dict[str, object]]] = []
        if requesters:
            free, logon = unobstructed(t), logon_capable(eku)
            supplies = bool((t.name_flag or 0) & ENROLLEE_SUPPLIES_SUBJECT)
            if free and supplies and logon:
                hits.append(("ESC1", "High", "субъект сертификата задаёт заявитель, сертификат годится для входа", requesters, {}))
            if free and (not eku or EKU_ANY in eku):
                hits.append(("ESC2", "High", "Any Purpose или EKU пуст: сертификат годится для любой цели", requesters, {}))
            if free and EKU_ENROLL_AGENT in eku:
                if on_behalf is None:
                    on_behalf = _on_behalf_templates(idx, templates)
                hits.append(("ESC3", "High", "сертификат агента регистрации: выпуск сертификатов от имени других", requesters, {"on_behalf_templates": on_behalf}))
            if free and (t.enrollment_flag or 0) & NO_SECURITY_EXTENSION and logon:
                hits.append(("ESC9", "Medium", "в сертификат не пишется расширение безопасности с SID (NO_SECURITY_EXTENSION), сертификат годится для входа", requesters, {}))
            groups = sorted({links[p] for p in t.issuance_policies if p in links})
            if free and groups and logon:
                hits.append(("ESC13", "High", "политика выдачи шаблона связана с группой: сертификат даёт её права", requesters, {"group": "; ".join(groups)}))
            if free and t.schema_version == 1 and supplies:
                hits.append(("ESC15", "High", "шаблон схемы v1, субъект задаёт заявитель: политики приложений подставляются из запроса (закрыто обновлением ноября 2024)", requesters, {}))
        rated = [(code, *requesters_details(idx, principals, text, base), extra) for code, base, text, principals, extra in hits]
        writers = unsafe_writers(idx, cfg, t, desc)
        if writers:
            text = "право менять шаблон (GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty или владелец)"
            rated.append(("ESC4", *writers_details(idx, writers, text, "High"), {}))
        published = idx.published_on(t)
        for code, severity, common, extra in rated:
            if published == []:
                severity = "Low"
                common["details"] = f"{common['details']}; {UNPUBLISHED_NOTE}"
            details: dict[str, object] = {
                "esc": code,
                **common,
                "published": PUBLICATION_UNKNOWN if published is None else published,
                "template_dn": t.dn,
                "eku": eku,
                **extra,
            }
            out.append(finalize(Finding(check="ADCS_ESC", severity=severity, target=names[t.dn], key_extra=code, details=details), cfg))
    return out
