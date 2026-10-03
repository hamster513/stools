"""Каких данных в выгрузке нет: проверка без находок и непроверенная — разное.

Сборщик может не принести часть данных молча (SYSVOL недоступен по SMB,
атрибут не отдан, контейнера нет). Проверка тогда честно ничего не находит, а
обзор показывал её в «Без находок». Здесь — код проверки → причина, по которой
её результат нельзя считать проверкой.
"""
from __future__ import annotations

from api.modules.ad.core.ca_data import CaAuthority, CaData, DcBinding
from api.modules.ad.core.checks.adcs_ca import broken_security, unread
from api.modules.ad.core.checks.domain import functional_level_value
from api.modules.ad.core.export import AdExport, ExportIndex


def coverage_gaps(export: AdExport, ca: CaData | None = None) -> dict[str, str]:
    users = gpos = templates = pki_objects = enrollment_services = computers = 0
    has_os = False
    dcs = dc_acl = 0
    logon_dates = False
    for o in export.objects:
        if o.cls == "user":
            users += 1
            logon_dates = logon_dates or bool(o.lastLogonTimestamp)
        elif o.cls == "computer":
            computers += 1
            has_os = has_os or bool(o.operatingSystem)
            if ExportIndex.is_dc(o):
                dcs += 1
                dc_acl += bool(o.sd)
        elif o.cls == "groupPolicyContainer":
            gpos += 1
        elif o.cls == "pKICertificateTemplate":
            templates += 1
        elif o.cls in ("pkiContainer", "pKIEnrollmentService"):
            pki_objects += 1
            enrollment_services += o.cls == "pKIEnrollmentService"
    gaps: dict[str, str] = {}
    if users and not logon_dates:
        gaps["InactiveUsers"] = "в выгрузке нет дат последнего входа ни у одной учётной записи"
    if computers and not has_os:
        gaps["ObsoleteOs"] = "в выгрузке нет ОС компьютеров (сборщик старой версии)"
    if not dcs:
        gaps["DcCount"] = "в выгрузке нет контроллеров домена"
    if dcs and not dc_acl:
        gaps["DcOwner"] = "компьютеры собраны без ACL: владелец контроллеров не известен"
    root = next((o for o in export.objects if o.dn.lower() == export.domain.dn.lower()), None)
    if root is None or not root.sd:
        gaps["DomainRootAcl"] = "дескриптор корня домена не собран"
    if functional_level_value(export.domain.functional_level) is None:
        gaps["FunctionalLevel"] = f"функциональный уровень домена не прочитан (значение «{export.domain.functional_level}»)"
    if gpos and not export.sysvol:
        note = next((n for n in export.collector.notes if "SYSVOL" in n), "")
        gaps["UserRightsAssignment"] = "файлы GptTmpl.inf из SYSVOL не прочитаны" + (f" ({note})" if note else "")
    if not templates:
        gaps["ADCS_ESC"] = "шаблонов сертификатов в выгрузке нет: в лесу нет AD CS или контейнер шаблонов недоступен"
    if not templates and not enrollment_services:
        # В домене нет AD CS: проверкам ЦС и привязки проверять нечего, они честно чистые.
        return gaps
    ca_reasons: list[str] = []
    if templates and not pki_objects:
        ca_reasons.append("ESC5 не проверен: выгрузка собрана без объектов PKI (старый сборщик)")
    sections = set(ca.sections) if ca else set()
    if "ca" not in sections:
        ca_reasons.append("ESC6, 7, 11, 16 не проверены: нужны данные ЦС (сборщик, пункт 5)")
    elif ca:
        for c in ca.cas:
            ca_reasons += _ca_record_reasons(c)
    if "web" not in sections:
        ca_reasons.append("ESC8 не проверен: нужна проверка веб-выдачи (сборщик, пункт 7)")
    elif ca:
        ca_reasons += [f"веб-выдача {w.url}: не проверена ({w.error})" for w in ca.web if w.error and w.status is None]
    if ca_reasons:
        gaps["ADCS_CA"] = "; ".join(ca_reasons)
    if "dc" not in sections:
        gaps["ADCS_MAPPING"] = "ESC10 не проверен: нужен реестр контроллеров (сборщик, пункт 6)"
    elif ca:
        dc_reasons = [reason for d in ca.dcs for reason in _dc_record_reasons(d)]
        if dc_reasons:
            gaps["ADCS_MAPPING"] = "; ".join(dc_reasons)
    return gaps


def _ca_record_reasons(c: CaAuthority) -> list[str]:
    """Сборщик прочитал ЦС не целиком (есть ошибка): каждое непрочитанное значение — свои ESC.
    Не прочитано ничего — одна общая причина."""
    if unread(c):
        return [f"ЦС {c.name}: данные не прочитаны ({c.error})"]
    reasons = [f"ЦС {c.name}: дескриптор прав не разобран"] if broken_security(c) else []
    if c.error:
        if c.security is None:
            reasons.append(f"ЦС {c.name}: ESC7 не проверен — права ЦС не прочитаны ({c.error})")
        if c.edit_flags is None:
            reasons.append(f"ЦС {c.name}: ESC6, 16 не проверены — флаги политики не прочитаны ({c.error})")
        if c.interface_flags is None:
            reasons.append(f"ЦС {c.name}: ESC11 не проверен — флаги интерфейса не прочитаны ({c.error})")
    return reasons


def _dc_record_reasons(d: DcBinding) -> list[str]:
    if not d.error:
        return []
    if d.strong_binding is None and d.mapping_methods is None:
        return [f"контроллер {d.host}: реестр не прочитан ({d.error})"]
    if d.mapping_methods is None:
        return [f"контроллер {d.host}: сопоставление по UPN (ESC10) не проверено ({d.error})"]
    if d.strong_binding is None:
        return [f"контроллер {d.host}: привязка (ESC10) не проверена ({d.error})"]
    return []
