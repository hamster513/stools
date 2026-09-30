"""Каких данных в выгрузке нет: проверка без находок и непроверенная — разное.

Сборщик может не принести часть данных молча (SYSVOL недоступен по SMB,
атрибут не отдан, контейнера нет). Проверка тогда честно ничего не находит, а
обзор показывал её в «Без находок». Здесь — код проверки → причина, по которой
её результат нельзя считать проверкой.
"""
from __future__ import annotations

from api.modules.ad.core.ca_data import CaData
from api.modules.ad.core.checks.adcs_ca import broken_security, unread
from api.modules.ad.core.export import AdExport


def coverage_gaps(export: AdExport, ca: CaData | None = None) -> dict[str, str]:
    users = gpos = templates = pki_objects = enrollment_services = 0
    logon_dates = False
    for o in export.objects:
        if o.cls == "user":
            users += 1
            logon_dates = logon_dates or bool(o.lastLogonTimestamp)
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
        ca_reasons += [f"ЦС {c.name}: данные не прочитаны ({c.error})" for c in ca.cas if unread(c)]
        ca_reasons += [f"ЦС {c.name}: дескриптор прав не разобран" for c in ca.cas if broken_security(c)]
    if "web" not in sections:
        ca_reasons.append("ESC8 не проверен: нужна проверка веб-выдачи (сборщик, пункт 7)")
    elif ca:
        ca_reasons += [f"веб-выдача {w.url}: не проверена ({w.error})" for w in ca.web if w.error and w.status is None]
    if ca_reasons:
        gaps["ADCS_CA"] = "; ".join(ca_reasons)
    if "dc" not in sections:
        gaps["ADCS_MAPPING"] = "ESC10 не проверен: нужен реестр контроллеров (сборщик, пункт 6)"
    elif ca:
        dc_reasons = [
            f"контроллер {d.host}: реестр не прочитан ({d.error})"
            for d in ca.dcs
            if d.error and d.strong_binding is None and d.mapping_methods is None
        ]
        if dc_reasons:
            gaps["ADCS_MAPPING"] = "; ".join(dc_reasons)
    return gaps
