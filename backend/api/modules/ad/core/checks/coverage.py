"""Каких данных в выгрузке нет: проверка без находок и непроверенная — разное.

Сборщик может не принести часть данных молча (SYSVOL недоступен по SMB,
атрибут не отдан, контейнера нет). Проверка тогда честно ничего не находит, а
обзор показывал её в «Без находок». Здесь — код проверки → причина, по которой
её результат нельзя считать проверкой.
"""
from __future__ import annotations

from api.modules.ad.core.ca_data import CaData
from api.modules.ad.core.export import AdExport


def coverage_gaps(export: AdExport, ca: CaData | None = None) -> dict[str, str]:
    users = gpos = templates = pki_objects = 0
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
    gaps: dict[str, str] = {}
    if users and not logon_dates:
        gaps["InactiveUsers"] = "в выгрузке нет дат последнего входа ни у одной учётной записи"
    if gpos and not export.sysvol:
        note = next((n for n in export.collector.notes if "SYSVOL" in n), "")
        gaps["UserRightsAssignment"] = "файлы GptTmpl.inf из SYSVOL не прочитаны" + (f" ({note})" if note else "")
    if not templates:
        gaps["ADCS_ESC"] = "шаблонов сертификатов в выгрузке нет: в лесу нет AD CS или контейнер шаблонов недоступен"
    elif not pki_objects:
        gaps["ADCS_CA"] = "ESC5 не проверен: выгрузка собрана без объектов PKI (старый сборщик)"
    return gaps
