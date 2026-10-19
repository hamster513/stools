"""Каких данных в выгрузке нет: проверка без находок и непроверенная — разное.

Сборщик может не принести часть данных молча (SYSVOL недоступен по SMB,
атрибут не отдан, контейнера нет). Проверка тогда честно ничего не находит, а
обзор показывал её в «Без находок». Здесь — код проверки → причина, по которой
её результат нельзя считать проверкой.
"""
from __future__ import annotations

import base64

from api.modules.ad.core.ca_data import CaAuthority, CaData, DcBinding
from api.modules.ad.core.checks.adcs_ca import broken_security, unread
from api.modules.ad.core.checks.critical_acl import DMSA_CLASS
from api.modules.ad.core.checks.domain import functional_level_value
from api.modules.ad.core.checks.gpo_settings import LINKS_UNKNOWN
from api.modules.ad.core.export import _LINK_CONTAINERS, CRITICAL_ACL_UNREAD, AdExport, ExportIndex
from api.modules.ad.core.sd import parse_sd


def coverage_gaps(export: AdExport, ca: CaData | None = None) -> dict[str, str]:
    users = gpos = templates = pki_objects = enrollment_services = computers = 0
    has_os = has_primary_group = False
    dcs = dc_acl = dc_owner = 0
    logon_dates = False
    for o in export.objects:
        if o.cls in ("user", "computer"):
            has_primary_group = has_primary_group or o.primaryGroupID is not None
        if o.cls == "user":
            users += 1
            logon_dates = logon_dates or bool(o.lastLogonTimestamp)
        elif o.cls == "computer":
            computers += 1
            has_os = has_os or bool(o.operatingSystem)
            if ExportIndex.is_dc(o):
                dcs += 1
                if o.sd:
                    dc_acl += 1
                    dc_owner += parse_sd(base64.b64decode(o.sd)).owner is not None
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
    elif dc_acl and not dc_owner:
        # LDAP-сборщик до SD_FLAGS 0x05 читал только DACL.
        gaps["DcOwner"] = "дескрипторы собраны без владельца (сборщик старой версии)"
    root = next((o for o in export.objects if o.dn.lower() == export.domain.dn.lower()), None)
    if root is None or not root.sd:
        gaps["DomainRootAcl"] = "дескриптор корня домена не собран"
    level_reasons = []
    if functional_level_value(export.domain.functional_level) is None:
        level_reasons.append(f"функциональный уровень домена не прочитан (значение «{export.domain.functional_level}»)")
    # None — сборщик старой версии уровень леса не читал: это не пробел, проверка уровня домена полная.
    forest = export.domain.forest_functional_level
    if forest and functional_level_value(forest) is None:
        level_reasons.append(f"функциональный уровень леса не прочитан (значение «{forest}»)")
    if level_reasons:
        gaps["FunctionalLevel"] = "; ".join(level_reasons)
    gaps.update(_domain_settings_gaps(export, users or computers, has_primary_group))
    gaps.update(_trust_dns_gaps(export))
    gaps.update(_critical_acl_gaps(export))
    if (users or computers) and not has_primary_group:
        # Ни у одной учётки нет primaryGroupID — атрибуты сборщика 1.1/2.1 не собраны вовсе.
        for code in ("SidHistory", "UnixPasswords", "ComputerCreators"):
            gaps[code] = "атрибуты учётных записей собраны старым сборщиком"
        note = "учётки без входов не проверены: нет whenCreated"
        gaps["InactiveUsers"] = f"{gaps['InactiveUsers']}; {note}" if "InactiveUsers" in gaps else note
    if gpos and not export.sysvol:
        note = next((n for n in export.collector.notes if "SYSVOL" in n), "")
        gaps["UserRightsAssignment"] = "файлы GptTmpl.inf из SYSVOL не прочитаны" + (f" ({note})" if note else "")
    if gpos:
        gaps.update(_gpo_gaps(export))
    dc_state = _dc_state_reasons(ca)
    if dc_state:
        gaps["DcHardening"] = "; ".join(dc_state)
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


OLD_COLLECTOR = "настройки домена не собраны (сборщик старой версии)"
PSO_UNREAD = "PSO не прочитаны или не видны (нужны права администратора домена); политика домена проверена"


def _domain_settings_gaps(export: AdExport, accounts: int, has_primary_group: bool) -> dict[str, str]:
    """Новые поля блока domain: None — не прочитано (сборщик старой версии или отказ чтения)."""
    d = export.domain
    not_read = {
        "PasswordPolicy": None in (d.min_pwd_length, d.lockout_threshold, d.pwd_properties),
        "RecycleBin": d.recycle_bin is None,
        "DsHeuristics": d.ds_heuristics is None,
        "BackupAge": not d.backup_read,
        "SmartcardPassword": d.smartcard_rotation is None,
        "NtfrsSysvol": d.sysvol_replication is None,
        "SchemaVulnerableClass": d.schema_poss_superiors is None,
        "LapsDeployment": d.laps_legacy_schema is None and d.laps_schema is None,
    }
    gaps = {code: OLD_COLLECTOR for code, missing in not_read.items() if missing}
    if d.laps_legacy_schema is None and d.laps_schema is False or d.laps_legacy_schema is False and d.laps_schema is None:
        gaps["LapsDeployment"] = "схема LAPS прочитана не полностью"
    if d.backup_read is False:
        gaps["BackupAge"] = "метаданные репликации корня домена (dSASignature) не прочитаны"
    if "PasswordPolicy" not in gaps and any("PSO не прочитаны" in n or "PSO не найдены" in n for n in export.collector.notes):
        gaps["PasswordPolicy"] = PSO_UNREAD
    if accounts and not has_primary_group:
        gaps["PrimaryGroup"] = "ни у одной учётной записи нет primaryGroupID (сборщик старой версии)"
    return gaps


def _trust_dns_gaps(export: AdExport) -> dict[str, str]:
    gaps: dict[str, str] = {}
    trusts = [o for o in export.objects if o.cls == "trustedDomain"]
    if trusts and all(t.trustDirection is None for t in trusts):
        gaps["TrustSecurity"] = "доверия собраны старым сборщиком"
    if not any(o.cls == "dnsZone" for o in export.objects):
        notes = [n for n in export.collector.notes if "зоны DNS не прочитаны" in n]
        gaps["DnsZones"] = f"зоны DNS не собраны: {'; '.join(notes)}" if notes else "зоны DNS не собраны (сборщик старой версии)"
    return gaps


_GPO_FILE_CHECKS = ("GpoSecurityOptions", "DcLogonRights", "RestrictedGroups")
_LINKS_UNKNOWN_CHECKS = ("GpoSecurityOptions", "DcLogonRights", "DcAuditPolicy")
_GPO_BLOCK_CHECKS = ("GpoRegistrySettings", "DcAuditPolicy", "GpoExternalFiles", "SysvolAcl")


def _gpo_gaps(export: AdExport) -> dict[str, str]:
    """Проверки этапа GPO: блок gpo (Registry.pol, GPP) и GptTmpl.inf; приписка о привязке — проверка при этом выполнена."""
    note = next((n for n in export.collector.notes if "SYSVOL" in n), "")
    suffix = f" ({note})" if note else ""
    reasons: dict[str, list[str]] = {}
    if export.gpo is None:
        reasons["GppPasswords"] = ["настройки GPP и Registry.pol не собраны (сборщик старой версии или SYSVOL не прочитан)" + suffix]
        for code in _GPO_BLOCK_CHECKS:
            reasons[code] = ["Registry.pol, audit.csv, сценарии и настройки GPP не собраны (сборщик старой версии или SYSVOL не прочитан)" + suffix]
        if not export.sysvol:
            for code in _GPO_FILE_CHECKS:
                reasons[code] = ["файлы GPO из SYSVOL не прочитаны" + suffix]
    elif all(data.acl is None for data in export.gpo.values()):
        reasons["SysvolAcl"] = ["права на SYSVOL читает только PowerShell-сборщик"]
    if not export.sysvol:
        # Права входа есть только в GptTmpl.inf: без него отсутствие запрета не доказано.
        reasons["TieringLogonDeny"] = ["файлы GptTmpl.inf не прочитаны" + suffix]
        reasons.setdefault("DcLogonRights", ["файлы GptTmpl.inf не прочитаны" + suffix])
    if not any(o.gpLink is not None for o in export.objects if o.cls in _LINK_CONTAINERS):
        for code in _LINKS_UNKNOWN_CHECKS:
            reasons.setdefault(code, []).append(LINKS_UNKNOWN)
    return {code: "; ".join(parts) for code, parts in reasons.items()}


def _critical_acl_gaps(export: AdExport) -> dict[str, str]:
    gaps: dict[str, str] = {}
    notes = export.collector.notes
    if not export.collector.critical_acl:
        gaps["CriticalObjectAcl"] = "дескрипторы критичных объектов не собраны (сборщик старой версии)"
    elif failed := [n for n in notes if CRITICAL_ACL_UNREAD in n]:
        gaps["CriticalObjectAcl"] = "; ".join(failed)
    # Ключа класса dMSA нет: старый сборщик схему не проверял, новый — не смог прочитать.
    if DMSA_CLASS not in export.guids.schema_classes:
        if not export.collector.critical_acl:
            gaps["BadSuccessor"] = "класс dMSA в схеме не проверялся (выгрузка старого сборщика)"
        else:
            failed = [n for n in notes if "схема не прочитана" in n]
            gaps["BadSuccessor"] = "класс dMSA в схеме не проверен: " + ("; ".join(failed) if failed else "схема не прочитана")
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


def _dc_state_reasons(ca: CaData | None) -> list[str]:
    """Состояние контроллеров (раздел dc сборщика 2.3): по каждому контроллеру — какой канал не отработал.
    Запись сборщика до 2.3 флагов не несёт — оба канала у неё не прочитаны."""
    if ca is None or "dc" not in ca.sections:
        return ["нужно состояние контроллеров (сборщик, пункт 6)"]
    reasons = []
    for d in ca.dcs:
        if not d.registry_read:
            reasons.append(f"контроллер {d.host}: реестр не прочитан{_channel_error(d.error, 'реестр: ')}")
        if not d.cim_read:
            reasons.append(f"контроллер {d.host}: службы и SMB не прочитаны{_channel_error(d.error, 'CIM: ')}")
    return reasons


def _channel_error(error: str, prefix: str) -> str:
    """Часть error о канале в скобках. Сборщик 2.3 пишет отказы частями через «; »: «реестр: …» — одна
    часть, «CIM: …» — последняя (внутри неё свои «; »). Части с префиксом нет — весь текст."""
    if not error:
        return ""
    parts = error.split("; ")
    for i, part in enumerate(parts):
        if part.startswith(prefix):
            return f" ({'; '.join(parts[i:]) if prefix == 'CIM: ' else part})"
    return f" ({error})"


def _dc_record_reasons(d: DcBinding) -> list[str]:
    # Реестр прочитан целиком: значения привязки, которого нет, — значение по умолчанию, а текст
    # в error относится к CIM.
    if not d.error or d.registry_read:
        return []
    if d.strong_binding is None and d.mapping_methods is None:
        return [f"контроллер {d.host}: реестр не прочитан ({d.error})"]
    if d.mapping_methods is None:
        return [f"контроллер {d.host}: сопоставление по UPN (ESC10) не проверено ({d.error})"]
    if d.strong_binding is None:
        return [f"контроллер {d.host}: привязка (ESC10) не проверена ({d.error})"]
    return []
