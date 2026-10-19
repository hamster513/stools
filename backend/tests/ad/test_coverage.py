"""«Не проверено: нет данных» — пустая проверка отличается от непроверенной."""
from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.modules.ad.core.ca_data import CaData, parse_ca_data
from api.modules.ad.core.checks import ANALYZER_VERSION
from api.modules.ad.core.checks.adcs_ca import check_adcs_ca
from api.modules.ad.core.checks.adcs_mapping import check_adcs_mapping
from api.modules.ad.core.checks.coverage import coverage_gaps
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex, load_export
from api.modules.ad.models import AdSnapshot
from tests.ad.synthetic import build_ca_data, build_export

FULL_CA = parse_ca_data(build_ca_data())


def _gaps(raw: dict[str, Any], ca: CaData | None = FULL_CA) -> dict[str, str]:
    gaps = coverage_gaps(load_export(json.dumps(raw).encode()), ca)
    # В синтетической выгрузке нет контроллеров; пробел DcCount проверяет test_computers.
    gaps.pop("DcCount", None)
    return gaps


def test_full_export_has_no_gaps() -> None:
    assert _gaps(build_export()) == {}


def test_old_collector_accounts_mark_new_attribute_checks_unchecked() -> None:
    raw = build_export()
    for o in raw["objects"]:
        o.pop("primaryGroupID", None)
    gaps = _gaps(raw)
    assert set(gaps) == {"PrimaryGroup", "SidHistory", "UnixPasswords", "ComputerCreators", "InactiveUsers"}
    assert gaps["SidHistory"] == gaps["UnixPasswords"] == gaps["ComputerCreators"] == "атрибуты учётных записей собраны старым сборщиком"
    assert gaps["InactiveUsers"] == "учётки без входов не проверены: нет whenCreated"


def test_old_collector_note_joins_inactive_users_reason() -> None:
    raw = build_export()
    for o in raw["objects"]:
        o.pop("primaryGroupID", None)
        o.pop("lastLogonTimestamp", None)
    assert _gaps(raw)["InactiveUsers"] == "в выгрузке нет дат последнего входа ни у одной учётной записи; учётки без входов не проверены: нет whenCreated"


def test_root_without_sd_marks_domain_root_acl_unchecked() -> None:
    raw = build_export()
    root = next(o for o in raw["objects"] if o["class"] == "domainDNS")
    root.pop("sd")
    assert _gaps(raw) == {"DomainRootAcl": "дескриптор корня домена не собран"}
    raw["objects"].remove(root)
    assert "DomainRootAcl" in _gaps(raw)


@pytest.mark.parametrize("value", ["", "WindowsThresholdDomain"])
def test_unknown_functional_level_marks_unchecked(value: str) -> None:
    raw = build_export()
    raw["domain"]["functional_level"] = value
    assert _gaps(raw) == {"FunctionalLevel": f"функциональный уровень домена не прочитан (значение «{value}»)"}


def test_missing_sysvol_marks_user_rights_unchecked() -> None:
    raw = build_export()
    raw["sysvol"] = {}
    gaps = _gaps(raw)
    assert set(gaps) == {"UserRightsAssignment", "TieringLogonDeny", "DcLogonRights"} and "SYSVOL" in gaps["UserRightsAssignment"]
    assert gaps["TieringLogonDeny"] == gaps["DcLogonRights"] == "файлы GptTmpl.inf не прочитаны"


def test_collector_note_explains_missing_sysvol() -> None:
    raw = build_export()
    raw["sysvol"] = {}
    raw["collector"]["notes"] = ["SYSVOL недоступен: ConnectionError"]
    assert "ConnectionError" in _gaps(raw)["UserRightsAssignment"]


GPO_FILE_CHECKS = {"GpoSecurityOptions", "DcLogonRights", "RestrictedGroups"}
GPO_BLOCK_CHECKS = {"GppPasswords", "GpoRegistrySettings", "DcAuditPolicy", "GpoExternalFiles", "SysvolAcl"}


def test_missing_gpo_block_marks_gpp_passwords_unchecked() -> None:
    raw = build_export()
    raw.pop("gpo")
    assert set(_gaps(raw)) == GPO_BLOCK_CHECKS


def test_gpo_block_without_acl_marks_sysvol_acl_unchecked() -> None:
    raw = build_export()
    for data in raw["gpo"].values():
        data.pop("acl")
    assert _gaps(raw) == {"SysvolAcl": "права на SYSVOL читает только PowerShell-сборщик"}


def test_missing_sysvol_and_gpo_block_mark_gpo_file_checks_unchecked() -> None:
    raw = build_export()
    raw["sysvol"] = {}
    raw.pop("gpo")
    gaps = _gaps(raw)
    assert set(gaps) == {"UserRightsAssignment", "TieringLogonDeny"} | GPO_BLOCK_CHECKS | GPO_FILE_CHECKS
    assert all(gaps[code] == "файлы GPO из SYSVOL не прочитаны" for code in GPO_FILE_CHECKS)
    assert gaps["TieringLogonDeny"] == "файлы GptTmpl.inf не прочитаны"


def test_unknown_gpo_links_are_noted() -> None:
    raw = build_export()
    for o in raw["objects"]:
        o.pop("gpLink", None)
    links = "привязка GPO неизвестна (сборщик старой версии)"
    assert _gaps(raw) == {code: links for code in ("GpoSecurityOptions", "DcLogonRights", "DcAuditPolicy")}
    raw["sysvol"] = {}
    raw.pop("gpo")
    assert _gaps(raw)["DcLogonRights"] == f"файлы GPO из SYSVOL не прочитаны; {links}"


def test_missing_logon_dates_mark_inactive_users_unchecked() -> None:
    raw = build_export()
    for o in raw["objects"]:
        o.pop("lastLogonTimestamp", None)
    assert set(_gaps(raw)) == {"InactiveUsers"}


def test_missing_templates_mark_adcs_unchecked() -> None:
    raw = build_export()
    raw["objects"] = [o for o in raw["objects"] if o["class"] != "pKICertificateTemplate"]
    assert set(_gaps(raw)) == {"ADCS_ESC"}


def test_old_export_without_pki_objects_marks_esc5_unchecked() -> None:
    raw = build_export()
    raw["objects"] = [o for o in raw["objects"] if o["class"] not in ("pkiContainer", "pKIEnrollmentService")]
    gaps = _gaps(raw)
    assert set(gaps) == {"ADCS_CA"} and "ESC5" in gaps["ADCS_CA"]


def test_ca_object_alone_is_enough_for_esc5() -> None:
    raw = build_export()
    raw["objects"] = [o for o in raw["objects"] if o["class"] != "pkiContainer"]
    assert _gaps(raw) == {}


def test_domain_without_gpo_is_not_a_gap() -> None:
    raw = build_export()
    raw["sysvol"] = {}
    raw["objects"] = [o for o in raw["objects"] if o["class"] != "groupPolicyContainer"]
    assert "UserRightsAssignment" not in _gaps(raw)


def test_without_ca_data_ca_checks_are_unchecked() -> None:
    gaps = _gaps(build_export(), None)
    assert set(gaps) == {"ADCS_CA", "ADCS_MAPPING", "DcHardening"}
    assert gaps["ADCS_CA"] == (
        "ESC6, 7, 11, 16 не проверены: нужны данные ЦС (сборщик, пункт 5); "
        "ESC8 не проверен: нужна проверка веб-выдачи (сборщик, пункт 7)"
    )
    assert gaps["ADCS_MAPPING"] == "ESC10 не проверен: нужен реестр контроллеров (сборщик, пункт 6)"


def test_only_ca_section_leaves_web_and_dc_unchecked() -> None:
    gaps = _gaps(build_export(), parse_ca_data(build_ca_data(sections=["ca"], dcs=[], web=[])))
    assert "ESC8" in gaps["ADCS_CA"] and "ESC6" not in gaps["ADCS_CA"] and "ESC10" in gaps["ADCS_MAPPING"]


def test_ca_reasons_join_with_esc5_reason() -> None:
    raw = build_export()
    raw["objects"] = [o for o in raw["objects"] if o["class"] not in ("pkiContainer", "pKIEnrollmentService")]
    reasons = _gaps(raw, parse_ca_data(build_ca_data(sections=["ca", "dc"], web=[])))["ADCS_CA"].split("; ")
    assert len(reasons) == 2 and reasons[0].startswith("ESC5") and reasons[1].startswith("ESC8")


def test_unread_ca_is_a_reason() -> None:
    ca = parse_ca_data(build_ca_data(cas=[{"name": "CORP-CA", "host": "ca01.corp.local", "error": "доступ запрещён"}]))
    assert _gaps(build_export(), ca) == {"ADCS_CA": "ЦС CORP-CA: данные не прочитаны (доступ запрещён)"}


def test_domain_without_adcs_has_no_ca_data_reasons() -> None:
    """Нет ни шаблонов, ни ЦС — в домене нет AD CS: проверкам ЦС и привязки проверять нечего."""
    raw = build_export()
    raw["objects"] = [o for o in raw["objects"] if o["class"] not in ("pKICertificateTemplate", "pKIEnrollmentService")]
    # Состоянию контроллеров AD CS не нужен: его причина остаётся.
    assert set(_gaps(raw, None)) == {"ADCS_ESC", "DcHardening"}


def test_templates_without_ca_objects_still_need_ca_data() -> None:
    raw = build_export()
    raw["objects"] = [o for o in raw["objects"] if o["class"] != "pKIEnrollmentService"]
    assert set(_gaps(raw, None)) == {"ADCS_CA", "ADCS_MAPPING", "DcHardening"}


def test_ca_object_without_templates_still_needs_ca_data() -> None:
    raw = build_export()
    raw["objects"] = [o for o in raw["objects"] if o["class"] != "pKICertificateTemplate"]
    assert set(_gaps(raw, None)) == {"ADCS_ESC", "ADCS_CA", "ADCS_MAPPING", "DcHardening"}


def _ca_entry(**fields: Any) -> dict[str, Any]:
    return {**build_ca_data()["cas"][0], **fields}


@pytest.mark.parametrize("security", ["!!!", base64.b64encode(b"garbage").decode()])
def test_broken_ca_security_is_a_reason(security: str) -> None:
    ca = parse_ca_data(build_ca_data(cas=[_ca_entry(security=security), _ca_entry(name="CORP-CA2")]))
    assert _gaps(build_export(), ca) == {"ADCS_CA": "ЦС CORP-CA: дескриптор прав не разобран"}


def test_unread_dc_is_a_reason() -> None:
    dcs = [{"host": "dc01.corp.local", "registry_read": False, "cim_read": True, "error": "нет доступа к реестру"},
           {"host": "dc02.corp.local", "strong_binding": 2, "mapping_methods": 0x18, "registry_read": True, "cim_read": True}]
    gaps = _gaps(build_export(), parse_ca_data(build_ca_data(dcs=dcs)))
    assert gaps == {"ADCS_MAPPING": "контроллер dc01.corp.local: реестр не прочитан (нет доступа к реестру)",
                    "DcHardening": "контроллер dc01.corp.local: реестр не прочитан (нет доступа к реестру)"}


def test_unchecked_web_is_a_reason() -> None:
    web = [{"url": "http://ca01.corp.local/certsrv/", "error": "таймаут"}]
    gaps = _gaps(build_export(), parse_ca_data(build_ca_data(web=web)))
    assert gaps == {"ADCS_CA": "веб-выдача http://ca01.corp.local/certsrv/: не проверена (таймаут)"}


def test_records_with_data_and_error_are_checked() -> None:
    dcs = [{"host": "dc01.corp.local", "strong_binding": 0, "registry_read": False, "cim_read": True, "error": "CertificateMappingMethods не прочитан"}]
    web = [{"url": "http://ca01.corp.local/certsrv/", "status": 401, "auth": ["NTLM"], "error": "сертификат не проверен"}]
    ca = parse_ca_data(build_ca_data(dcs=dcs, web=web))
    idx = ExportIndex(load_export(json.dumps(build_export()).encode()), ca)
    assert [f.key_extra for f in check_adcs_mapping(idx, AdConfig())] == ["ESC10"]
    assert [f.key_extra for f in check_adcs_ca(idx, AdConfig())] == ["ESC8"]
    # Веб-выдача с ответом проверена; у контроллера непрочитанное значение — своя причина.
    assert _gaps(build_export(), ca) == {
        "ADCS_MAPPING": "контроллер dc01.corp.local: сопоставление по UPN (ESC10) не проверено (CertificateMappingMethods не прочитан)",
        "DcHardening": "контроллер dc01.corp.local: реестр не прочитан (CertificateMappingMethods не прочитан)",
    }


@pytest.mark.parametrize(
    ("missing", "reason"),
    [
        ("security", "ЦС CORP-CA: ESC7 не проверен — права ЦС не прочитаны (частично)"),
        ("edit_flags", "ЦС CORP-CA: ESC6, 16 не проверены — флаги политики не прочитаны (частично)"),
        ("interface_flags", "ЦС CORP-CA: ESC11 не проверен — флаги интерфейса не прочитаны (частично)"),
    ],
    ids=["security", "edit_flags", "interface_flags"],
)
def test_partly_read_ca_names_unchecked_esc(missing: str, reason: str) -> None:
    ca = parse_ca_data(build_ca_data(cas=[_ca_entry(**{missing: None}, error="частично")]))
    assert _gaps(build_export(), ca) == {"ADCS_CA": reason}


def test_ca_missing_several_fields_lists_each() -> None:
    ca = parse_ca_data(build_ca_data(cas=[_ca_entry(security=None, interface_flags=None, error="частично")]))
    reasons = _gaps(build_export(), ca)["ADCS_CA"].split("; ")
    assert [r.split(": ")[1].split(" —")[0] for r in reasons] == ["ESC7 не проверен", "ESC11 не проверен"]


def test_ca_field_missing_without_error_is_not_a_reason() -> None:
    ca = parse_ca_data(build_ca_data(cas=[_ca_entry(security=None)]))
    assert _gaps(build_export(), ca) == {}


@pytest.mark.parametrize(
    ("dc", "reason"),
    [
        ({"strong_binding": 2}, "контроллер dc01.corp.local: сопоставление по UPN (ESC10) не проверено (частично)"),
        ({"mapping_methods": 0x18}, "контроллер dc01.corp.local: привязка (ESC10) не проверена (частично)"),
    ],
    ids=["mapping_methods", "strong_binding"],
)
def test_partly_read_dc_names_unchecked_value(dc: dict[str, Any], reason: str) -> None:
    ca = parse_ca_data(build_ca_data(dcs=[{"host": "dc01.corp.local", **dc, "registry_read": False, "cim_read": True, "error": "частично"}]))
    assert _gaps(build_export(), ca) == {"ADCS_MAPPING": reason, "DcHardening": "контроллер dc01.corp.local: реестр не прочитан (частично)"}


DC_STATE_NEEDED = "нужно состояние контроллеров (сборщик, пункт 6)"


def test_without_dc_section_dc_hardening_needs_collector() -> None:
    assert _gaps(build_export(), None)["DcHardening"] == DC_STATE_NEEDED
    ca = parse_ca_data(build_ca_data(sections=["ca", "web"], dcs=[]))
    assert _gaps(build_export(), ca) == {"ADCS_MAPPING": "ESC10 не проверен: нужен реестр контроллеров (сборщик, пункт 6)",
                                         "DcHardening": DC_STATE_NEEDED}


def _dc(**fields: Any) -> dict[str, Any]:
    return {**build_ca_data()["dcs"][0], **fields}


def test_dc_with_unread_channels_names_each() -> None:
    dcs = [_dc(host="dc01.corp.local", registry_read=False, error="реестр: доступ запрещён"),
           _dc(host="dc02.corp.local", cim_read=False, error="CIM: WinRM и DCOM недоступны"), _dc(host="dc03.corp.local")]
    reasons = _gaps(build_export(), parse_ca_data(build_ca_data(dcs=dcs)))["DcHardening"].split("; ")
    assert reasons == ["контроллер dc01.corp.local: реестр не прочитан (реестр: доступ запрещён)",
                       "контроллер dc02.corp.local: службы и SMB не прочитаны (CIM: WinRM и DCOM недоступны)"]


def test_dc_reasons_show_only_their_channel_error() -> None:
    dcs = [_dc(registry_read=False, cim_read=False, error="реестр: Access is denied.; CIM: WSMan: отказ; DCOM: отказ")]
    reasons = _gaps(build_export(), parse_ca_data(build_ca_data(dcs=dcs)))["DcHardening"].split("; контроллер ")
    assert reasons == ["контроллер dc01.corp.local: реестр не прочитан (реестр: Access is denied.)",
                       "dc01.corp.local: службы и SMB не прочитаны (CIM: WSMan: отказ; DCOM: отказ)"]


def test_unread_dc_record_of_collector_2_2_keeps_esc10_reason() -> None:
    """Литеральная запись сборщика 2.2: флагов нет, привязка не прочитана — прежняя причина ESC10."""
    dcs = [{"host": "dc01.corp.local", "strong_binding": None, "mapping_methods": None, "error": "The network path was not found."}]
    gaps = _gaps(build_export(), parse_ca_data(build_ca_data(dcs=dcs)))
    assert gaps["ADCS_MAPPING"] == "контроллер dc01.corp.local: реестр не прочитан (The network path was not found.)"
    assert gaps["DcHardening"] == ("контроллер dc01.corp.local: реестр не прочитан (The network path was not found.); "
                                   "контроллер dc01.corp.local: службы и SMB не прочитаны (The network path was not found.)")


def test_dc_record_of_old_collector_is_unread_for_dc_hardening() -> None:
    """Запись сборщика до 2.3: флагов нет — оба канала не прочитаны; ESC10 проверен по привязке."""
    dcs = [{"host": "dc01.corp.local", "strong_binding": 2, "mapping_methods": 0x18}]
    gaps = _gaps(build_export(), parse_ca_data(build_ca_data(dcs=dcs)))
    assert gaps == {"DcHardening": "контроллер dc01.corp.local: реестр не прочитан; контроллер dc01.corp.local: службы и SMB не прочитаны"}


def test_cim_error_of_read_registry_is_not_an_esc10_reason() -> None:
    """Реестр прочитан, значений привязки в нём нет (действуют значения по умолчанию), а CIM отказал: ESC10 проверен."""
    dcs = [_dc(strong_binding=None, mapping_methods=None, cim_read=False, error="CIM: WinRM недоступен")]
    gaps = _gaps(build_export(), parse_ca_data(build_ca_data(dcs=dcs)))
    assert gaps == {"DcHardening": "контроллер dc01.corp.local: службы и SMB не прочитаны (CIM: WinRM недоступен)"}


def _upload(client: TestClient, raw: dict[str, Any]) -> dict[str, Any]:
    r = client.post("/api/ad/snapshots/file", files={"file": ("ad.json", json.dumps(raw).encode(), "application/json")})
    assert r.status_code == 202, r.text
    return client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()


def test_overview_reports_unchecked_and_reanalysis_keeps_it(auth_client: TestClient) -> None:
    raw = build_export()
    raw["sysvol"] = {}
    assert _upload(auth_client, raw)["status"] == "done"
    domain_id = auth_client.get("/api/ad/domains").json()[0]["id"]

    def unchecked() -> dict[str, Any]:
        checks = auth_client.get(f"/api/ad/domains/{domain_id}/overview").json()["checks"]
        return {c["code"]: c["unchecked"] for c in checks}

    first = unchecked()
    assert "SYSVOL" in first["UserRightsAssignment"] and first["DCSync"] is None
    snapshot_id = auth_client.get(f"/api/ad/snapshots?domain_id={domain_id}").json()[0]["id"]
    job = auth_client.post(f"/api/ad/snapshots/{snapshot_id}/reanalyze").json()
    assert auth_client.get(f"/api/ad/jobs/{job['job_id']}").json()["status"] == "done"
    assert unchecked() == first


def test_overview_marks_adcs_ca_unchecked_until_ca_data_upload(auth_client: TestClient) -> None:
    assert _upload(auth_client, build_export())["status"] == "done"
    domain_id = auth_client.get("/api/ad/domains").json()[0]["id"]

    def unchecked(code: str) -> Any:
        checks = auth_client.get(f"/api/ad/domains/{domain_id}/overview").json()["checks"]
        return next(c["unchecked"] for c in checks if c["code"] == code)

    assert "пункт 5" in unchecked("ADCS_CA") and "пункт 6" in unchecked("ADCS_MAPPING")
    assert _upload(auth_client, build_ca_data())["status"] == "done"
    assert unchecked("ADCS_CA") is None and unchecked("ADCS_MAPPING") is None


def test_snapshot_of_previous_analyzer_marks_empty_checks_unchecked(auth_client: TestClient, db_session: Any) -> None:
    """Проверки, данные для которых появились в новой версии анализатора, у старого
    снапшота тихо пусты: пустая проверка такого снапшота — не «без находок»."""
    raw = build_export()
    raw["sysvol"] = {}
    assert _upload(auth_client, raw)["status"] == "done"
    assert _upload(auth_client, build_ca_data())["status"] == "done"
    domain_id = auth_client.get("/api/ad/domains").json()[0]["id"]
    fresh = auth_client.get(f"/api/ad/domains/{domain_id}/overview").json()
    assert fresh["snapshot"]["analyzer_version"] == ANALYZER_VERSION and fresh["snapshot"]["stale_analysis"] is False
    snap = db_session.get(AdSnapshot, fresh["snapshot"]["id"])
    snap.analyzer_version = "1"
    db_session.commit()

    overview = auth_client.get(f"/api/ad/domains/{domain_id}/overview").json()
    assert overview["snapshot"]["analyzer_version"] == "1" and overview["snapshot"]["stale_analysis"] is True
    before = {c["code"]: c for c in fresh["checks"]}
    stale = "снапшот посчитан прежней версией анализатора (1) — пересчитайте"
    for c in overview["checks"]:
        if before[c["code"]]["unchecked"]:
            assert c["unchecked"] == before[c["code"]]["unchecked"], c["code"]
        elif c["total"] == 0:
            assert c["unchecked"] == stale, c["code"]
        else:
            assert c["unchecked"] is None, c["code"]
    # Все три случая на месте: сохранённая причина (SYSVOL), пустые (ЦС, привязка) и непустые проверки.
    after = {c["code"]: c for c in overview["checks"]}
    assert "SYSVOL" in after["UserRightsAssignment"]["unchecked"] and after["DCSync"]["total"]
    assert after["ADCS_CA"]["unchecked"] == stale and after["ADCS_MAPPING"]["unchecked"] == stale


def test_dc_descriptors_without_owner_mark_dc_owner_unchecked() -> None:
    import base64

    from api.modules.ad.core import sd
    from tests.ad.mini import dc, mini_export

    blob = base64.b64encode(sd.build_sd([sd.build_ace("S-1-5-18", sd.GENERIC_ALL)], owner=None)).decode()
    gaps = coverage_gaps(mini_export([dc("DC01", 1001, sd=blob)]))
    assert gaps["DcOwner"] == "дескрипторы собраны без владельца (сборщик старой версии)"
    with_owner = base64.b64encode(sd.build_sd([sd.build_ace("S-1-5-18", sd.GENERIC_ALL)])).decode()
    assert "DcOwner" not in coverage_gaps(mini_export([dc("DC01", 1001, sd=with_owner)]))
