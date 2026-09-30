"""ADCS_CA по снапшоту: ESC5 — запись в контейнеры PKI и объект ЦС."""
from __future__ import annotations

import base64
import datetime as dt
import json
from typing import Any

from fastapi.testclient import TestClient

from api.modules.ad.core import sd
from api.modules.ad.core.ca_data import parse_ca_data
from api.modules.ad.core.checks.adcs_ca import check_adcs_ca
from api.modules.ad.core.checks.adcs_rules import requester_kind
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex, load_export
from api.modules.ad.core.findings import Finding
from tests.ad.synthetic import DN, NOW, OTHER_SID, PKI, b64sd, build_ca_data, build_export, rid

NTAUTH = f"CN=NTAuthCertificates,{PKI}"
CA_DN = f"CN=CORP-CA,CN=Enrollment Services,{PKI}"


def run(dn: str, aces: list[bytes], *, owner: str | None = None, extra: list[dict[str, Any]] | None = None) -> list[Finding]:
    raw: dict[str, Any] = build_export()
    raw["objects"].extend(extra or [])
    obj = next(o for o in raw["objects"] if o["dn"] == dn)
    all_aces = [*aces, sd.build_ace(rid(512), sd.GENERIC_ALL)]
    obj["sd"] = b64sd(all_aces) if owner is None else base64.b64encode(sd.build_sd(all_aces, owner=owner)).decode()
    return check_adcs_ca(ExportIndex(load_export(json.dumps(raw).encode())), AdConfig())


def upload(client: TestClient, raw: dict[str, Any], name: str) -> dict[str, Any]:
    r = client.post("/api/ad/snapshots/file", files={"file": (name, json.dumps(raw).encode(), "application/octet-stream")})
    assert r.status_code == 202, r.text
    return client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()


def computer(sam: str, n: int) -> dict[str, Any]:
    return {"dn": f"CN={sam.rstrip('$')},CN=Computers,{DN}", "class": "computer", "sid": rid(n), "sam": sam, "name": sam.rstrip("$"), "uac": 4096}


def test_synthetic_pki_is_clean() -> None:
    assert check_adcs_ca(ExportIndex(load_export(json.dumps(build_export()).encode())), AdConfig()) == []


def test_esc5_other_writer_on_ntauth() -> None:
    fs = run(NTAUTH, [sd.build_ace(rid(1108), sd.WRITE_PROPERTY)])
    assert len(fs) == 1
    f = fs[0]
    assert (f.check, f.key_extra, f.target, f.severity, f.identity) == ("ADCS_CA", "ESC5", NTAUTH, "Medium", "")
    assert f.details["esc"] == "ESC5" and f.details["principals_broad"] is False and "requesters" not in f.details
    assert f.details["principals"] == [{"name": "CORP\\helpdesk", "sid": rid(1108), "kind": "other", "rights": ["WriteProperty"]}]


def test_esc5_broad_writer_on_ca_object_is_high() -> None:
    fs = run(CA_DN, [sd.build_ace("S-1-5-11", sd.GENERIC_ALL)])
    assert [(f.target, f.severity) for f in fs] == [(CA_DN, "High")]


def test_esc5_not_for_admins() -> None:
    assert run(NTAUTH, [sd.build_ace(rid(519), sd.WRITE_DACL), sd.build_ace("S-1-5-18", sd.GENERIC_ALL)]) == []


def test_esc5_not_for_cert_publishers() -> None:
    """Cert Publishers (RID 517) — группа самих серверов ЦС; AD по умолчанию даёт ей запись в контейнеры PKI."""
    assert run(PKI, [sd.build_ace(rid(517), sd.GENERIC_ALL)]) == []
    assert run(NTAUTH, [sd.build_ace(rid(517), sd.WRITE_PROPERTY)]) == []


def test_cert_publishers_of_any_domain_are_safe() -> None:
    idx = ExportIndex(load_export(json.dumps(build_export()).encode()))
    assert requester_kind(idx, AdConfig(), f"{OTHER_SID}-517") == "safe"


def test_esc5_ignores_read_and_inherit_only() -> None:
    aces = [sd.build_ace("S-1-5-11", sd.READ_PROPERTY), sd.build_ace(rid(1108), sd.GENERIC_ALL, flags=sd.ACE_FLAG_INHERIT_ONLY)]
    assert run(PKI, aces) == []


def test_esc5_owner_is_writer() -> None:
    """Владелец неявно имеет WriteDacl."""
    fs = run(NTAUTH, [], owner=rid(1108))
    assert [(f.target, f.severity) for f in fs] == [(NTAUTH, "Medium")]
    assert fs[0].details["principals"] == [{"name": "CORP\\helpdesk", "sid": rid(1108), "kind": "other", "rights": ["owner"]}]


def test_esc5_owner_and_ace_rights_are_merged() -> None:
    fs = run(NTAUTH, [sd.build_ace(rid(1108), sd.WRITE_DACL)], owner=rid(1108))
    assert fs[0].details["principals"][0]["rights"] == ["WriteDacl", "owner"]


def test_esc5_create_child_on_container() -> None:
    """Создание дочерних объектов в контейнере PKI — подложный корневой ЦС, ЦС предприятия или шаблон."""
    fs = run(PKI, [sd.build_ace("S-1-5-11", sd.CREATE_CHILD)])
    assert [(f.target, f.severity) for f in fs] == [(PKI, "High")]
    assert fs[0].details["principals"][0]["rights"] == ["CreateChild"]


def test_esc5_create_child_not_on_ca_object() -> None:
    assert run(CA_DN, [sd.build_ace("S-1-5-11", sd.CREATE_CHILD)]) == []


def test_ca_server_account_is_safe_on_its_ca_object() -> None:
    assert run(CA_DN, [sd.build_ace(rid(1401), sd.GENERIC_ALL)], extra=[computer("CA01$", 1401)]) == []


def test_other_computer_on_ca_object_is_esc5() -> None:
    fs = run(CA_DN, [sd.build_ace(rid(1402), sd.GENERIC_ALL)], extra=[computer("CA01$", 1401), computer("CA02$", 1402)])
    assert [(f.target, f.severity) for f in fs] == [(CA_DN, "Medium")]


def test_ca_server_account_is_not_safe_on_containers() -> None:
    assert len(run(NTAUTH, [sd.build_ace(rid(1401), sd.GENERIC_ALL)], extra=[computer("CA01$", 1401)])) == 1


# ---- По данным ЦС: ESC6, 7, 8, 11, 16 ------------------------------------------

MANAGE_CA, MANAGE_CERTS = 0x1, 0x2


def run_ca(**overrides: Any) -> list[Finding]:
    ca = parse_ca_data(build_ca_data(**overrides))
    return check_adcs_ca(ExportIndex(load_export(json.dumps(build_export()).encode()), ca), AdConfig())


def ca_entry(**fields: Any) -> list[dict[str, Any]]:
    entry = dict(build_ca_data()["cas"][0])
    entry.update(fields)
    return [entry]


def codes(fs: list[Finding]) -> list[str]:
    return sorted(f.key_extra for f in fs)


def test_safe_ca_data_gives_no_findings() -> None:
    assert run_ca() == []


def test_esc6_san_flag() -> None:
    fs = run_ca(cas=ca_entry(edit_flags=0x11014E | 0x40000))
    assert [(f.check, f.key_extra, f.target, f.severity) for f in fs] == [("ADCS_CA", "ESC6", "CORP-CA", "High")]
    assert "мая 2022" in fs[0].details["details"] and fs[0].details["esc"] == "ESC6"


def test_esc6_not_without_flag() -> None:
    assert codes(run_ca(cas=ca_entry(edit_flags=0x11014E))) == []


def test_ca_findings_carry_section_date_and_source() -> None:
    ca = parse_ca_data(build_ca_data(cas=ca_entry(edit_flags=0x40000)))
    ca.section_dates = {"ca": NOW - dt.timedelta(days=3)}
    ca.section_sources = {"ca": 42}
    fs = check_adcs_ca(ExportIndex(load_export(json.dumps(build_export()).encode()), ca), AdConfig())
    assert fs[0].details["ca_data_collected_at"] == (NOW - dt.timedelta(days=3)).isoformat()
    assert fs[0].details["ca_data_id"] == 42


def test_ca_findings_fall_back_to_file_date() -> None:
    fs = run_ca(cas=ca_entry(edit_flags=0x40000))
    assert fs[0].details["ca_data_collected_at"] == NOW.isoformat() and "ca_data_id" not in fs[0].details


def ca_security(*aces: bytes) -> str:
    return b64sd([*aces, sd.build_ace(rid(512), MANAGE_CA | MANAGE_CERTS)])


def test_esc7_other_with_manage_certificates_is_medium() -> None:
    fs = run_ca(cas=ca_entry(security=ca_security(sd.build_ace(rid(1108), MANAGE_CERTS))))
    assert [(f.key_extra, f.target, f.severity) for f in fs] == [("ESC7", "CORP-CA", "Medium")]
    assert fs[0].details["rights"] == ["ManageCertificates"]
    assert fs[0].details["principals"][0]["name"] == "CORP\\helpdesk"


def test_esc7_broad_with_manage_ca_is_high() -> None:
    fs = run_ca(cas=ca_entry(security=ca_security(sd.build_ace("S-1-5-11", MANAGE_CA))))
    assert [(f.key_extra, f.severity) for f in fs] == [("ESC7", "High")]
    assert fs[0].details["rights"] == ["ManageCA"] and fs[0].details["principals_broad"] is True


def test_esc7_rights_listed_by_fact() -> None:
    fs = run_ca(cas=ca_entry(security=ca_security(sd.build_ace(rid(1108), MANAGE_CERTS), sd.build_ace("S-1-5-11", MANAGE_CA))))
    assert fs[0].details["rights"] == ["ManageCA", "ManageCertificates"]


def test_esc7_not_for_admins_or_enroll_only() -> None:
    enroll_right = 0x200  # «Запрос сертификатов» на ЦС — не управление
    assert run_ca(cas=ca_entry(security=ca_security(sd.build_ace(rid(519), MANAGE_CA), sd.build_ace("S-1-5-11", enroll_right)))) == []


def test_esc7_deny_and_inherit_only() -> None:
    aces = [
        sd.build_ace(rid(1108), MANAGE_CA, allow=False),
        sd.build_ace(rid(1108), MANAGE_CA),
        sd.build_ace("S-1-5-11", MANAGE_CA, flags=sd.ACE_FLAG_INHERIT_ONLY),
    ]
    assert run_ca(cas=ca_entry(security=ca_security(*aces))) == []


def test_esc8_http_ntlm_is_high() -> None:
    fs = run_ca(web=[{"url": "http://ca01.corp.local/certsrv/", "status": 401, "auth": ["NTLM", "Negotiate"], "error": ""}])
    assert [(f.key_extra, f.target, f.severity) for f in fs] == [("ESC8", "http://ca01.corp.local/certsrv/", "High")]


def test_esc8_https_negotiate_is_medium_with_epa_note() -> None:
    fs = run_ca(web=[{"url": "https://ca01.corp.local/certsrv/", "status": 401, "auth": ["negotiate"], "error": ""}])
    assert [(f.key_extra, f.severity) for f in fs] == [("ESC8", "Medium")]
    assert "расширенная защита (EPA)" in fs[0].details["details"]


def test_esc8_one_finding_per_endpoint() -> None:
    web = [
        {"url": "http://ca01.corp.local/certsrv/", "status": 401, "auth": ["NTLM"], "error": ""},
        {"url": "https://ca01.corp.local/CES/service.svc", "status": 401, "auth": ["Negotiate"], "error": ""},
    ]
    fs = run_ca(web=web)
    assert sorted(f.target for f in fs) == sorted(w["url"] for w in web) and len({f.key for f in fs}) == 2


def test_esc8_not_for_404_or_basic() -> None:
    assert run_ca(web=[{"url": "http://ca01.corp.local/certsrv/", "status": 404, "auth": ["NTLM"], "error": ""}]) == []
    assert run_ca(web=[{"url": "http://ca01.corp.local/certsrv/", "status": 401, "auth": ["Basic"], "error": ""}]) == []


def test_esc11_rpc_without_encryption() -> None:
    fs = run_ca(cas=ca_entry(interface_flags=0x641 & ~0x200))
    assert [(f.key_extra, f.target, f.severity) for f in fs] == [("ESC11", "CORP-CA", "High")]


def test_esc11_not_when_encryption_enforced_or_unknown() -> None:
    assert run_ca(cas=ca_entry(interface_flags=0x641)) == []
    assert run_ca(cas=ca_entry(interface_flags=None)) == []


def test_esc16_security_extension_disabled() -> None:
    fs = run_ca(cas=ca_entry(disable_extension_list=["1.3.6.1.4.1.311.25.2"]))
    assert [(f.key_extra, f.target, f.severity) for f in fs] == [("ESC16", "CORP-CA", "High")]


def test_esc16_not_for_other_extensions() -> None:
    assert run_ca(cas=ca_entry(disable_extension_list=["1.3.6.1.4.1.311.21.7"])) == []


def test_unread_ca_gives_no_findings() -> None:
    assert run_ca(cas=[{"name": "CORP-CA", "host": "ca01.corp.local", "error": "доступ запрещён"}]) == []


def test_ca_data_findings_upload_via_api(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export(), "ad.json")["status"] == "done"
    assert upload(auth_client, build_ca_data(cas=ca_entry(edit_flags=0x11014E | 0x40000)), "adca.json")["status"] == "done"
    domain_id = auth_client.get("/api/ad/domains").json()[0]["id"]
    snap_id = auth_client.get(f"/api/ad/snapshots?domain_id={domain_id}").json()[0]["id"]
    items = auth_client.get(f"/api/ad/snapshots/{snap_id}/findings?check=ADCS_CA").json()["items"]
    esc6 = [i for i in items if i["details"]["esc"] == "ESC6"]
    assert len(esc6) == 1 and esc6[0]["target"] == "CORP-CA" and esc6[0]["details"]["ca_data_id"]
