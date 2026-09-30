"""ADCS_CA по снапшоту: ESC5 — запись в контейнеры PKI и объект ЦС."""
from __future__ import annotations

import base64
import json
from typing import Any

from api.modules.ad.core import sd
from api.modules.ad.core.checks.adcs_ca import check_adcs_ca
from api.modules.ad.core.checks.adcs_rules import requester_kind
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex, load_export
from api.modules.ad.core.findings import Finding
from tests.ad.synthetic import DN, OTHER_SID, PKI, b64sd, build_export, rid

NTAUTH = f"CN=NTAuthCertificates,{PKI}"
CA_DN = f"CN=CORP-CA,CN=Enrollment Services,{PKI}"


def run(dn: str, aces: list[bytes], *, owner: str | None = None, extra: list[dict[str, Any]] | None = None) -> list[Finding]:
    raw: dict[str, Any] = build_export()
    raw["objects"].extend(extra or [])
    obj = next(o for o in raw["objects"] if o["dn"] == dn)
    all_aces = [*aces, sd.build_ace(rid(512), sd.GENERIC_ALL)]
    obj["sd"] = b64sd(all_aces) if owner is None else base64.b64encode(sd.build_sd(all_aces, owner=owner)).decode()
    return check_adcs_ca(ExportIndex(load_export(json.dumps(raw).encode())), AdConfig())


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
