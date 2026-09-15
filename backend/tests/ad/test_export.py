from __future__ import annotations

import gzip
import json

import pytest

from api.modules.ad.core.export import ExportFormatError, ExportIndex, load_export
from tests.ad.synthetic import DOMAIN_SID, build_export, export_bytes, rid, user_dn


def test_load_plain_and_gzip() -> None:
    e1 = load_export(export_bytes())
    e2 = load_export(gzip.compress(export_bytes()))
    assert e1.domain.sid == e2.domain.sid == DOMAIN_SID
    assert len(e1.objects) == len(build_export()["objects"])


def test_bad_format_rejected() -> None:
    with pytest.raises(ExportFormatError, match="не выгрузка"):
        load_export(b'{"format": "something/9"}')
    with pytest.raises(ExportFormatError, match="JSON"):
        load_export(b"not json")


def test_list_fields_accept_powershell_unrolling() -> None:
    # ConvertTo-Json в PowerShell отдаёт пустой список как null, а список из
    # одного элемента как скаляр — модель обязана принять оба варианта.
    raw = build_export()
    raw["objects"][0]["member"] = None
    raw["objects"][0]["spn"] = "HTTP/one"
    raw["objects"][0]["allowedToDelegateTo"] = None
    raw["objects"][1]["member"] = {}  # Windows PowerShell 5.1: пустой массив → {}
    gpo_dn, files = next(iter(raw["sysvol"].items()))
    inf = files["GptTmpl.inf"]
    # Windows PowerShell 5.1: строка из Get-Content -Raw уходит объектом с полем value.
    raw["sysvol"][gpo_dn]["GptTmpl.inf"] = {"value": inf, "PSPath": "x", "ReadCount": 1}
    exp = load_export(json.dumps(raw).encode())
    assert exp.objects[0].member == [] and exp.objects[0].spn == ["HTTP/one"]
    assert exp.objects[0].allowedToDelegateTo == [] and exp.objects[1].member == []
    assert exp.sysvol[gpo_dn]["GptTmpl.inf"] == inf


def test_validation_error_names_fields() -> None:
    raw = build_export()
    raw["objects"][0]["uac"] = "not-an-int"
    with pytest.raises(ExportFormatError, match=r"objects\.0\.uac.*\(str\): 'not-an-int'"):
        load_export(json.dumps(raw).encode())


def test_index_groups_and_names() -> None:
    idx = ExportIndex(load_export(export_bytes()))
    da = idx.group_by_rid(512)
    assert da is not None and da.sam == "Domain Admins"
    members = sorted(m.label for m in idx.members_recursive(da))
    # admin2 — через вложенную Tier0; цикл Tier0 ↔ Domain Admins не зацикливает.
    assert members == ["WS01$", "admin1", "admin2"]
    assert idx.principal_name(rid(1108)) == "CORP\\helpdesk"
    assert idx.principal_name("S-1-5-11") == "NT AUTHORITY\\Authenticated Users"
    assert idx.principal_name(rid(9999)) == rid(9999)
    assert idx.get(user_dn("admin1")).enabled and not idx.get(user_dn("user.disabled")).enabled
    assert idx.get(user_dn("delegate.user")).unconstrained_delegation
    root = idx.root
    assert root is not None and idx.sd_of(root) is not None and len(idx.sd_of(root).dacl) == 6
    assert idx.extended_right("Enroll") == "0e10c968-78fb-11d2-90d4-00c04f79dc55"
