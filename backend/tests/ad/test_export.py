from __future__ import annotations

import gzip
import json

import pytest

from api.modules.ad.core.export import (
    AdObject,
    ExportFormatError,
    ExportIndex,
    GppItem,
    load_export,
)
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


def test_gzip_bomb_rejected_with_limit_in_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """Аудит H2: gzip распаковывается со счётчиком, а не целиком в память."""
    from api.modules.ad.core import export

    monkeypatch.setattr(export, "MAX_UNPACKED", 1024 * 1024)
    bomb = gzip.compress(b" " * (10 * 1024 * 1024))
    with pytest.raises(ExportFormatError, match="распакованный размер больше лимита"):
        load_export(bomb)
    # Под лимитом та же выгрузка в gzip разбирается как раньше.
    assert load_export(gzip.compress(export_bytes())).format == "stools-ad/1"


def test_deeply_nested_json_is_a_format_error() -> None:
    """Аудит L9: вложенность без предела — ошибка формата, а не RecursionError."""
    deep = b'{"format": "stools-ad/1", "x": ' + b"[" * 200_000 + b"]" * 200_000 + b"}"
    with pytest.raises(ExportFormatError, match="JSON"):
        load_export(deep)


def test_new_optional_fields_are_read_and_old_export_still_loads():
    raw = build_export()
    exp = load_export(json.dumps(raw).encode())
    assert exp.domain.min_pwd_length == 12 and exp.domain.recycle_bin is True
    assert exp.guids.schema_classes == {"msDS-DelegatedManagedServiceAccount": ""}
    zone = next(o for o in exp.objects if o.cls == "dnsZone")
    assert zone.allowUpdate == 2 and zone.name == "corp.local"
    for key in ("forest_functional_level", "min_pwd_length", "lockout_threshold", "pwd_properties", "recycle_bin", "ds_heuristics",
                "smartcard_rotation", "laps_legacy_schema", "laps_schema", "last_backup", "backup_read", "sysvol_replication", "schema_poss_superiors"):
        raw["domain"].pop(key)
    raw["guids"].pop("schema_classes")
    old = load_export(json.dumps(raw).encode())
    assert old.domain.min_pwd_length is None and old.domain.recycle_bin is None and old.guids.schema_classes == {}


def test_old_gpp_item_fields_none():
    """Выгрузки сборщиков до LDAP 1.4 / PowerShell 2.5: признаков GPP и UPN нет — None, «не собрано»."""
    item = GppItem.model_validate({"scope": "machine", "file": "Groups.xml", "kind": "Group"})
    assert item.filtered is None and item.delete_all is None
    obj = AdObject.model_validate({"dn": user_dn("helpdesk"), "class": "user"})
    assert obj.userPrincipalName is None and obj.displayName is None
    new = AdObject.model_validate({"dn": user_dn("helpdesk"), "class": "user", "userPrincipalName": "helpdesk@corp.local"})
    assert new.userPrincipalName == "helpdesk@corp.local"


def test_naive_timestamps_are_utc():
    raw = build_export()
    raw["objects"][1]["whenCreated"] = "2025-01-02T03:04:05"
    assert load_export(json.dumps(raw).encode()).objects[1].whenCreated.tzinfo is not None
