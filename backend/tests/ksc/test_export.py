from __future__ import annotations

import datetime as dt
import gzip
import json

import pytest

from api.modules.ksc.core.export import (
    ExportFormatError,
    ExportIndex,
    ip_from_long,
    load_export,
    unwrap,
)
from tests.ksc.synthetic import NOW, build_export, export_bytes


def test_unwrap_typed_values() -> None:
    assert unwrap({"type": "datetime", "value": "2026-09-15T12:00:00Z"}) == dt.datetime(2026, 9, 15, 12, tzinfo=dt.UTC)
    assert unwrap({"type": "long", "value": 13}) == 13
    assert unwrap({"type": "binary", "value": "AAAA"}) == "AAAA"
    assert unwrap({"a": {"type": "long", "value": 1}, "b": [{"type": "date", "value": "2026-09-15"}]}) == {"a": 1, "b": ["2026-09-15"]}
    assert unwrap("x") == "x" and unwrap(None) is None


def test_ip_from_long_handles_signed_values() -> None:
    assert ip_from_long(3232235777) == "192.168.1.1"
    assert ip_from_long(-1062731519) == "192.168.1.1"  # тот же адрес знаковым int32
    assert ip_from_long(0) == ""


def test_load_export_plain_and_gzip() -> None:
    raw = export_bytes()
    for data in (raw, gzip.compress(raw)):
        export = load_export(data)
        assert export.format == "stools-ksc/1" and export.server.name == "ksc01"
        assert export.server.collected_at == NOW and len(export.hosts) == 14


def test_load_export_rejects_foreign_or_broken() -> None:
    with pytest.raises(ExportFormatError, match="не выгрузка"):
        load_export(json.dumps({"format": "stools-ad/1"}).encode())
    with pytest.raises(ExportFormatError, match="JSON"):
        load_export(b"\x1f\x8bnot gzip")
    raw = build_export()
    del raw["server"]
    with pytest.raises(ExportFormatError, match="неполная"):
        load_export(json.dumps(raw).encode())


def test_load_export_without_new_sections_has_empty_defaults() -> None:
    """Файл без секций блока 1 разбирается как раньше и не даёт новых находок."""
    raw = build_export()
    for key in ("role_assignments", "internal_users", "security", "server_certs", "secondary_servers", "update_agents", "policy_contents"):
        raw.pop(key, None)
    export = load_export(json.dumps(raw).encode())
    assert export.role_assignments == [] and export.internal_users == [] and export.security == {}
    assert export.server_certs == {} and export.secondary_servers == [] and export.update_agents == []
    assert export.policy_contents == {}


def test_index_parses_hosts() -> None:
    idx = ExportIndex(load_export(export_bytes()))
    by = {h.name: h for h in idx.hosts}
    assert by["WS01"].agent_installed and by["WS01"].agent_alive and by["WS01"].protection_installed
    assert by["WS01"].fqdn == "ws01.corp.local" and by["WS01"].domain == "corp.local" and by["WS01"].ip == "192.168.1.2"
    assert by["WS01"].group_path == "Managed devices/Workstations" and by["WS01"].product == "KES" and by["WS01"].product_version == "12.0.0.0"
    assert by["WS06"].agent_installed is False and by["WS08"].unassigned
    assert by["WS11"].components == [(c, 4 if c != "Firewall" else 1) for c in ["File Threat Protection", "Behavior Detection", "Exploit Prevention", "Firewall", "Network Threat Protection", "Web Control", "Device Control"]]
    assert by["WS03"].bases_at == NOW - dt.timedelta(days=1) * 10
    assert by["WG01"].domain == "" and by["WG01"].windomain == "WORKGROUP"
    assert idx.now == NOW


def test_live_params_wrappers_are_stripped() -> None:
    """Живой KSC заворачивает каждую запись в {"type": "params", "value": {…}} — разбор даёт те же хосты."""
    from tests.ksc.fake_ksc import _wrap_nested

    raw = build_export()
    for section in ("groups", "hosts", "policies", "licenses", "domains"):
        raw[section] = [_wrap_nested(item) for item in raw[section]]
    raw["effective_policies"] = {k: [_wrap_nested(p) for p in v] for k, v in raw["effective_policies"].items()}
    raw["host_products"] = {k: {prod: _wrap_nested(v) for prod, v in p.items()} for k, p in raw["host_products"].items()}
    raw["host_components"] = {k: {pk: [_wrap_nested(c) for c in items] for pk, items in comp.items()} for k, comp in raw["host_components"].items()}
    for t in raw["tasks"]:
        t["TASK_INFO_PARAMS"] = _wrap_nested(t["TASK_INFO_PARAMS"])
    wrapped = ExportIndex(load_export(json.dumps(raw).encode()))
    plain = ExportIndex(load_export(export_bytes()))
    assert [(h.name, h.fqdn, h.group_path, h.agent_alive, h.protection, h.product, h.components) for h in wrapped.hosts] == [
        (h.name, h.fqdn, h.group_path, h.agent_alive, h.protection, h.product, h.components) for h in plain.hosts
    ]
    from api.modules.ksc.core.checks import run_all
    from api.modules.ksc.core.config import KscConfig

    assert sorted(f.key for f in run_all(wrapped, KscConfig())) == sorted(f.key for f in run_all(plain, KscConfig()))
