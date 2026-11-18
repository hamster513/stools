from __future__ import annotations

import datetime as dt
import gzip
import json
from pathlib import Path

import pytest

from api.modules.ksc.core.export import (
    ExportFormatError,
    ExportIndex,
    HostUser,
    ip_from_long,
    load_export,
    load_export_path,
    unwrap,
)
from tests.ksc.synthetic import (
    LAB_SID,
    NOTEBOOKS_EXPRESSION,
    NOW,
    PRODUCT_STATUS_TEXT,
    SECRET_VALUES,
    build_export,
    expected_policy_contents,
    export_bytes,
    user_bin_id,
    without_new_sections,
)


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


def test_host_status_reasons_from_mask_and_product_text() -> None:
    by = {h.name: h for h in ExportIndex(load_export(export_bytes())).hosts}
    # Биты маски — по порядку номеров; текст управляемого продукта (бит 18) — последним пунктом, как есть.
    assert by["WS04"].status == "warning" and by["WS04"].status_reasons == ["полный поиск давно не выполнялся", "требуется перезагрузка"]
    assert by["WS09"].status_text == PRODUCT_STATUS_TEXT
    assert by["WS09"].status_reasons == ["слишком много невылеченных объектов", "статус задан управляемым продуктом", PRODUCT_STATUS_TEXT]
    # Статус «ок» с пустой маской — причин нет; маска и текст уходят в `extra` строки хоста.
    assert by["WS01"].status_reasons == [] and by["WS01"].extra["status_mask"] == 0 and by["WS01"].extra["status_text"] == ""
    assert by["WS04"].extra["status_mask"] == (1 << 6) | (1 << 11) and by["WS09"].extra["status_text"] == PRODUCT_STATUS_TEXT
    # Бит без расшифровки — «код N»; статус не «ок» без битов и текста — «причина не расшифрована»; не строка в HSDP — пусто.
    raw = build_export()
    hosts = {h["KLHST_WKS_DN"]: h for h in raw["hosts"]}
    hosts["WS01"].update(KLHST_WKS_STATUS_ID=1, KLHST_WKS_STATUS_MASK=(1 << 7) | (1 << 11) | (1 << 25))
    hosts["WS02"].update(KLHST_WKS_STATUS_ID=2, KLHST_WKS_STATUS_HSDP={"type": "params", "value": {}})
    by = {h.name: h for h in ExportIndex(load_export(json.dumps(raw).encode())).hosts}
    assert by["WS01"].status_reasons == ["базы давно не обновлялись", "требуется перезагрузка", "код 25"]
    assert by["WS02"].status_text == "" and by["WS02"].status_reasons == ["причина не расшифрована"]


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


def test_gzip_bomb_rejected_with_limit_in_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """Аудит H2: gzip распаковывается со счётчиком, а не целиком в память."""
    from api.modules.ksc.core import export

    monkeypatch.setattr(export, "MAX_UNPACKED", 1024 * 1024)
    bomb = gzip.compress(b" " * (10 * 1024 * 1024))
    with pytest.raises(ExportFormatError, match="распакованный размер больше лимита"):
        load_export(bomb)
    # Под лимитом та же выгрузка в gzip разбирается как раньше.
    assert load_export(gzip.compress(export_bytes())).format == "stools-ksc/1"


def corrupted_gzip() -> bytes:
    """Выгрузка в gzip с испорченным потоком deflate: распаковка падает `zlib.error`, а не `OSError`."""
    data = bytearray(gzip.compress(export_bytes()))
    data[20:40] = b"\xff" * 20
    return bytes(data)


def test_corrupted_gzip_is_a_format_error(tmp_path: Path) -> None:
    path = tmp_path / "1.json.gz"
    path.write_bytes(corrupted_gzip())
    with pytest.raises(ExportFormatError, match="битый gzip"):
        load_export_path(path)
    with pytest.raises(ExportFormatError, match="битый gzip"):
        load_export(corrupted_gzip())


def test_deeply_nested_json_is_a_format_error() -> None:
    """Аудит L9: вложенность без предела — ошибка формата, а не RecursionError."""
    deep = b'{"format": "stools-ksc/1", "x": ' + b"[" * 200_000 + b"]" * 200_000 + b"}"
    with pytest.raises(ExportFormatError, match="JSON"):
        load_export(deep)
    # Глубина, которую JSON-разбор ещё держит, а снятие обёрток — уже нет.
    text = json.dumps(build_export())[:-1] + ', "extra": ' + "[" * 5000 + "]" * 5000 + "}"
    with pytest.raises(ExportFormatError, match="вложенность"):
        load_export(text.encode())


def test_export_reads_host_tags_and_profiles() -> None:
    export = load_export(export_bytes())
    assert export.host_tags is not None and export.host_tags["h-ws01"] == ["VIP", "Бухгалтерия"]
    assert export.policy_profiles is not None and [p["name"] for p in export.policy_profiles["1"]["profiles"]] == ["Ноутбуки", "Выключенный"]
    assert export.policy_profiles["1"]["profiles"][0]["attrs"]["EXPRESSION"] == NOTEBOOKS_EXPRESSION
    by = {h.name: h for h in ExportIndex(export).hosts}
    assert by["WS01"].tags == ["VIP", "Бухгалтерия"] and by["WS01"].extra["tags"] == ["VIP", "Бухгалтерия"]
    assert by["WS02"].tags == [] and by["WS02"].extra["tags"] == []


def test_export_without_new_sections_marks_not_collected() -> None:
    export = load_export(json.dumps(without_new_sections(build_export())).encode())
    assert export.host_tags is None and export.policy_profiles is None
    for h in ExportIndex(export).hosts:
        assert h.tags == [] and "tags" not in h.extra


def test_export_hides_secrets_in_profiles() -> None:
    export = load_export(export_bytes())
    assert export.policy_profiles is not None
    assert export.policy_profiles["1"]["profiles"][0]["sections"]["KLPRSS_Basic"]["ProxyPassword"]["KLPRSS_Val"] == "<скрыто>"
    text = json.dumps(export.policy_profiles, ensure_ascii=False)
    assert not [v for v in SECRET_VALUES if v in text]


def test_old_collector_file_keeps_what_it_hid() -> None:
    """Файл сборщика 1.2: адрес `octets`, пустой `Login` и пустые строки замка под признаком уже
    скрыты. Разбор их не восстанавливает и ничего не меняет — адреса и пустые строки появятся только
    в выгрузках 1.3+."""
    raw = build_export()
    raw["server"]["collector_version"] = "1.2"
    contents = expected_policy_contents()
    for policy in contents.values():
        sections = policy["sections"]
        for rule in sections["KLPRSS_Firewall"]["rules"]["KLPRSS_Val"][:2]:
            rule["octets"] = "<скрыто>"
        protection = sections["KLPRSS_Basic"]["PasswordProtection"]
        protection.update(KLPRSS_ValLckPolicy="<скрыто>", KLPRSS_ValLckGroup="<скрыто>")
        protection["KLPRSS_Val"]["Login"] = "<скрыто>"
    raw["policy_contents"] = contents
    export = load_export(json.dumps(raw).encode())
    assert export.server.collector_version == "1.2"
    assert export.policy_contents == contents


def test_host_tags_keys_match_hosts_with_agent() -> None:
    raw = build_export()
    with_agent = {h["KLHST_WKS_HOSTNAME"] for h in raw["hosts"] if h["KLHST_WKS_STATUS"] & 4}
    assert set(raw["host_tags"]) == with_agent
    assert "h-wg01" in raw["host_tags"] and "h-ws14" not in raw["host_tags"]


def test_host_tags_are_normalised() -> None:
    raw = build_export()
    raw["host_tags"]["h-ws01"] = ["", " ", "VIP", "VIP"]
    by = {h.name: h for h in ExportIndex(load_export(json.dumps(raw).encode())).hosts}
    assert by["WS01"].tags == ["VIP"]


USER01 = HostUser(sid=f"{LAB_SID}-1001", sam="LAB\\user01", upn="user01@lab.local", display_name="Пользователь 01", domain="lab.local",
                  local=False, group=False, active=True)


def test_export_reads_host_users_and_owner() -> None:
    """Сборщик 1.4: пользователи хоста — поля контракта (§2.1), владелец связан со списком хоста по `ul_binId`."""
    export = load_export(export_bytes())
    assert export.host_users is not None and set(export.host_users) == set(build_export()["host_users"])
    by = {h.name: h for h in ExportIndex(export).hosts}
    ws01 = by["WS01"]
    assert ws01.users_collected and ws01.users is not None and [u.sam for u in ws01.users] == ["LAB\\user01", "LAB\\user02", "LAB\\Domain Users"]
    assert ws01.users[0] == USER01 and ws01.users[1].active is False and ws01.users[1].domain == "LAB" and ws01.users[2].group is True
    assert ws01.owner == {"sid": f"{LAB_SID}-1001", "sam": "LAB\\user01", "display_name": "Пользователь 01"}
    assert ws01.extra["users"] == [
        {"sid": f"{LAB_SID}-1001", "sam": "LAB\\user01", "upn": "user01@lab.local", "display_name": "Пользователь 01", "domain": "lab.local",
         "local": False, "group": False, "active": True},
        {"sid": f"{LAB_SID}-1002", "sam": "LAB\\user02", "upn": "", "display_name": "Пользователь 02", "domain": "LAB",
         "local": False, "group": False, "active": False},
        {"sid": f"{LAB_SID}-513", "sam": "LAB\\Domain Users", "upn": "", "display_name": "", "domain": "lab.local",
         "local": False, "group": True, "active": True},
    ]
    assert ws01.extra["owner"] == ws01.owner and ws01.extra["users_collected"] is True
    # владелец задан, но в списке пользователей хоста его нет — только идентификатор
    assert by["WS03"].owner == {"owner_id": user_bin_id(1003)["value"]} and by["WS03"].extra["owner"] == by["WS03"].owner
    srv = by["SRV01"]
    assert srv.users is not None and srv.users[0] == USER01
    assert srv.users[1] == HostUser(sid="", sam="svc-local", upn="", display_name="", domain="", local=True, group=False, active=False)
    # никто не заходил — пустой список; без агента пользователей не спрашивали — «не собрано»
    assert by["WS02"].users == [] and by["WS02"].extra["users"] == [] and by["WS02"].owner is None and by["WS02"].extra["owner"] is None
    assert by["WS06"].users is None and by["WS06"].users_collected and by["WS06"].extra["users"] is None


def test_export_host_users_null_host_is_not_collected() -> None:
    raw = build_export()
    raw["host_users"]["h-ws01"] = None
    by = {h.name: h for h in ExportIndex(load_export(json.dumps(raw).encode())).hosts}
    assert by["WS01"].users is None and by["WS01"].users_collected and by["WS01"].extra["users"] is None
    # список не собран — владельца не с чем связать, остаётся идентификатор
    assert by["WS01"].owner == {"owner_id": user_bin_id(1001)["value"]}
    assert by["WS03"].users is not None and len(by["WS03"].users) == 1


def test_export_without_host_users_marks_not_collected() -> None:
    raw = build_export()
    raw.pop("host_users")
    for h in raw["hosts"]:
        h.pop("KLHST_WKS_OWNER_ID", None)
    export = load_export(json.dumps(raw).encode())
    assert export.host_users is None
    for h in ExportIndex(export).hosts:
        assert h.users is None and h.users_collected is False and h.owner is None
        assert h.extra["users"] is None and h.extra["owner"] is None and h.extra["users_collected"] is False


def test_export_host_users_tolerates_partial_items() -> None:
    """Запись без части полей (файл, поправленный руками) разбирается пустыми значениями, а не отказом."""
    raw = build_export()
    raw["host_users"]["h-ws02"] = [{"sam": "LAB\\user09", "active": True}]
    by = {h.name: h for h in ExportIndex(load_export(json.dumps(raw).encode())).hosts}
    assert by["WS02"].users == [HostUser(sid="", sam="LAB\\user09", upn="", display_name="", domain="", local=False, group=False, active=True)]


@pytest.mark.parametrize("packed", [False, True])
def test_snapshot_reader_matches_import_without_full_text_read(tmp_path, monkeypatch, packed):
    from api.modules.ksc.core import export

    raw = build_export()
    raw["numeric_probe"] = {"large": 2**80, "decimal": 1.25, "array": [0.125, 2**64]}
    data = json.dumps(raw, ensure_ascii=False).encode()
    expected = load_export(data)
    path = tmp_path / "snapshot.json.gz"
    path.write_bytes(gzip.compress(data) if packed else data)
    original = gzip.GzipFile.read

    def bounded_read(self, size=-1):
        assert size >= 0, "must not materialize the whole decompressed JSON"
        return original(self, size)

    monkeypatch.setattr(gzip.GzipFile, "read", bounded_read)
    monkeypatch.setattr(export, "MAX_UNPACKED", 64)
    actual = export.load_snapshot_export(path)
    assert actual.model_dump() == expected.model_dump()
    # Decimal from the streaming parser must not leak into stored JSON fields.
    assert json.loads(json.dumps(actual.model_extra["numeric_probe"])) == raw["numeric_probe"]


@pytest.mark.parametrize("body", [b"", b"{", b"{}{}", b"[]", b"null", b'{"format":"other"}', b'\xff'])
@pytest.mark.parametrize("packed", [False, True])
def test_snapshot_reader_rejects_invalid_documents(tmp_path, body, packed):
    from api.modules.ksc.core.export import load_snapshot_export

    path = tmp_path / "snapshot.json.gz"
    path.write_bytes(gzip.compress(body) if packed else body)
    with pytest.raises(ExportFormatError):
        load_snapshot_export(path)


@pytest.mark.parametrize("damage", ["deflate", "crc", "truncated", "trailing_json", "second_member"])
def test_snapshot_reader_checks_entire_gzip(tmp_path, damage):
    from api.modules.ksc.core.export import load_snapshot_export

    compressed = gzip.compress(export_bytes())
    if damage == "deflate":
        compressed = corrupted_gzip()
    elif damage == "crc":
        compressed = compressed[:-8] + bytes([compressed[-8] ^ 255]) + compressed[-7:]
    elif damage == "truncated":
        compressed = compressed[:-4]
    elif damage == "trailing_json":
        compressed = gzip.compress(export_bytes() + b" {}")
    else:
        compressed += gzip.compress(b"{}")
    path = tmp_path / "snapshot.json.gz"
    path.write_bytes(compressed)
    with pytest.raises(ExportFormatError):
        load_snapshot_export(path)


def test_synthetic_profiles_are_independent():
    first, second = build_export(), build_export()
    first["policy_profiles"]["1"]["profiles"][0]["attrs"]["KLSSPOL_PRF_ENABLED"] = False
    assert second["policy_profiles"]["1"]["profiles"][0]["attrs"]["KLSSPOL_PRF_ENABLED"] is True
