"""Извлекатель KES для Windows: исключения, доверенные программы и сетевые правила из секций политики."""
from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.ksc.core.changes import Change, diff_exports
from api.modules.ksc.core.export import load_export
from api.modules.ksc.core.extractors.kes_windows import extract_kes
from api.modules.ksc.core.policy_contents import flat_settings
from api.modules.ksc.core.policy_index import policy_objects
from api.modules.ksc.core.policy_model import EXTRACTORS, Exclusion, NetRule, PolicyObjects, extract
from api.modules.ksc.models import KscChange, KscExclusion, KscNetRule, KscPolicy
from tests.ksc.kes11 import (
    ICMP,
    ICMPV6,
    TCP,
    UDP,
    exclusion,
    kes11_export,
    kes11_sections,
    octets,
    packet_rule,
    trusted_app,
)
from tests.ksc.test_api import upload

EXCLUSIONS = "852d0287/scanExclusionsAndTrustedZone.scanExclusions"
TRUSTED = "852d0287/scanExclusionsAndTrustedZone.trustedApplications"
PACKET = "cf9370d5/firewall.networkPacketRules"
GROUPS = "cf9370d5/hips.appGroups"
SHAPES = ["leaf", "top", "section", "mixed"]
CONSUMED = {
    ("852d0287", "scanExclusionsAndTrustedZone.scanExclusions"),
    ("852d0287", "scanExclusionsAndTrustedZone.scanExclusions_merging_crutch"),
    ("852d0287", "scanExclusionsAndTrustedZone.trustedApplications"),
    ("852d0287", "scanExclusionsAndTrustedZone.trustedApplications_merging_crutch"),
    ("cf9370d5", "firewall.networkPacketRules"),
}


def _objects(**over: Any) -> PolicyObjects:
    return extract_kes(kes11_sections(**over))


def _rule(**kwargs: Any) -> NetRule:
    [rule] = _objects(**{PACKET: [packet_rule("Правило", **kwargs)], GROUPS: []}).net_rules
    return rule


def _packet(name: str = "Правило", **kwargs: Any) -> dict[str, Any]:
    return packet_rule(name, **{"action": 0, "direction": 0, **kwargs})


def _one(item: dict[str, Any]) -> NetRule:
    [rule] = _objects(**{PACKET: [item], GROUPS: []}).net_rules
    return rule


def _address(address: str, mask: int) -> dict[str, Any]:
    return {"hostName": "", "hostNameIPs": [], "mask": mask, "octets": octets(address), "unique_id": 1143071574, "zoneIPv6": ""}


# --- регистрация -------------------------------------------------------------------------------


def test_registered_for_kes_only() -> None:
    assert EXTRACTORS["KES"] is extract_kes
    assert extract("KES", {}) == PolicyObjects(consumed=CONSUMED)
    assert extract("kesl", kes11_sections()) is None


def test_failing_extractor_does_not_break_extract(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    def broken(sections: dict[str, Any]) -> PolicyObjects:
        raise RuntimeError("boom")

    monkeypatch.setitem(EXTRACTORS, "KES", broken)
    assert extract("KES", kes11_sections()) == PolicyObjects()
    assert "boom" in caplog.text


# --- исключения --------------------------------------------------------------------------------


@pytest.mark.parametrize(("item", "expected"), [
    (exclusion("C:\\Tools\\a.exe", comment="к"), Exclusion("path", "C:\\Tools\\a.exe", comment="к")),
    (exclusion("C:\\Tools\\*.tmp"), Exclusion("mask", "C:\\Tools\\*.tmp")),
    (exclusion("C:\\Tools\\a?.exe", recursive=True), Exclusion("mask", "C:\\Tools\\a?.exe", components=("рекурсивно",))),
    (exclusion("C:\\Tools\\", name="Test.Win32.*", enabled=False),
     Exclusion("path", "C:\\Tools\\", components=("объект: Test.Win32.*",), enabled=False)),
    (exclusion(file_hash="ab" * 32, comment="хеш"), Exclusion("hash", "ab" * 32, comment="хеш")),
    (exclusion(name="not-a-virus:Test.Win32.Sample"), Exclusion("threat", "not-a-virus:Test.Win32.Sample")),
    ({**exclusion("C:\\Data"), "components": ["Защита от файловых угроз", "AMSI"]},
     Exclusion("path", "C:\\Data", components=("Защита от файловых угроз", "AMSI"))),
])
def test_exclusion_kinds(item: dict[str, Any], expected: Exclusion) -> None:
    assert _objects(**{EXCLUSIONS: [item], TRUSTED: []}).exclusions == [expected]


FLAGS = [
    ("excludeOpenFiles", "не проверять открываемые файлы"),
    ("excludeBehavior", "не контролировать активность"),
    ("excludeChildsBehavior", "не контролировать дочерние процессы"),
    ("excludeChildsBehaviorRecursive", "не контролировать дочерние процессы рекурсивно"),
    ("excludeHipsNoInherit", "не наследовать ограничения родителя"),
    ("excludeNet", "не проверять сетевой трафик"),
    ("excludeSelfProt", "разрешить взаимодействие с интерфейсом программы"),
    ("excludeAmsiScan", "не проверять через AMSI"),
    ("excludeXDRTelemetry", "не передавать телеметрию XDR"),
    ("excludeFileIntegrityMonitoring", "не контролировать целостность файлов"),
    ("excludeRegistryIntegrityMonitoring", "не контролировать целостность реестра"),
    ("excludeConsoleInputMonitoring", "не контролировать ввод в консоли"),
]


@pytest.mark.parametrize(("flag", "label"), FLAGS)
def test_trusted_app_flag(flag: str, label: str) -> None:
    [e] = _objects(**{EXCLUSIONS: [], TRUSTED: [trusted_app("C:\\Tools\\b.exe", comment="к", **{flag: True})]}).exclusions
    assert e == Exclusion("trusted_app", "C:\\Tools\\b.exe", components=(label,), comment="к")


def test_trusted_app_encrypted_traffic_only_and_order() -> None:
    app = trusted_app("C:\\Tools\\b.exe", enabled=False, excludeNet=True, encryptedTrafficOnly=True, excludeOpenFiles=True, excludeAmsiScan=True)
    [e] = _objects(**{EXCLUSIONS: [], TRUSTED: [app]}).exclusions
    assert e.components == ("не проверять открываемые файлы", "не проверять сетевой трафик (только зашифрованный)", "не проверять через AMSI")
    assert e.enabled is False
    [plain] = _objects(**{EXCLUSIONS: [], TRUSTED: [trusted_app("C:\\Tools\\c.exe")]}).exclusions
    assert plain.components == ()


def test_trusted_app_net_hosts_and_ports() -> None:
    app = trusted_app("C:\\Tools\\b.exe", excludeNet=True)
    app["excludeNet"].update(hosts=["updates.example.test", "192.0.2.1"], ports=[80, 443])
    off = trusted_app("C:\\Tools\\c.exe")
    off["excludeNet"].update(hosts=["updates.example.test"], ports=[80])  # проверка трафика не отключена — узлы не в счёт
    odd = trusted_app("C:\\Tools\\d.exe", excludeNet=True)
    odd["excludeNet"].update(hosts=[{"name": "x"}], ports="80")  # не список скаляров — не показывается
    [e, e_off, e_odd] = _objects(**{EXCLUSIONS: [], TRUSTED: [app, off, odd]}).exclusions
    assert e.components == ("не проверять сетевой трафик", "узлы: updates.example.test, 192.0.2.1", "порты: 80, 443")
    assert e_off.components == () and e_odd.components == ("не проверять сетевой трафик",)


def test_enabled_only_explicit_false_disables() -> None:
    hidden = {**exclusion("C:\\a"), "enabled": "<скрыто>"}
    missing = {k: v for k, v in exclusion("C:\\b").items() if k != "enabled"}
    app = {k: v for k, v in trusted_app("C:\\c.exe").items() if k != "enabled"}
    assert [e.enabled for e in _objects(**{EXCLUSIONS: [hidden, missing, exclusion("C:\\d", enabled=False)], TRUSTED: [app]}).exclusions] == [
        True, True, False, True]
    rule = {k: v for k, v in _packet().items() if k != "enabled"}
    assert _one(rule).enabled is True and _one({**_packet(), "enabled": "<скрыто>"}).enabled is True
    assert _one(_packet(enabled=False)).enabled is False


def test_fixture_exclusions() -> None:
    assert _objects().exclusions == [
        Exclusion("path", "C:\\Tools\\a.exe", comment="Тестовое исключение"),
        Exclusion("mask", "D:\\Data\\Test\\*.log", components=("объект: not-a-virus:Test.Win32.Sample", "рекурсивно")),
        Exclusion("hash", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", comment="по хешу"),
        Exclusion("trusted_app", "C:\\Tools\\backup.exe", components=("не проверять открываемые файлы", "не контролировать активность"),
                  comment="Тестовая программа"),
        Exclusion("trusted_app", "C:\\Program Files\\Test App\\agent.exe", components=("не проверять сетевой трафик (только зашифрованный)",),
                  enabled=False),
    ]


# --- сетевые правила ---------------------------------------------------------------------------


def test_packet_rule_tcp_rdp_public_networks() -> None:
    rule = _objects().net_rules[0]
    assert rule == NetRule(
        layer="packet", position=0, name="Тестовое правило: удалённый рабочий стол", action="запретить", direction="входящий (поток)",
        protocol="TCP", local_ports="3389", remote_ports="", addresses="публичные сети", enabled=True,
    )


def test_fixture_net_rules() -> None:
    rules = [(r.layer, r.position, r.name, r.action, r.direction, r.protocol, r.remote_ports, r.addresses, r.enabled)
             for r in _objects().net_rules]
    assert rules == [
        ("packet", 0, "Тестовое правило: удалённый рабочий стол", "запретить", "входящий (поток)", "TCP", "", "публичные сети", True),
        ("packet", 1, "Тестовое правило: DNS", "разрешить", "входящий/исходящий", "UDP", "53", "192.0.2.53/32", True),
        ("packet", 2, "Тестовое правило: эхо-запрос", "разрешить", "входящий (пакет)", "ICMP (вид 8)", "", "", True),
        ("packet", 3, "Тестовое правило: любой протокол", "по правилам программ", "входящий/исходящий", "любой", "",
         "updates.example.test; 2001:db8::10/64", True),
        ("packet", 4, "Тестовое правило: ICMPv6", "запретить", "исходящий (поток)", "ICMPv6", "", "локальный: 192.0.2.0/24", False),
        ("app", 0, "Тестовая программа: Тестовое правило программы", "разрешить", "входящий/исходящий", "любой", "", "", True),
    ]


def test_ports_ranges_and_codes() -> None:
    rule = _rule(action=7, direction=1, protocol=UDP, local_ports=[{"begin": 53, "end": 53}, {"begin": 1024, "end": 65535}],
                 remote_ports=[{"begin": 1, "end": 2}], networks=9)
    assert (rule.action, rule.direction, rule.protocol, rule.local_ports, rule.remote_ports, rule.addresses) == (
        "код 7", "исходящий (пакет)", "UDP", "53, 1024-65535", "1-2", "код 9")
    assert _rule(action=0, direction=0, protocol=12345).protocol == "код 12345"
    assert _rule(action=0, direction=0).protocol == "любой"
    assert _rule(action=0, direction=0, protocol=ICMP, icmp_type=0).protocol == "ICMP (вид 0)"
    assert _rule(action=0, direction=0, protocol=ICMP).protocol == "ICMP"
    assert _rule(action=0, direction=0, networks=0).addresses == "доверенные сети"
    assert _rule(action=0, direction=0, networks=1).addresses == "локальные сети"
    # «(вид N)» — только у ICMP и ICMPv6.
    assert _rule(action=0, direction=0, protocol=ICMPV6, icmp_type=3).protocol == "ICMPv6 (вид 3)"
    assert _rule(action=0, direction=0, protocol=TCP, icmp_type=3).protocol == "TCP"
    assert _rule(action=0, direction=0, protocol=12345, icmp_type=3).protocol == "код 12345"
    null_proto = _packet(protocol=TCP)
    null_proto["protocol"]["unique_id"] = None
    assert _one(null_proto).protocol == "любой"
    null_networks = _packet(remote=[_address("192.0.2.1", 32)], networks=0)
    null_networks["scope"]["networks"] = None
    assert _one(null_networks).addresses == "192.0.2.1/32"


def test_addresses_ipv4_ipv6_mask_hidden_and_local() -> None:
    hidden = {"hostName": "", "hostNameIPs": [], "mask": 32, "octets": "<скрыто>", "unique_id": 1143071574, "zoneIPv6": ""}
    odd = {**hidden, "octets": base64.b64encode(b"\x01\x02\x03").decode()}
    non_ascii = {**hidden, "octets": "адрес"}
    resolved = {"hostName": "", "hostNameIPs": [{"octets": octets("192.0.2.7"), "zoneIPv6": ""}], "unique_id": 1253756384}
    rule = _rule(action=1, direction=2, protocol=TCP, networks=2,
                 remote=[_address("192.0.2.0", 24), _address("2001:db8::", 32), hidden, odd, non_ascii, resolved],
                 local=[_address("198.51.100.1", 32), {"hostName": "srv.example.test", "hostNameIPs": [], "unique_id": 1253756384}])
    assert rule.addresses == ("публичные сети; 192.0.2.0/24; 2001:db8::/32; адрес скрыт (сборщик до 1.3); адрес не разобран; "
                              "адрес не разобран; 192.0.2.7; "
                              "локальный: 198.51.100.1/32; локальный: srv.example.test")


def test_app_group_rules() -> None:
    rule = {"action": 1, "enabled": False, "log": False, "name": "Блок", "networkAdapters": [], "packetDirection": 4, "userChanged": False,
            "protocol": {"localPorts": [], "remotePorts": [{"begin": 443, "end": 443}], "unique_id": TCP}}
    groups = [
        {"name": "Группа А", "networkPacketRules": [rule], "applications": [
            {"name": "Программа 1", "networkPacketRules": [rule, dict(rule, name="Второе")]},
            {"name": "Программа 2", "networkPacketRules": []},
        ]},
        {"name": "Группа Б", "applications": [{"name": "Программа 3", "networkPacketRules": [rule]}]},
    ]
    rules = [r for r in _objects(**{GROUPS: groups, PACKET: []}).net_rules]
    assert [(r.layer, r.position, r.name) for r in rules] == [
        ("app", 0, "Группа А: Блок"), ("app", 1, "Программа 1: Блок"), ("app", 2, "Программа 1: Второе"), ("app", 3, "Программа 3: Блок"),
    ]
    assert {(r.action, r.direction, r.protocol, r.remote_ports, r.enabled) for r in rules} == {("запретить", "исходящий (поток)", "TCP", "443", False)}


def test_junk_items_are_skipped() -> None:
    objs = _objects(**{
        EXCLUSIONS: [None, "C:\\x", 5, {}, {"objectMask": "C:\\x"}, exclusion("C:\\ok")],
        TRUSTED: [[], {"filePath": 1}, {"comment": "без пути"}, trusted_app("C:\\ok.exe")],
        PACKET: [None, "правило", {}, {"name": "без действия"}, {"name": 5, "action": 0}, packet_rule("ОК", action=0, direction=0, remote=[None, 3, {"octets": "ä", "mask": 1}])],
        GROUPS: [None, {"name": "Г", "applications": [None, {"name": "П", "networkPacketRules": "x"}], "networkPacketRules": [7]}],
    })
    assert [e.value for e in objs.exclusions] == ["C:\\ok", "C:\\ok.exe"]
    assert [(r.name, r.addresses) for r in objs.net_rules] == [("ОК", "адрес не разобран")]
    assert _objects(**{EXCLUSIONS: "не список", PACKET: {"a": 1}, GROUPS: 3}).net_rules == []
    assert extract_kes({"852d0287": "мусор", "cf9370d5": [1, 2]}) == PolicyObjects(consumed=CONSUMED)


# --- форма выгрузки ----------------------------------------------------------------------------


@pytest.mark.parametrize("shape", SHAPES)
def test_consumed_are_leaf_paths_in_every_shape(shape: str) -> None:
    sections = kes11_sections(shape)
    objs = extract_kes(sections)
    assert objs.consumed == CONSUMED
    assert CONSUMED <= {(s.section, s.path) for s in flat_settings(sections)}
    assert objs == extract_kes(kes11_sections())


def test_params_wrapped_items_survive_load() -> None:
    raw = kes11_export(**{
        EXCLUSIONS: [{"type": "params", "value": exclusion("C:\\Wrapped\\a.exe")}],
        PACKET: [{"type": "params", "value": packet_rule("Обёрнутое", action=0, direction=2, protocol=TCP,
                                                          remote=[{"type": "params", "value": _address("192.0.2.9", 32)}])}],
    })
    assert extract_kes(raw["policy_contents"]["1"]["sections"]).exclusions[0].value == "C:\\Wrapped\\a.exe"
    objs, described = policy_objects(load_export(json.dumps(raw).encode()), "1")
    assert described is True
    assert objs.exclusions[0] == Exclusion("path", "C:\\Wrapped\\a.exe")
    assert [(r.name, r.addresses) for r in objs.net_rules if r.layer == "packet"] == [("Обёрнутое", "192.0.2.9/32")]


# --- импорт и API ------------------------------------------------------------------------------


def _sid(client: TestClient) -> int:
    return int(client.get("/api/ksc/snapshots").json()[0]["id"])


def test_import_stores_records_and_api_returns_them(auth_client: TestClient, db_session: Session) -> None:
    assert upload(auth_client, kes11_export())["status"] == "done"
    sid = _sid(auth_client)
    db_session.expire_all()
    p1 = db_session.execute(select(KscPolicy).where(KscPolicy.snapshot_id == sid, KscPolicy.policy_id == 1)).scalar_one()
    assert p1.described is True and p1.exclusions == 5 and p1.net_rules == 6
    kinds = sorted(e.kind for e in db_session.execute(
        select(KscExclusion).where(KscExclusion.snapshot_id == sid, KscExclusion.policy_id == 1)).scalars())
    assert kinds == ["hash", "mask", "path", "trusted_app", "trusted_app"]
    rules = db_session.execute(select(KscNetRule).where(KscNetRule.snapshot_id == sid, KscNetRule.policy_id == 1)).scalars().all()
    assert sorted((r.layer, r.position) for r in rules) == [("app", 0)] + [("packet", i) for i in range(5)]

    excl = auth_client.get(f"/api/ksc/snapshots/{sid}/exclusions?policy_id=1").json()
    assert excl["undescribed"] == [] and excl["total"] == 5
    mask = next(i for i in excl["items"] if i["kind"] == "mask")
    assert mask["value"] == "D:\\Data\\Test\\*.log" and mask["components"] == ["объект: not-a-virus:Test.Win32.Sample", "рекурсивно"]
    nets = auth_client.get(f"/api/ksc/snapshots/{sid}/net-rules?policy_id=1").json()
    assert nets["undescribed"] == [] and nets["total"] == 6
    rdp = next(i for i in nets["items"] if i["local_ports"] == "3389")
    assert (rdp["action"], rdp["direction"], rdp["protocol"], rdp["addresses"]) == ("запретить", "входящий (поток)", "TCP", "публичные сети")


def test_failing_extractor_does_not_break_import(auth_client: TestClient, db_session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(sections: dict[str, Any]) -> PolicyObjects:
        raise ValueError("boom")

    monkeypatch.setitem(EXTRACTORS, "KES", broken)
    assert upload(auth_client, kes11_export())["status"] == "done"
    db_session.expire_all()
    p1 = db_session.execute(select(KscPolicy).where(KscPolicy.snapshot_id == _sid(auth_client), KscPolicy.policy_id == 1)).scalar_one()
    assert p1.described is True and p1.exclusions == 0 and p1.net_rules == 0


def test_two_imports_journal_records_not_settings(auth_client: TestClient, db_session: Session) -> None:
    first = kes11_export()
    second = kes11_export(**{EXCLUSIONS: [
        exclusion("C:\\Tools\\a.exe", comment="Поправленный комментарий"),
        exclusion("D:\\Data\\Test\\*.log", name="not-a-virus:Test.Win32.Sample", recursive=True),
        exclusion(file_hash="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", comment="по хешу"),
        exclusion("E:\\New"),
    ]})
    second["server"]["collected_at"] = "2026-09-16T12:00:00Z"
    assert upload(auth_client, first)["status"] == "done"
    assert upload(auth_client, second)["status"] == "done"
    sid = _sid(auth_client)
    db_session.expire_all()
    rows = db_session.execute(select(KscChange).where(KscChange.snapshot_id == sid)).scalars().all()
    assert sorted((c.kind, c.action) for c in rows) == [("exclusion", "added"), ("exclusion", "changed")]
    changed = next(c for c in rows if c.action == "changed")
    before, after = json.loads(changed.before_json), json.loads(changed.after_json)
    assert (changed.policy_id, before["comment"], after["comment"]) == (1, "Тестовое исключение", "Поправленный комментарий")
    assert not [c for c in rows if c.kind == "setting" and (c.section, c.path) in CONSUMED]


# --- журнал изменений --------------------------------------------------------------------------


def _journal(prev: dict[str, Any], cur: dict[str, Any]) -> list[Change]:
    """Как при импорте: обёртки сняты, секреты скрыты."""
    return diff_exports(load_export(json.dumps(prev).encode()), load_export(json.dumps(cur).encode())).changes


def test_journal_keeps_hips_and_firewall_settings() -> None:
    """`hips.appGroups` не поглощается извлекателем: правки правил доступа к сети в группах видны как настройка, как и
    выключение сетевого экрана."""
    groups = kes11_sections("section")["cf9370d5"]["KLPRSS_Val"]["hips"]["appGroups"]
    groups[0]["networkAccessRules"][0]["allow"] = False
    for edit, path in ((({"cf9370d5/firewall.enabled": False}), "firewall.enabled"), ({GROUPS: groups}, "hips.appGroups")):
        rows = _journal(kes11_export(), kes11_export(**edit))
        assert [(c.kind, c.action, c.section, c.path) for c in rows] == [("setting", "changed", "cf9370d5", path)]


def _pair(comment: str = "первое") -> list[dict[str, Any]]:
    return [exclusion("C:\\Tools\\", name="Test.Win32.A", comment=comment), exclusion("C:\\Tools\\", name="Test.Win32.B")]


def test_journal_records_with_equal_keys_compared_as_multisets() -> None:
    """Два исключения с одним путём и разными именами объекта — один ключ: правка одного не теряется."""
    base = kes11_export(**{EXCLUSIONS: _pair()})
    assert _journal(base, kes11_export(**{EXCLUSIONS: _pair()})) == []
    edited = _journal(base, kes11_export(**{EXCLUSIONS: _pair("поправлено")}))
    assert [(c.kind, c.action, (c.before or c.after)["comment"]) for c in edited] == [
        ("exclusion", "removed", "первое"), ("exclusion", "added", "поправлено")]
    assert {(c.before or c.after)["components"] for c in edited} == {("объект: Test.Win32.A",)}
    [gone] = _journal(base, kes11_export(**{EXCLUSIONS: _pair()[1:]}))
    assert (gone.kind, gone.action, gone.before["components"], gone.after) == ("exclusion", "removed", ("объект: Test.Win32.A",), None)
