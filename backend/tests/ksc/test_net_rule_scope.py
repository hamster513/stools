"""Структура адресов сетевого правила (`Scope`): разбор извлекателем KES, JSON и текст `addresses`."""
from __future__ import annotations

import base64
import json
from typing import Any

from api.modules.ksc.core.extractors.kes_windows import addresses_text, extract_kes
from api.modules.ksc.core.policy_model import (
    Address,
    NetRule,
    Scope,
    net_rule_key,
    scope_from_json,
    scope_to_json,
)
from api.modules.ksc.core.secrets import HIDDEN
from tests.ksc.kes11 import ICMP, ICMPV6, TCP, kes11_sections, octets, packet_rule

PACKET = "cf9370d5/firewall.networkPacketRules"
GROUPS = "cf9370d5/hips.appGroups"


def _address(address: str, mask: int | None = None, **extra: Any) -> dict[str, Any]:
    item: dict[str, Any] = {"hostName": "", "hostNameIPs": [], "octets": octets(address), "unique_id": 1143071574, "zoneIPv6": ""}
    if mask is not None:
        item["mask"] = mask
    return {**item, **extra}


def _scope(**kwargs: Any) -> Scope:
    """Структура адресов единственного пакетного правила, собранного `packet_rule(**kwargs)`."""
    sections = kes11_sections(**{PACKET: [packet_rule("Правило", action=0, direction=0, **kwargs)], GROUPS: []})
    [rule] = extract_kes(sections).net_rules
    return rule.scope


def test_scope_of_fixture_rules() -> None:
    rules = extract_kes(kes11_sections()).net_rules
    assert rules[0].scope == Scope(networks=2)
    assert rules[1].scope == Scope(remote=(Address(ip="192.0.2.53", mask=32),))
    assert rules[2].scope == Scope(icmp_type=8)
    assert rules[3].scope.remote == (Address(host="updates.example.test"), Address(ip="2001:db8::10", mask=64))
    assert rules[4].scope.local == (Address(ip="192.0.2.0", mask=24),)


def test_scope_ignores_bool_mask_and_non_int_networks() -> None:
    item = _address("192.0.2.53", mask=True)  # type: ignore[arg-type]
    packet = packet_rule("Правило", action=0, direction=0, remote=[item], networks=2)
    packet["scope"]["networks"] = "2"
    [rule] = extract_kes(kes11_sections(**{PACKET: [packet], GROUPS: []})).net_rules
    assert rule.scope.remote == (Address(ip="192.0.2.53", mask=None),)
    assert rule.scope.networks is None
    packet["scope"]["networks"] = True
    [rule] = extract_kes(kes11_sections(**{PACKET: [packet], GROUPS: []})).net_rules
    assert rule.scope.networks is None


def test_scope_icmp_type_only_for_icmp_and_int() -> None:
    assert _scope(protocol=ICMPV6, icmp_type=3).icmp_type == 3
    assert _scope(protocol=ICMP, icmp_type=0).icmp_type == 0
    assert _scope(protocol=TCP, icmp_type=3).icmp_type is None
    packet = packet_rule("Правило", action=0, direction=0, protocol=ICMP, icmp_type=8)
    packet["protocol"]["type"]["value"] = True
    [rule] = extract_kes(kes11_sections(**{PACKET: [packet], GROUPS: []})).net_rules
    assert rule.scope.icmp_type is None


def test_scope_ipv6_and_host_ips() -> None:
    resolved = {"hostName": "", "hostNameIPs": [{"octets": octets("2001:db8::10"), "zoneIPv6": ""}, {"octets": octets("192.0.2.7")}],
                "unique_id": 1253756384}
    assert _scope(remote=[resolved]).remote == (Address(ips=(Address(ip="2001:db8::10"), Address(ip="192.0.2.7"))),)


def test_scope_hidden_and_unparsed() -> None:
    hidden = _address("192.0.2.1", 32, octets=HIDDEN)
    odd = _address("192.0.2.1", 32, octets=base64.b64encode(b"\x01\x02\x03").decode())
    non_ascii = _address("192.0.2.1", 32, octets="AAA")
    assert _scope(remote=[hidden, odd, non_ascii]).remote == (Address(hidden="secret"), Address(hidden="unparsed"), Address(hidden="unparsed"))


def _resolved(*octets_values: Any) -> dict[str, Any]:
    return {"hostName": "", "hostNameIPs": [{"octets": value, "zoneIPv6": ""} for value in octets_values], "unique_id": 1253756384}


def test_host_ips_hidden_kept_one_by_one() -> None:
    [rule] = extract_kes(kes11_sections(**{PACKET: [packet_rule("Правило", action=0, direction=0, remote=[_resolved(HIDDEN, HIDDEN)])],
                                           GROUPS: []})).net_rules
    assert rule.scope.remote == (Address(ips=(Address(hidden="secret"), Address(hidden="secret"))),)
    # Строка прежнего вывода: подпись на каждую запись.
    assert rule.addresses == "адрес скрыт (сборщик до 1.3), адрес скрыт (сборщик до 1.3)"


def test_host_ips_unparsed_keeps_export_order() -> None:
    [rule] = extract_kes(kes11_sections(**{
        PACKET: [packet_rule("Правило", action=0, direction=0, remote=[_resolved("AAA", octets("192.0.2.7")), _resolved(octets("192.0.2.8"), None)])],
        GROUPS: [],
    })).net_rules
    assert rule.scope.remote == (
        Address(ips=(Address(hidden="unparsed"), Address(ip="192.0.2.7"))),
        Address(ips=(Address(ip="192.0.2.8"), Address(hidden="unparsed"))),
    )
    assert rule.addresses == "адрес не разобран, 192.0.2.7; 192.0.2.8, адрес не разобран"


def test_scope_skips_empty_and_foreign_items() -> None:
    empty = {"hostName": "", "hostNameIPs": [], "unique_id": 1253756384}
    assert _scope(remote=[empty, None, 3], local=[empty]) == Scope()  # type: ignore[list-item]


def test_scope_json_roundtrip_and_text() -> None:
    scope = Scope(networks=1, remote=(Address(host="h", ips=(Address(ip="192.0.2.1"), Address(hidden="secret"))),), local=(Address(ip="192.0.2.0", mask=24),), icmp_type=3)
    assert scope_from_json(scope_to_json(scope)) == scope
    assert scope_from_json(None) is None and scope_from_json("") is None and scope_from_json("{") is None
    assert addresses_text(scope) == "локальные сети; h; локальный: 192.0.2.0/24"


def test_scope_json_shape() -> None:
    scope = Scope(networks=2, remote=(Address(ip="192.0.2.53", mask=32),))
    assert json.loads(scope_to_json(scope)) == {
        "networks": 2, "icmp_type": None, "local": [],
        "remote": [{"host": "", "ip": "192.0.2.53", "mask": 32, "ips": [], "hidden": ""}],
    }


def test_scope_from_json_wrong_shape_is_none() -> None:
    for text in ("[]", "3", "null", '{"remote": 5}', '{"remote": [3]}', '{"networks": "x"}', '{"remote": [{"ips": 7}]}', '{"icmp_type": true}',
                 '{"remote": [{"mask": true}]}',
                 '{"remote": [{"ips": ["192.0.2.1"]}]}', '{"remote": [{"ips": [{"ips": 3}]}]}'):
        assert scope_from_json(text) is None, text
    assert scope_from_json("{}") == Scope()
    assert scope_from_json("[" * 100000) is None  # слишком глубокая вложенность
    nested = Scope(remote=(Address(ips=(Address(ip="192.0.2.1"), Address(hidden="unparsed"))),))
    assert scope_from_json(scope_to_json(nested)) == nested


def test_scope_is_not_part_of_net_rule_key() -> None:
    a = NetRule(layer="packet", position=0, name="n", action="разрешить")
    b = NetRule(layer="packet", position=0, name="n", action="разрешить", scope=Scope(networks=2))
    assert net_rule_key(a) == net_rule_key(b)
