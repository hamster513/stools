"""Структура сетевого правила (`Scope`): адреса, направление, протокол, порты и маркеры нечитаемого — разбор извлекателем
KES, JSON и текст `addresses`."""
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
from tests.ksc.kes11 import ICMP, ICMPV6, TCP, UDP, kes11_sections, octets, packet_rule

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
    assert rules[0].scope == Scope(networks=2, direction=3, protocol=TCP, local_ports=((3389, 3389),))
    assert rules[1].scope == Scope(remote=(Address(ip="192.0.2.53", mask=32),), direction=2, protocol=UDP, remote_ports=((53, 53),))
    assert rules[2].scope == Scope(icmp_type=8, direction=0, protocol=ICMP)
    assert rules[3].scope == Scope(remote=(Address(host="updates.example.test"), Address(ip="2001:db8::10", mask=64)), direction=2)
    assert rules[4].scope == Scope(local=(Address(ip="192.0.2.0", mask=24),), direction=4, protocol=ICMPV6)
    # Правило программы без протокола: протокол любой (None), портов нет.
    assert rules[5].layer == "app" and rules[5].scope == Scope(direction=2)
    assert all(r.scope.unread == () for r in rules)


def test_scope_ports_skip_non_int_pairs() -> None:
    """Пары портов — только int (не bool), в порядке выгрузки; пропущенная пара, элемент не словарь или список не списком
    помечаются `ports`. Текст `local_ports` строится как раньше."""
    ports: list[Any] = [{"begin": 1, "end": "x"}, {"begin": True, "end": True}, {"begin": 80, "end": 81}, "мусор"]
    packet = packet_rule("Правило", action=0, direction=0, protocol=TCP, remote_ports=[{"begin": 443, "end": 443}])
    packet["protocol"]["localPorts"] = ports
    [rule] = extract_kes(kes11_sections(**{PACKET: [packet], GROUPS: []})).net_rules
    assert (rule.scope.local_ports, rule.scope.remote_ports, rule.scope.unread) == (((80, 81),), ((443, 443),), ("ports",))
    assert (rule.local_ports, rule.remote_ports) == ("True, 80-81", "443")
    packet["protocol"]["localPorts"] = {"begin": 1, "end": 2}
    [rule] = extract_kes(kes11_sections(**{PACKET: [packet], GROUPS: []})).net_rules
    assert (rule.scope.local_ports, rule.scope.unread, rule.local_ports) == ((), ("ports",), "")


def test_scope_empty_ports() -> None:
    scope = _scope(protocol=TCP)
    assert (scope.local_ports, scope.remote_ports, scope.unread, scope.protocol, scope.direction) == ((), (), (), TCP, 0)


def test_scope_unread_markers() -> None:
    """Критерий есть в выгрузке, но не прочитан: `networks` не int, маска bool при `octets`, вид ICMP не int, направление или
    протокол не int. Отсутствие и null — не маркер; маска у имени узла не читается и не маркер."""
    item = _address("192.0.2.53", mask=True)  # type: ignore[arg-type]
    packet = packet_rule("Правило", action=0, direction=0, protocol=ICMP, icmp_type=8, remote=[item], networks=2)
    packet["scope"]["networks"] = "2"
    packet["protocol"]["type"]["value"] = "8"
    packet["packetDirection"] = "0"
    [rule] = extract_kes(kes11_sections(**{PACKET: [packet], GROUPS: []})).net_rules
    assert rule.scope.unread == ("direction", "networks", "mask", "icmp_type")
    assert (rule.scope.direction, rule.scope.networks, rule.scope.icmp_type, rule.scope.protocol) == (None, None, None, ICMP)
    assert (rule.direction, rule.protocol) == ("код 0", "ICMP")  # текст прежний
    packet = packet_rule("Правило", action=0, direction=0, remote=[{**_address("192.0.2.1", 24), "hostName": "h", "mask": False}])
    packet["protocol"]["unique_id"] = "TCP"
    packet["scope"]["networks"] = None
    [rule] = extract_kes(kes11_sections(**{PACKET: [packet], GROUPS: []})).net_rules
    assert (rule.scope.unread, rule.scope.protocol, rule.scope.networks) == (("protocol",), None, None)
    assert _scope(protocol=TCP, icmp_type=3).unread == ()  # вид ICMP у TCP не критерий


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
    bad_base64 = _address("192.0.2.1", 32, octets="AAA")
    assert _scope(remote=[hidden, odd, bad_base64]).remote == (Address(hidden="secret"), Address(hidden="unparsed"), Address(hidden="unparsed"))


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
    assert _scope(remote=[empty, None, 3], local=[empty]) == Scope(direction=0)  # type: ignore[list-item]


def test_scope_json_roundtrip_and_text() -> None:
    scope = Scope(networks=1, remote=(Address(host="h", ips=(Address(ip="192.0.2.1"), Address(hidden="secret"))),), local=(Address(ip="192.0.2.0", mask=24),), icmp_type=3,
                  direction=2, protocol=ICMP, local_ports=((1, 2), (5, 5)), remote_ports=((80, 80),), unread=("ports", "mask"))
    assert scope_from_json(scope_to_json(scope)) == scope
    assert scope_from_json(None) is None and scope_from_json("") is None and scope_from_json("{") is None
    assert addresses_text(scope) == "локальные сети; h; локальный: 192.0.2.0/24"


def test_scope_json_shape() -> None:
    scope = Scope(networks=2, remote=(Address(ip="192.0.2.53", mask=32),), direction=3, protocol=TCP, local_ports=((3389, 3389),))
    assert json.loads(scope_to_json(scope)) == {
        "networks": 2, "icmp_type": None, "local": [],
        "remote": [{"host": "", "ip": "192.0.2.53", "mask": 32, "ips": [], "hidden": ""}],
        "direction": 3, "protocol": TCP, "local_ports": [[3389, 3389]], "remote_ports": [], "unread": [],
    }


def test_scope_from_json_wrong_shape_is_none() -> None:
    for text in ("[]", "3", "null", '{"remote": 5}', '{"remote": [3]}', '{"networks": "x"}', '{"remote": [{"ips": 7}]}', '{"icmp_type": true}',
                 '{"remote": [{"mask": true}]}',
                 '{"remote": [{"ips": ["192.0.2.1"]}]}', '{"remote": [{"ips": [{"ips": 3}]}]}',
                 '{"direction": true}', '{"protocol": "TCP"}', '{"local_ports": 5}', '{"local_ports": [3]}', '{"local_ports": [[1]]}',
                 '{"remote_ports": [[1, true]]}', '{"remote_ports": [[1, 2, 3]]}', '{"remote_ports": [{"begin": 1, "end": 1}]}',
                 '{"unread": "ports"}', '{"unread": [1]}'):
        assert scope_from_json(text) is None, text
    assert scope_from_json("{}") == Scope()
    assert scope_from_json("[" * 100000) is None  # слишком глубокая вложенность
    nested = Scope(remote=(Address(ips=(Address(ip="192.0.2.1"), Address(hidden="unparsed"))),))
    assert scope_from_json(scope_to_json(nested)) == nested


def test_scope_is_not_part_of_net_rule_key() -> None:
    a = NetRule(layer="packet", position=0, name="n", action="разрешить")
    b = NetRule(layer="packet", position=0, name="n", action="разрешить", scope=Scope(networks=2))
    assert net_rule_key(a) == net_rule_key(b)
