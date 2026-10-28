"""Сопоставление пакета с правилом сетевого экрана по критериям (спека §4.3): да, нет, возможно."""
from __future__ import annotations

import ipaddress
from typing import Any

import pytest

from api.modules.ksc.core.firewall.match import Tri, match_rule, zone_of
from api.modules.ksc.core.firewall.model import Packet, Protocol, RuleView, ZoneView
from api.modules.ksc.core.policy_model import Address, Scope

HOST_IP = "192.0.2.10"
ZONES = (
    ZoneView("Тестовая локальная", 1, ipaddress.ip_network("198.51.100.0/24")),
    ZoneView("Тестовая публичная", 2, ipaddress.ip_network("203.0.113.0/24")),
)


def rule(enabled: bool = True, **scope: Any) -> RuleView:
    return RuleView(row_id=1, policy_id=1, profile="", layer="packet", position=1, name="Тестовое правило", action="разрешить",
                    enabled=enabled, scope=Scope(**scope), direction_text="", protocol_text="", local_ports_text="",
                    remote_ports_text="", addresses_text="")


def packet(**over: Any) -> Packet:
    base: dict[str, Any] = {"outbound": True, "protocol": Protocol.TCP, "local_port": 50000, "remote_port": 3389,
                            "remote_ip": "198.51.100.7", "remote_host": ""}
    return Packet(**{**base, **over})


def crit(r: RuleView, p: Packet, name: str, *, reply: bool = False, host_ip: str = HOST_IP) -> Tri:
    m = match_rule(r, p, ZONES, host_ip, reply=reply)
    return next(c.result for c in m.criteria if c.name == name)


# --- направление -------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("code", "outbound", "expected"), [
    (0, False, Tri.YES), (0, True, Tri.NO), (1, True, Tri.YES), (1, False, Tri.NO),
])
def test_packet_rule_by_packet_direction(code: int, outbound: bool, expected: Tri) -> None:
    assert crit(rule(direction=code), packet(outbound=outbound), "direction") is expected


@pytest.mark.parametrize(("code", "outbound", "expected"), [
    (3, False, Tri.YES), (3, True, Tri.NO), (4, True, Tri.YES), (4, False, Tri.NO),
])
def test_stream_rule_by_connection_direction(code: int, outbound: bool, expected: Tri) -> None:
    assert crit(rule(direction=code), packet(outbound=outbound), "direction") is expected


@pytest.mark.parametrize("reply", [False, True])
@pytest.mark.parametrize("outbound", [False, True])
def test_both_directions_rule_always_matches(outbound: bool, reply: bool) -> None:
    assert crit(rule(direction=2), packet(outbound=outbound), "direction", reply=reply) is Tri.YES


def test_rule_without_direction_matches_with_note() -> None:
    m = match_rule(rule(direction=None), packet(), ZONES, HOST_IP)
    c = next(c for c in m.criteria if c.name == "direction")
    assert c.result is Tri.YES and c.text == "направление не задано"


def test_unknown_direction_code_is_maybe() -> None:
    assert crit(rule(direction=9), packet(), "direction") is Tri.MAYBE


# --- протокол ----------------------------------------------------------------------------------------------------------

def test_any_protocol_matches() -> None:
    assert crit(rule(protocol=None), packet(protocol=Protocol.UDP), "protocol") is Tri.YES


def test_protocol_by_equality() -> None:
    m = match_rule(rule(protocol=Protocol.TCP), packet(protocol=Protocol.TCP), ZONES, HOST_IP)
    assert next(c.text for c in m.criteria if c.name == "protocol") == "TCP = TCP"
    assert crit(rule(protocol=Protocol.TCP), packet(protocol=Protocol.UDP), "protocol") is Tri.NO


def test_packet_without_protocol_against_specific_rule_is_maybe() -> None:
    assert crit(rule(protocol=Protocol.TCP), packet(protocol=None), "protocol") is Tri.MAYBE


# --- порты -------------------------------------------------------------------------------------------------------------

def test_empty_port_lists_match_any() -> None:
    m = match_rule(rule(), packet(), ZONES, HOST_IP)
    assert {c.name: c.result for c in m.criteria}["local_ports"] is Tri.YES
    assert {c.name: c.result for c in m.criteria}["remote_ports"] is Tri.YES


@pytest.mark.parametrize(("port", "expected"), [(1540, Tri.YES), (1591, Tri.YES), (1560, Tri.YES), (1539, Tri.NO),
                                                (1592, Tri.NO), (3389, Tri.YES)])
def test_port_ranges_inclusive(port: int, expected: Tri) -> None:
    r = rule(remote_ports=((1540, 1591), (3389, 3389)))
    assert crit(r, packet(remote_port=port), "remote_ports") is expected


def test_remote_port_text_shows_both_values() -> None:
    m = match_rule(rule(remote_ports=((1540, 1591),)), packet(remote_port=3389), ZONES, HOST_IP)
    assert next(c.text for c in m.criteria if c.name == "remote_ports") == "уд. порт 3389 ∉ 1540-1591"


def test_local_ports_checked_against_local_port() -> None:
    assert crit(rule(local_ports=((50000, 50010),)), packet(local_port=50005), "local_ports") is Tri.YES
    assert crit(rule(local_ports=((80, 80),)), packet(local_port=50005), "local_ports") is Tri.NO


def test_packet_without_port_against_port_list_is_maybe() -> None:
    assert crit(rule(remote_ports=((53, 53),)), packet(remote_port=None), "remote_ports") is Tri.MAYBE


# --- адрес -------------------------------------------------------------------------------------------------------------

def test_rule_without_addresses_matches_any() -> None:
    assert crit(rule(), packet(remote_ip=None), "address") is Tri.YES


@pytest.mark.parametrize(("ip", "expected"), [("198.51.100.7", Tri.YES), ("198.51.101.7", Tri.NO)])
def test_address_by_network(ip: str, expected: Tri) -> None:
    r = rule(remote=(Address(ip="198.51.100.0", mask=24),))
    assert crit(r, packet(remote_ip=ip), "address") is expected


def test_address_network_text() -> None:
    m = match_rule(rule(remote=(Address(ip="198.51.100.0", mask=24),)), packet(), ZONES, HOST_IP)
    assert next(c.text for c in m.criteria if c.name == "address") == "адрес 198.51.100.7 ∈ 198.51.100.0/24"


def test_single_address_without_mask() -> None:
    r = rule(remote=(Address(ip="198.51.100.7"),))
    assert crit(r, packet(remote_ip="198.51.100.7"), "address") is Tri.YES
    assert crit(r, packet(remote_ip="198.51.100.8"), "address") is Tri.NO


def test_address_ips_any_of_them() -> None:
    r = rule(remote=(Address(ips=(Address(ip="203.0.113.1"), Address(ip="203.0.113.2"))),))
    assert crit(r, packet(remote_ip="203.0.113.2"), "address") is Tri.YES
    assert crit(r, packet(remote_ip="203.0.113.3"), "address") is Tri.NO


def test_host_with_ips_matched_by_ips_not_by_name() -> None:
    r = rule(remote=(Address(host="srv.example.test", ips=(Address(ip="203.0.113.1"),)),))
    assert crit(r, packet(remote_ip="203.0.113.1", remote_host=""), "address") is Tri.YES
    assert crit(r, packet(remote_ip="203.0.113.9", remote_host="srv.example.test"), "address") is Tri.NO


@pytest.mark.parametrize(("rule_host", "remote_host", "expected"), [
    ("SRV.example.test", "srv.example.test", Tri.YES),
    ("srv", "srv.example.test", Tri.YES),
    ("srv.example.test", "SRV", Tri.YES),
    ("srv.example.test", "other.example.test", Tri.NO),
    ("srv.example.test", "srv.other.test", Tri.NO),
])
def test_host_name_case_insensitive_with_and_without_fqdn(rule_host: str, remote_host: str, expected: Tri) -> None:
    r = rule(remote=(Address(host=rule_host),))
    assert crit(r, packet(remote_ip="203.0.113.1", remote_host=remote_host), "address") is expected


def test_host_name_without_remote_host_is_maybe() -> None:
    m = match_rule(rule(remote=(Address(host="srv.example.test"),)), packet(remote_host=""), ZONES, HOST_IP)
    assert m.result is Tri.MAYBE
    assert "имя узла" in m.assumption and "srv.example.test" in m.assumption


@pytest.mark.parametrize("hidden", ["secret", "unparsed"])
def test_hidden_address_is_maybe(hidden: str) -> None:
    m = match_rule(rule(remote=(Address(hidden=hidden),)), packet(), ZONES, HOST_IP)
    assert m.result is Tri.MAYBE
    assert ("адрес скрыт" if hidden == "secret" else "адрес не разобран") in m.assumption


def test_hidden_address_in_host_ips_is_maybe() -> None:
    r = rule(remote=(Address(ips=(Address(ip="203.0.113.1"), Address(hidden="secret"))),))
    assert crit(r, packet(remote_ip="203.0.113.9"), "address") is Tri.MAYBE
    assert crit(r, packet(remote_ip="203.0.113.1"), "address") is Tri.YES


@pytest.mark.parametrize(("ip", "expected"), [("198.51.100.7", Tri.YES), ("203.0.113.7", Tri.NO)])
def test_zone_by_networks_code(ip: str, expected: Tri) -> None:
    assert crit(rule(networks=1), packet(remote_ip=ip), "address") is expected


def test_zone_or_address_any_of_them() -> None:
    r = rule(networks=2, remote=(Address(ip="198.51.100.7"),))
    assert crit(r, packet(remote_ip="198.51.100.7"), "address") is Tri.YES
    assert crit(r, packet(remote_ip="203.0.113.7"), "address") is Tri.YES
    assert crit(r, packet(remote_ip="198.51.100.8"), "address") is Tri.NO


def test_unknown_zone_is_maybe() -> None:
    m = match_rule(rule(networks=1), packet(remote_ip="192.0.2.77"), ZONES, HOST_IP)
    assert m.result is Tri.MAYBE
    assert m.assumption == "зона адреса 192.0.2.77 неизвестна"


def test_ip_version_mismatch_is_no() -> None:
    r = rule(remote=(Address(ip="198.51.100.0", mask=24),))
    m = match_rule(r, packet(remote_ip="2001:db8::1"), ZONES, HOST_IP)
    c = next(c for c in m.criteria if c.name == "address")
    assert c.result is Tri.NO and "другая версия IP" in c.text


def test_ipv6_network() -> None:
    r = rule(remote=(Address(ip="2001:db8::", mask=32),))
    assert crit(r, packet(remote_ip="2001:db8::1"), "address") is Tri.YES


def test_unknown_remote_ip_against_addresses_is_maybe() -> None:
    m = match_rule(rule(remote=(Address(ip="198.51.100.7"),)), packet(remote_ip=None), ZONES, HOST_IP)
    assert m.result is Tri.MAYBE
    assert "адрес назначения не задан" in m.assumption


def test_local_addresses_against_host_ip() -> None:
    r = rule(local=(Address(ip="192.0.2.0", mask=28),))
    assert crit(r, packet(), "local_address", host_ip="192.0.2.10") is Tri.YES
    assert crit(r, packet(), "local_address", host_ip="192.0.2.200") is Tri.NO
    assert crit(r, packet(), "local_address", host_ip="") is Tri.MAYBE
    assert crit(rule(), packet(), "local_address", host_ip="") is Tri.YES


# --- вид ICMP ----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("rule_type", "packet_type", "expected"), [
    (None, 8, Tri.YES), (8, 8, Tri.YES), (8, 0, Tri.NO), (8, None, Tri.YES),
])
def test_icmp_type(rule_type: int | None, packet_type: int | None, expected: Tri) -> None:
    r = rule(protocol=Protocol.ICMP, icmp_type=rule_type)
    assert crit(r, packet(protocol=Protocol.ICMP, icmp_type=packet_type, local_port=None, remote_port=None), "icmp_type") is expected


def test_icmp_type_not_given_in_packet_is_noted() -> None:
    m = match_rule(rule(protocol=Protocol.ICMP, icmp_type=8), packet(protocol=Protocol.ICMP, icmp_type=None), ZONES, HOST_IP)
    assert next(c.text for c in m.criteria if c.name == "icmp_type") == "вид ICMP 8 не проверялся"


# --- нечитаемые критерии -----------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("marker", "name", "scope"), [
    ("direction", "direction", {}),
    ("protocol", "protocol", {}),
    ("ports", "remote_ports", {"remote_ports": ((80, 80),)}),
    ("networks", "address", {}),
    ("mask", "address", {"remote": (Address(ip="198.51.100.0"),)}),
    ("icmp_type", "icmp_type", {"protocol": Protocol.ICMP}),
])
def test_unread_criterion_is_maybe(marker: str, name: str, scope: dict[str, Any]) -> None:
    p = packet(protocol=Protocol.ICMP, icmp_type=8) if marker == "icmp_type" else packet(remote_port=3389)
    r = rule(unread=(marker,), **scope)
    assert crit(r, p, name) is Tri.MAYBE
    assert match_rule(r, p, ZONES, HOST_IP).result is Tri.MAYBE


def test_unread_ports_with_matching_pair_is_yes() -> None:
    assert crit(rule(unread=("ports",), remote_ports=((3389, 3389),)), packet(remote_port=3389), "remote_ports") is Tri.YES


def test_unread_mask_with_exact_address_is_yes() -> None:
    assert crit(rule(unread=("mask",), remote=(Address(ip="198.51.100.7"),)), packet(), "address") is Tri.YES


# --- ответный пакет ----------------------------------------------------------------------------------------------------

def test_reply_packet_swaps_ports_and_direction() -> None:
    # Исходящее соединение 50000 → 3389: ответный пакет входящий, локальные и удалённые порты меняются местами (спека §4.3).
    p = packet(outbound=True, local_port=50000, remote_port=3389)
    r = rule(direction=0, local_ports=((3389, 3389),), remote_ports=((50000, 50000),))
    assert match_rule(r, p, ZONES, HOST_IP, reply=True).result is Tri.YES
    assert match_rule(r, p, ZONES, HOST_IP).result is Tri.NO
    assert crit(rule(direction=1), p, "direction", reply=True) is Tri.NO


@pytest.mark.parametrize("code", [3, 4])
def test_stream_rule_skipped_on_reply(code: int) -> None:
    m = match_rule(rule(direction=code), packet(outbound=code == 3), ZONES, HOST_IP, reply=True)
    c = next(c for c in m.criteria if c.name == "direction")
    assert c.result is Tri.NO and c.text == "правило потока не участвует в ответном пакете"
    assert m.result is Tri.NO and m.almost is None


# --- итог и «почти подошло» --------------------------------------------------------------------------------------------

def test_all_yes_is_yes() -> None:
    r = rule(direction=1, protocol=Protocol.TCP, remote_ports=((3389, 3389),), remote=(Address(ip="198.51.100.0", mask=24),))
    m = match_rule(r, packet(), ZONES, HOST_IP)
    assert m.result is Tri.YES and m.almost is None and m.assumption == ""


def test_no_beats_maybe() -> None:
    m = match_rule(rule(networks=1, protocol=Protocol.UDP), packet(remote_ip="192.0.2.77"), ZONES, HOST_IP)
    assert m.result is Tri.NO and m.almost is None and m.assumption == ""


def test_almost_single_no() -> None:
    r = rule(direction=1, protocol=Protocol.TCP, remote_ports=((1540, 1591),))
    m = match_rule(r, packet(remote_port=3389), ZONES, HOST_IP)
    assert m.result is Tri.NO
    assert m.almost is not None and m.almost.name == "remote_ports"
    assert m.almost.text == "уд. порт 3389 ∉ 1540-1591"


def test_two_no_is_not_almost() -> None:
    m = match_rule(rule(protocol=Protocol.UDP, remote_ports=((1540, 1591),)), packet(remote_port=3389), ZONES, HOST_IP)
    assert m.result is Tri.NO and m.almost is None


def test_no_with_maybe_is_not_almost() -> None:
    m = match_rule(rule(protocol=Protocol.UDP, networks=1), packet(remote_ip="192.0.2.77"), ZONES, HOST_IP)
    assert m.almost is None


def test_disabled_rule_is_no_without_almost() -> None:
    m = match_rule(rule(enabled=False), packet(), ZONES, HOST_IP)
    c = next(c for c in m.criteria if c.name == "enabled")
    assert c.result is Tri.NO and c.text == "правило выключено"
    assert m.result is Tri.NO and m.almost is None
    assert match_rule(rule(enabled=False, protocol=Protocol.UDP), packet(), ZONES, HOST_IP).almost is None


# --- зона адреса -------------------------------------------------------------------------------------------------------

def test_zone_of() -> None:
    assert zone_of("198.51.100.7", ZONES) == 1
    assert zone_of("203.0.113.7", ZONES) == 2
    assert zone_of("192.0.2.7", ZONES) is None
    assert zone_of("2001:db8::1", ZONES) is None
    assert zone_of("198.51.100.7", (ZoneView("Тестовая скрытая", 0, None),)) is None


def test_hidden_zone_of_rule_kind_makes_no_into_maybe() -> None:
    zones = ZONES + (ZoneView("Тестовая скрытая", 1, None),)
    m = match_rule(rule(networks=1), packet(remote_ip="203.0.113.7"), zones, HOST_IP)
    assert m.result is Tri.MAYBE
