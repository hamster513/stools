"""Правила в тени и дубли (спека §4.6): более раннее включённое правило того же слоя полностью покрывает позднее."""
from __future__ import annotations

from typing import Any

import pytest

from api.modules.ksc.core.firewall.model import Protocol, RuleView
from api.modules.ksc.core.firewall.shadow import Shadow, covers, shadows
from api.modules.ksc.core.policy_model import Address, Scope


def rule(row_id: int = 1, *, position: int | None = None, action: str = "разрешить", enabled: bool = True,
         layer: str = "packet", **scope: Any) -> RuleView:
    return RuleView(row_id=row_id, policy_id=1, profile="", layer=layer, position=row_id if position is None else position,
                    name=f"Тестовое правило {row_id}", action=action, enabled=enabled, scope=Scope(**scope), direction_text="",
                    protocol_text="", local_ports_text="", remote_ports_text="", addresses_text="")


def net(cidr: str) -> Address:
    ip, _, mask = cidr.partition("/")
    return Address(ip=ip, mask=int(mask) if mask else None)


# --- шаги брифа ----------------------------------------------------------------------------------------------------------

def test_wider_cidr_shadows() -> None:
    wide = rule(1, action="запретить", remote=(net("198.51.100.0/24"),))
    narrow = rule(2, remote=(net("198.51.100.0/28"),))
    assert shadows([wide, narrow]) == {2: Shadow(by_row_id=1, by_position=1, by_name="Тестовое правило 1", same_action=False)}
    # Обратное не верно: узкая сеть не покрывает широкую.
    assert shadows([narrow, rule(3, remote=(net("198.51.100.0/24"),))]) == {}


def test_same_action_is_duplicate() -> None:
    first = rule(1, protocol=Protocol.TCP, remote_ports=((3389, 3389),))
    second = rule(2, protocol=Protocol.TCP, remote_ports=((3389, 3389),))
    assert shadows([first, second])[2].same_action is True
    assert 1 not in shadows([first, second])


def test_disabled_rule_does_not_shadow() -> None:
    off = rule(1, enabled=False)
    later = rule(2, remote=(net("203.0.113.5"),))
    assert shadows([off, later]) == {}
    # Выключенное позднее правило в тени бывает.
    assert shadows([rule(1), rule(2, enabled=False)])[2].by_row_id == 1


def test_zone_vs_cidr_not_covered() -> None:
    zone = rule(1, networks=1)
    cidr = rule(2, remote=(net("198.51.100.0/24"),))
    assert not covers(zone, cidr)
    assert not covers(cidr, zone)
    assert covers(zone, rule(3, networks=1))
    assert not covers(zone, rule(4, networks=2))


def test_ports_subset() -> None:
    outer = rule(1, local_ports=((1000, 2000), (3000, 3000)))
    assert covers(outer, rule(2, local_ports=((1500, 1600), (3000, 3000))))
    assert not covers(outer, rule(3, local_ports=((1500, 2500),)))
    # Пустой список — любой порт: не внутри заданных пар, но покрывает любые.
    assert not covers(outer, rule(4))
    assert covers(rule(5), rule(6, remote_ports=((80, 80),)))


def test_layer_separation() -> None:
    packet = rule(1, layer="packet")
    app = rule(2, layer="app")
    assert shadows([packet, app]) == {}
    assert not covers(packet, app)


# --- критерии покрытия ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize(("outer", "inner", "expected"), [
    (None, 0, True), (2, 3, True), (2, None, True), (0, 0, True),
    (0, 2, False), (0, None, False), (3, 1, False), (1, 4, False),
])
def test_direction(outer: int | None, inner: int | None, expected: bool) -> None:
    assert covers(rule(1, direction=outer), rule(2, direction=inner)) is expected


def test_protocol_and_icmp_type() -> None:
    assert covers(rule(1), rule(2, protocol=Protocol.UDP))
    assert not covers(rule(1, protocol=Protocol.TCP), rule(2))
    assert not covers(rule(1, protocol=Protocol.TCP), rule(2, protocol=Protocol.UDP))
    icmp = {"protocol": Protocol.ICMP}
    assert covers(rule(1, **icmp), rule(2, icmp_type=8, **icmp))
    assert covers(rule(1, icmp_type=8, **icmp), rule(2, icmp_type=8, **icmp))
    assert not covers(rule(1, icmp_type=8, **icmp), rule(2, icmp_type=0, **icmp))
    assert not covers(rule(1, icmp_type=8, **icmp), rule(2, **icmp))


def test_addresses_by_ips_and_names() -> None:
    outer = rule(1, remote=(net("198.51.100.0/24"), Address(host="srv.example.test")))
    resolved = Address(host="web.example.test", ips=(Address(ip="198.51.100.7"), Address(ip="198.51.100.8")))
    assert covers(outer, rule(2, remote=(resolved,)))
    partly = Address(host="web.example.test", ips=(Address(ip="198.51.100.7"), Address(ip="203.0.113.8")))
    assert not covers(outer, rule(3, remote=(partly,)))
    assert covers(outer, rule(4, remote=(Address(host="SRV.example.test"),)))
    assert not covers(outer, rule(5, remote=(Address(host="other.example.test"),)))
    # Любой адрес не покрывается заданным.
    assert not covers(outer, rule(6))
    # Разные версии IP.
    assert not covers(rule(7, remote=(net("2001:db8::/32"),)), rule(8, remote=(net("198.51.100.1"),)))
    assert covers(rule(9, remote=(net("2001:db8::/32"),)), rule(10, remote=(net("2001:db8:1::/48"),)))


def test_hidden_and_unread_never_cover() -> None:
    hidden = Address(hidden="secret")
    assert not covers(rule(1, remote=(net("198.51.100.0/24"), hidden)), rule(2, remote=(net("198.51.100.1"),)))
    assert not covers(rule(1), rule(2, remote=(hidden,)))
    assert not covers(rule(1, unread=("ports",)), rule(2, remote_ports=((80, 80),)))
    assert not covers(rule(1), rule(2, unread=("direction",)))


def test_local_addresses() -> None:
    outer = rule(1, local=(net("192.0.2.0/24"),))
    assert covers(outer, rule(2, local=(net("192.0.2.10"),)))
    assert not covers(outer, rule(3))
    assert covers(rule(4), rule(5, local=(net("192.0.2.10"),)))
    assert not covers(outer, rule(6, local=(net("203.0.113.1"),)))


def test_first_earlier_rule_wins_and_order_is_kept() -> None:
    rules = [rule(1, remote=(net("198.51.100.0/24"),)), rule(2), rule(3, remote=(net("198.51.100.9"),))]
    found = shadows(rules)
    assert found[3].by_row_id == 1
    assert 2 not in found
    # Порядок не пересортировывается по `position`: «раньше» — раньше в последовательности.
    assert shadows([rule(5, position=9), rule(6, position=1)])[6].by_position == 9
