"""Представление сетевого экрана хоста: политика KES хоста, профили по активации и замкам листов HIPS, зоны сетей,
состояние экрана и компонента, оговорки."""
from __future__ import annotations

import ipaddress
from typing import Any

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import delete, update
from sqlalchemy.orm import Session

from api.modules.ksc.core.firewall.model import ZoneView
from api.modules.ksc.core.firewall.view import Source, host_firewall
from api.modules.ksc.core.policy_model import Address, FirewallSettings, Locks, NetworkZone, Scope
from api.modules.ksc.models import KscNetRule, KscPolicyFirewall
from api.modules.ksc.services.firewall import load_host_firewall
from tests.ksc.kes11 import TCP, kes11_export, kes11_sections, octets, packet_rule
from tests.ksc.synthetic import (
    _lock,
    activation,
    add_inactive_policy,
    condition_group,
    tag_condition,
)
from tests.ksc.test_api import upload
from tests.ksc.test_firewall_settings import _APP, _NETWORKS, _PACKET, _set_lock

RULES = "cf9370d5/firewall.networkPacketRules"
ZONES = "cf9370d5/firewall.availableNetworks"
PROFILE_RULE = packet_rule("Тестовое правило профиля", action=0, direction=2, protocol=TCP, remote_ports=[{"begin": 443, "end": 443}])
#: Условие не по тегам — активацию профиля не определить.
UNDETERMINED = activation(condition_group({"OP": 7, "name": "NGTPP_sNlaLocation", "val": "Office"}))


def _sections(over: dict[str, Any] | None = None, locks: dict[str, bool | None] | None = None,
              component: bool | None = True) -> dict[str, Any]:
    """`kes11_sections(**over)` для профиля: в синтетике листья HIPS замкнуты, `locks` меняет замок листа (None — признака
    нет); компонент Firewall выключен флагом `KLPRSS_Components` с замком `component` (None — без признака замка, как у
    `P_NOTEBOOKS` синтетики при True)."""
    sections = kes11_sections(**(over or {}))
    for path, locked in (locks or {}).items():
        _set_lock(sections, path, locked)
    sections["KLPRSS_Components"] = {"KLPRSS_Val": {"Firewall": {"KLPRSS_Val": {"Enabled": _lock(False, locked=component)}}}}
    return sections


def _export(*, over: dict[str, Any] | None = None, locks: dict[str, bool | None] | None = None,
            expression: dict[str, Any] | None = None, component: bool | None = True) -> dict[str, Any]:
    """`kes11_export()`, где у профиля «Ноутбуки» политики 1 (условие — тег VIP, он есть у WS01, у WS02 нет) секции —
    `_sections(over, locks, component)`."""
    raw = kes11_export()
    sections = _sections(over, locks, component)
    profiles = raw["policy_profiles"]["1"]["profiles"]
    assert profiles[0]["name"] == "Ноутбуки"
    attrs = profiles[0]["attrs"] if expression is None else {**profiles[0]["attrs"], "EXPRESSION": {"type": "params", "value": expression}}
    profiles[0] = {**profiles[0], "attrs": attrs, "sections": sections}
    return raw


def _upload(client: TestClient, raw: dict[str, Any]) -> int:
    assert upload(client, raw)["status"] == "done"
    return int(client.get("/api/ksc/snapshots").json()[0]["id"])


def test_view_policy_and_active_profile(auth_client: TestClient, db_session: Session) -> None:
    """WS01: политика 1 и активный профиль «Ноутбуки» со своим списком под замком; профиль выключает компонент Firewall
    под замком — экран выключен, с оговоркой. WS02 (без тега): профиль не действует."""
    sid = _upload(auth_client, _export(over={RULES: [PROFILE_RULE]}))
    fw = load_host_firewall(db_session, sid, "h-ws01")
    assert (fw.host_id, fw.host_name, fw.policy_id, fw.policy_name) == ("h-ws01", "WS01", 1, "KES workstations")
    assert fw.packet is not None and (fw.packet.policy_id, fw.packet.profile, fw.packet.priority, fw.packet.locked) == (1, "", None, True)
    assert len(fw.packet.rules) == 5 and [r.position for r in fw.packet.rules] == [0, 1, 2, 3, 4]
    first = fw.packet.rules[0]
    row = db_session.get(KscNetRule, first.row_id)
    assert row is not None and (row.policy_id, row.profile, row.layer, row.name) == (1, "", "packet", first.name)
    assert first.scope == Scope(networks=2, direction=3, protocol=TCP, local_ports=((3389, 3389),))
    assert (first.action, first.enabled, first.direction_text, first.protocol_text, first.local_ports_text, first.remote_ports_text,
            first.addresses_text) == (row.action, True, row.direction, row.protocol, row.local_ports, row.remote_ports, row.addresses)
    assert [(s.policy_id, s.profile, s.priority, s.locked, [r.name for r in s.rules]) for s in fw.packet_profiles] == [
        (1, "Ноутбуки", 0, True, ["Тестовое правило профиля"])]
    assert fw.packet_undetermined == ()
    assert fw.app is not None and fw.app.rules and all(r.layer == "app" for r in fw.app.rules)
    assert [s.profile for s in fw.app_profiles] == ["Ноутбуки"] and fw.app_undetermined == ()
    assert (fw.firewall_enabled, fw.notify_only, fw.hips_enabled, fw.hips_notify_only) == (False, False, True, False)
    assert [g.name for g in fw.trust_groups] == ["Тестовая группа"]
    assert fw.component_running is True and fw.notes == ("компонент „Сетевой экран“ выключен профилем „Ноутбуки“",)
    other = load_host_firewall(db_session, sid, "h-ws02")
    assert other.policy_id == 1 and other.packet_profiles == () and other.app_profiles == () and other.packet_undetermined == ()
    assert other.firewall_enabled is True and other.notes == ()


def test_view_profile_without_lock_ignored(auth_client: TestClient, db_session: Session) -> None:
    """Профиль без замка на листе (копия настроек политики) список и состояние политики не перекрывает."""
    sid = _upload(auth_client, _export(over={RULES: [PROFILE_RULE], "cf9370d5/firewall.enabled": False},
                                       locks={_PACKET: None, _APP: False}, component=None))
    fw = load_host_firewall(db_session, sid, "h-ws01")
    assert fw.packet_profiles == () and fw.app_profiles == () and fw.firewall_enabled is True and fw.notes == ()


def test_view_undetermined_profile_listed_separately(auth_client: TestClient, db_session: Session) -> None:
    sid = _upload(auth_client, _export(over={RULES: [PROFILE_RULE], "cf9370d5/firewall.enabled": False}, expression=UNDETERMINED))
    fw = load_host_firewall(db_session, sid, "h-ws01")
    assert fw.packet_profiles == () and [(s.profile, s.priority, s.locked) for s in fw.packet_undetermined] == [("Ноутбуки", 0, True)]
    assert [r.name for r in fw.packet_undetermined[0].rules] == ["Тестовое правило профиля"]
    assert fw.app_profiles == () and [s.profile for s in fw.app_undetermined] == ["Ноутбуки"]
    # Неопределённый профиль ничего не перекрывает: зоны и состояние — политики, перекрытие зон — оговоркой.
    assert [z.name for z in fw.zones] == ["Тестовая сеть"] and fw.firewall_enabled is True
    assert fw.notes == ("зоны сетей могут перекрываться профилем „Ноутбуки“ (активация не определена)",
                        "состояние сетевого экрана может перекрываться профилем „Ноутбуки“ (активация не определена)",
                        "компонент Firewall может быть выключен профилем „Ноутбуки“ (активация не определена)")


def test_view_zones_from_locked_profile(auth_client: TestClient, db_session: Session) -> None:
    """Зоны — профиля с замком на листе зон (независимо от замка пакетных правил); адрес без маски — один узел, нечитаемый —
    без сети."""
    zones = [
        {"address": {"mask": 24, "octets": octets("198.51.100.0"), "zoneIPv6": ""}, "name": "Тестовая сеть профиля", "type": 1},
        {"address": {"octets": octets("203.0.113.7"), "zoneIPv6": ""}, "name": "Тестовый узел", "type": 0},
        {"address": {"mask": 64, "octets": octets("2001:db8::"), "zoneIPv6": ""}, "name": "Тестовая сеть IPv6", "type": 1},
        {"address": {"octets": {"type": "binary", "value": "AAA="}}, "name": "Тестовая зона без адреса", "type": 2},
    ]
    sid = _upload(auth_client, _export(over={ZONES: zones}, locks={_PACKET: None, _NETWORKS: True}, component=None))
    fw = load_host_firewall(db_session, sid, "h-ws01")
    assert fw.zones == (
        ZoneView("Тестовая сеть профиля", 1, ipaddress.ip_network("198.51.100.0/24")),
        ZoneView("Тестовый узел", 0, ipaddress.ip_network("203.0.113.7/32")),
        ZoneView("Тестовая сеть IPv6", 1, ipaddress.ip_network("2001:db8::/64")),
        ZoneView("Тестовая зона без адреса", 2, None),
    )
    assert fw.packet_profiles == () and fw.notes == ()
    other = load_host_firewall(db_session, sid, "h-ws02")
    assert other.zones == (ZoneView("Тестовая сеть", 2, ipaddress.ip_network("192.0.2.0/24")),)


def test_view_component_status_unknown_without_components(auth_client: TestClient, db_session: Session) -> None:
    """WS05 без продукта защиты — компонентов нет: статус неизвестен; WS11 — Firewall выключен; WS01 — работает."""
    sid = _upload(auth_client, kes11_export())
    assert load_host_firewall(db_session, sid, "h-ws05").component_running is None
    assert load_host_firewall(db_session, sid, "h-ws11").component_running is False
    assert load_host_firewall(db_session, sid, "h-ws01").component_running is True


def test_view_component_disabled_in_policy(auth_client: TestClient, db_session: Session) -> None:
    """Компонент Firewall выключен флагом политики — экран выключен, с оговоркой."""
    raw = kes11_export()
    raw["policy_contents"]["1"]["sections"]["KLPRSS_Components"] = {
        "KLPRSS_Val": {"Firewall": {"KLPRSS_Val": {"Enabled": _lock(False, locked=True)}}}}
    sid = _upload(auth_client, raw)
    fw = load_host_firewall(db_session, sid, "h-ws02")
    assert fw.firewall_enabled is False and fw.notes == ("компонент „Сетевой экран“ выключен в политике",)


def test_view_no_kes_policy(auth_client: TestClient, db_session: Session) -> None:
    """SRV01: у группы только политика агента."""
    sid = _upload(auth_client, kes11_export())
    fw = load_host_firewall(db_session, sid, "h-srv01")
    assert (fw.host_name, fw.policy_id, fw.policy_name, fw.packet, fw.app) == ("SRV01", None, "", None, None)
    assert (fw.packet_profiles, fw.packet_undetermined, fw.app_profiles, fw.app_undetermined, fw.zones, fw.trust_groups) == ((),) * 6
    assert (fw.firewall_enabled, fw.notify_only, fw.hips_enabled, fw.hips_notify_only) == (None,) * 4
    assert fw.notes == ("политики KES у хоста нет",)


def test_view_inactive_kes_policy_noted(auth_client: TestClient, db_session: Session) -> None:
    """Неактивная политика KES у группы (например, для автономных пользователей) не проверяется — оговоркой."""
    raw = add_inactive_policy(kes11_export())
    raw["effective_policies"]["2"].append(dict(raw["policies"][-1], KLPOL_INHERITED=True))
    sid = _upload(auth_client, raw)
    fw = load_host_firewall(db_session, sid, "h-ws02")
    assert fw.policy_id == 1
    assert fw.notes == ("политика для автономных пользователей / неактивная политика не проверялась",)


def test_view_unknown_host(auth_client: TestClient, db_session: Session) -> None:
    sid = _upload(auth_client, kes11_export())
    with pytest.raises(HTTPException) as e:
        load_host_firewall(db_session, sid, "nope")
    assert e.value.status_code == 404


ZONE_A = [{"address": {"mask": 24, "octets": octets("198.51.100.0"), "zoneIPv6": ""}, "name": "Тестовая сеть A", "type": 1}]
SECOND = "Тестовый профиль бухгалтерии"


def test_view_two_active_profiles(auth_client: TestClient, db_session: Session) -> None:
    """Два активных профиля политики 1 (на WS01 оба тега): списки по приоритету, а не по порядку в выгрузке; зоны — у лучшего
    по приоритету профиля с замком зон; флаг экрана — у лучшего по приоритету профиля, где он задан."""
    raw = _export(over={RULES: [PROFILE_RULE], "cf9370d5/firewall.enabled": False}, locks={_NETWORKS: None}, component=None)
    second_rule = packet_rule("Тестовое правило второго профиля", action=1, direction=2, protocol=TCP)
    second = {"name": SECOND, "attrs": {"KLSSPOL_PRF_ENABLED": True,
                                        "EXPRESSION": {"type": "params", "value": activation(condition_group(tag_condition("Бухгалтерия")))}},
              "sections": _sections({RULES: [second_rule], ZONES: ZONE_A}, component=None), "errors": []}
    pp = raw["policy_profiles"]["1"]
    pp["profiles"].insert(0, second)
    pp["priorities"] = ["Ноутбуки", SECOND, "Выключенный"]
    sid = _upload(auth_client, raw)
    fw = load_host_firewall(db_session, sid, "h-ws01")
    assert [(s.profile, s.priority, [r.name for r in s.rules]) for s in fw.packet_profiles] == [
        ("Ноутбуки", 0, ["Тестовое правило профиля"]), (SECOND, 1, ["Тестовое правило второго профиля"])]
    assert [s.profile for s in fw.app_profiles] == ["Ноутбуки", SECOND]
    assert fw.zones == (ZoneView("Тестовая сеть A", 1, ipaddress.ip_network("198.51.100.0/24")),)
    assert fw.firewall_enabled is False and fw.notes == ()


def _fw(*, enabled: bool | None = None, zone: str = "", networks: bool | None = None, packet: bool | None = None,
        component: bool | None = None, component_enabled: bool | None = None) -> FirewallSettings:
    zones = (NetworkZone(zone, 1, Address(ip="192.0.2.0", mask=24)),) if zone else ()
    return FirewallSettings(enabled=enabled, notify_only=None, hips_enabled=None, hips_notify_only=None, zones=zones, app_groups=(),
                            locks=Locks(packet=packet, networks=networks, app=None, component=component), component_enabled=component_enabled)


def _view(*profiles: Source) -> tuple[list[str], tuple[str, ...], bool | None]:
    policy = Source("", None, True, _fw(enabled=True, zone="Политика"), (), ())
    fw = host_firewall("h", "H", "192.0.2.1", 1, "Тестовая политика", policy, list(profiles), [], [])
    return [z.name for z in fw.zones], fw.notes, fw.firewall_enabled


def test_view_zones_and_notes_by_priority() -> None:
    """Зоны — лучший по приоритету активный профиль с замком зон; неопределённый профиль выше него — оговорка, ниже — нет.
    То же для флагов экрана и компонента."""
    above = Source("Выше", 0, None, _fw(zone="Выше", networks=True, enabled=True, packet=True, component=True, component_enabled=False), (), ())
    zonal = Source("Зоновый", 1, True, _fw(zone="Зоновый", networks=True, enabled=False, packet=True), (), ())
    below = Source("Ниже", 2, None, _fw(zone="Ниже", networks=True, enabled=True, packet=True), (), ())
    worse = Source("Хуже", 3, True, _fw(zone="Хуже", networks=True, enabled=True, packet=True), (), ())
    zones, notes, enabled = _view(worse, below, zonal, above)
    assert zones == ["Зоновый"] and enabled is False
    assert notes == ("зоны сетей могут перекрываться профилем „Выше“ (активация не определена)",
                     "состояние сетевого экрана может перекрываться профилем „Выше“ (активация не определена)",
                     "компонент Firewall может быть выключен профилем „Выше“ (активация не определена)")
    # Профиль с тем же значением флага — без оговорки; без активного профиля с замком — зоны политики.
    same = Source("Тот же", 0, None, _fw(enabled=True, packet=True), (), ())
    assert _view(same) == (["Политика"], (), True)


def test_view_no_scope_note_only_for_used_rules(auth_client: TestClient, db_session: Session) -> None:
    """Правило без структуры адресов даёт оговорку, только если оно в действующих или неопределённых списках."""
    sid = _upload(auth_client, _export(over={RULES: [PROFILE_RULE]}, locks={_PACKET: None}, component=None))
    unused = (KscNetRule.snapshot_id == sid) & (KscNetRule.profile == "Ноутбуки") & (KscNetRule.layer == "packet")
    db_session.execute(update(KscNetRule).where(unused).values(scope_json=None))
    db_session.commit()
    assert load_host_firewall(db_session, sid, "h-ws01").notes == ()
    used = (KscNetRule.snapshot_id == sid) & (KscNetRule.profile == "") & (KscNetRule.position == 0) & (KscNetRule.layer == "packet")
    db_session.execute(update(KscNetRule).where(used).values(scope_json=None))
    db_session.commit()
    fw = load_host_firewall(db_session, sid, "h-ws01")
    assert fw.notes == ("правило без структуры адресов",) and fw.packet is not None and fw.packet.rules[0].scope == Scope()


def test_view_policy_without_firewall_row(auth_client: TestClient, db_session: Session) -> None:
    sid = _upload(auth_client, kes11_export())
    db_session.execute(delete(KscPolicyFirewall).where(KscPolicyFirewall.snapshot_id == sid, KscPolicyFirewall.policy_id == 1,
                                                       KscPolicyFirewall.profile == ""))
    db_session.commit()
    fw = load_host_firewall(db_session, sid, "h-ws02")
    assert (fw.firewall_enabled, fw.notify_only, fw.hips_enabled, fw.hips_notify_only, fw.zones, fw.trust_groups) == (None,) * 4 + ((), ())
    assert fw.packet is not None and fw.packet.locked is None and len(fw.packet.rules) == 5
    assert fw.notes == ("настроек сетевого экрана у политики нет в выгрузке",)
