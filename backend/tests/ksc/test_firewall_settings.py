"""Состояние сетевого экрана и HIPS, зоны сетей, группы доверия и замки листов из секции HIPS политики или профиля KES."""
from __future__ import annotations

from typing import Any

from api.modules.ksc.core.extractors.kes_windows import HIPS, TRUSTED_ZONE, extract_kes
from api.modules.ksc.core.policy_model import (
    AccessRule,
    Address,
    AppGroupDefault,
    FirewallSettings,
    Locks,
    NetworkZone,
    firewall_to_json,
)
from tests.ksc.kes11 import kes11_sections

#: Листья секции HIPS, замки которых читает извлекатель.
_PACKET, _NETWORKS, _APP = "firewall.networkPacketRules", "firewall.availableNetworks", "hips.appGroups"


def _set_lock(sections: dict[str, Any], path: str, locked: bool | None) -> None:
    """Меняет признак замка `KLPRSS_Mnd` в контейнере листа `path` секции HIPS (форма `container="leaf"`):
    None — признак убирается (как в профиле, где замок не задан), bool — ставится это значение."""
    node = sections[HIPS]
    for key in path.split("."):
        node = node[key]
    node.pop("KLPRSS_Mnd", None)
    if locked is not None:
        node["KLPRSS_Mnd"] = locked


def _firewall(sections: dict[str, Any]) -> FirewallSettings:
    fw = extract_kes(sections).firewall
    assert fw is not None
    return fw


def test_firewall_settings_from_fixture() -> None:
    fw = _firewall(kes11_sections())
    assert fw.enabled is True and fw.notify_only is False and fw.hips_enabled is True and fw.hips_notify_only is False
    assert fw.zones == (NetworkZone(name="Тестовая сеть", kind=2, address=Address(ip="192.0.2.0", mask=24)),)
    assert fw.app_groups == (AppGroupDefault(name="Тестовая группа", parent=0, depth=0,
                                             access=(AccessRule(networks=0, allow=True, inherited=False),)),)
    assert fw.locks == Locks(packet=True, networks=True, app=True)  # фикстура kes11 ставит замки на все листы, кроме _UNLOCKED


def test_firewall_locks_none_without_flag() -> None:
    """Замок каждого листа читается из его контейнера: без `KLPRSS_Mnd` — None, `False` — False, у соседей не меняется."""
    sections = kes11_sections(container="leaf")
    _set_lock(sections, _PACKET, None)
    _set_lock(sections, _NETWORKS, False)
    assert _firewall(sections).locks == Locks(packet=None, networks=False, app=True)


def test_firewall_settings_profile_copy_without_locks() -> None:
    """Профиль — те же значения без замков у трёх листов: значения совпадают с политикой, замки — None."""
    sections = kes11_sections(container="leaf")
    for path in (_PACKET, _NETWORKS, _APP):
        _set_lock(sections, path, None)
    fw, policy = _firewall(sections), _firewall(kes11_sections())
    assert fw.locks == Locks(packet=None, networks=None, app=None)
    assert (fw.enabled, fw.notify_only, fw.hips_enabled, fw.hips_notify_only, fw.zones, fw.app_groups) == (
        policy.enabled, policy.notify_only, policy.hips_enabled, policy.hips_notify_only, policy.zones, policy.app_groups)


def test_firewall_settings_absent_without_hips_section() -> None:
    assert extract_kes({TRUSTED_ZONE: kes11_sections()[TRUSTED_ZONE]}).firewall is None


def test_firewall_json_shape() -> None:
    d = firewall_to_json(_firewall(kes11_sections()))
    assert set(d) == {"enabled", "notify_only", "hips_enabled", "hips_notify_only", "zones", "app_groups", "locks"}
    assert d["zones"] == ({"name": "Тестовая сеть", "kind": 2,
                           "address": {"host": "", "ip": "192.0.2.0", "mask": 24, "ips": (), "hidden": ""}},)
    assert d["app_groups"][0]["access"] == ({"networks": 0, "allow": True, "inherited": False},)
    assert d["locks"] == {"packet": True, "networks": True, "app": True}


def _groups_firewall(groups: list[dict[str, Any]]) -> FirewallSettings:
    over: dict[str, Any] = {f"{HIPS}/{_APP}": groups}
    return _firewall(kes11_sections(**over))


def test_app_group_depth_by_parent() -> None:
    """Глубина по `parent` (номер родителя в списке с 1, 0 — корень): цепочка стандартных групп 0,1,2,3 → глубина 0..3,
    своя группа с `parent` 0 — 0, ссылка вне списка или не int — 0, самоссылка — 1 (обход не зацикливается)."""
    parents: list[Any] = [0, 1, 2, 3, 0, 9, True, 8]
    names = ["А", "Б", "В", "Г", "Своя", "Вне списка", "Не число", "На себя"]
    fw = _groups_firewall([{"name": n, "parent": p} for n, p in zip(names, parents, strict=True)])
    assert [(g.name, g.parent, g.depth, g.access) for g in fw.app_groups] == [
        ("А", 0, 0, ()), ("Б", 1, 1, ()), ("В", 2, 2, ()), ("Г", 3, 3, ()), ("Своя", 0, 0, ()), ("Вне списка", 9, 0, ()),
        ("Не число", None, 0, ()), ("На себя", 8, 1, ())]


def test_app_group_keeps_all_access_rules_in_order() -> None:
    """Все правила `networkAccessRules` группы — в порядке выгрузки; `networks` bool или строка, `allow`/`inherited` не bool — None,
    элемент не словарь пропускается."""
    rules: list[Any] = [
        {"networks": -1, "allow": False, "inherited": False}, {"networks": 0, "allow": False, "inherited": True},
        {"networks": 1, "allow": True, "inherited": True}, {"networks": 2, "allow": False, "inherited": True},
        "мусор", {"networks": True, "allow": 1, "inherited": "да"}, {"networks": "2"},
    ]
    fw = _groups_firewall([{"name": "Группа", "parent": 0, "networkAccessRules": rules}])
    assert fw.app_groups[0].access == (
        AccessRule(networks=-1, allow=False, inherited=False), AccessRule(networks=0, allow=False, inherited=True),
        AccessRule(networks=1, allow=True, inherited=True), AccessRule(networks=2, allow=False, inherited=True),
        AccessRule(networks=None, allow=None, inherited=None), AccessRule(networks=None, allow=None, inherited=None),
    )


def test_firewall_flags_not_bool_are_none() -> None:
    over: dict[str, Any] = {f"{HIPS}/firewall.enabled": 1, f"{HIPS}/hips.notifyOnly": "нет"}
    fw = _firewall(kes11_sections(**over))
    assert (fw.enabled, fw.notify_only, fw.hips_enabled, fw.hips_notify_only) == (None, False, True, None)
