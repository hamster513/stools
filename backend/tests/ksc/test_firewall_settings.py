"""Состояние сетевого экрана и HIPS, зоны сетей, группы доверия и замки листов из секции HIPS политики или профиля KES;
флаги компонентов Firewall и HIPS из `KLPRSS_Components`."""
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
from tests.ksc.synthetic import P_NOTEBOOKS, _lock

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
    assert fw.default_app_group == 1
    # Секции `KLPRSS_Components` в KES 11 нет: флагов компонентов и их замков нет.
    assert (fw.component_enabled, fw.hips_component_enabled, fw.locks.component, fw.locks.hips_component) == (None, None, None, None)


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


def test_firewall_settings_absent_without_hips_section_and_component() -> None:
    """Нет ни секции HIPS, ни флага компонента Firewall — настроек нет; флаг одного HIPS-компонента строку не заводит."""
    assert extract_kes({TRUSTED_ZONE: kes11_sections()[TRUSTED_ZONE]}).firewall is None
    assert extract_kes({"KLPRSS_Components": _components(**{"Host Intrusion Prevention": _lock(True)})}).firewall is None


def _components(**components: Any) -> dict[str, Any]:
    """Секция `KLPRSS_Components` в форме синтетики: контейнер секции, в нём компонент → контейнер с листом `Enabled`."""
    return {"KLPRSS_Val": {name: {"KLPRSS_Val": {"Enabled": leaf}} for name, leaf in components.items()}}


def test_firewall_settings_profile_with_component_only() -> None:
    """Профиль, который только выключает компонент Firewall (секции HIPS нет): строка есть, зон и групп нет, флаг и замок — из
    `KLPRSS_Components`."""
    fw = _firewall(P_NOTEBOOKS["sections"])
    assert fw.component_enabled is False and fw.locks.component is True
    assert fw.hips_component_enabled is None and fw.locks.hips_component is None
    assert (fw.enabled, fw.notify_only, fw.hips_enabled, fw.hips_notify_only, fw.default_app_group) == (None, None, None, None, None)
    assert fw.zones == () and fw.app_groups == ()
    assert (fw.locks.packet, fw.locks.networks, fw.locks.app) == (None, None, None)


def test_component_flags_with_hips_section() -> None:
    """Флаги обоих компонентов рядом с секцией HIPS; HIPS-компонент — первый найденный ключ `HIPS_COMPONENT_KEYS`; замок без
    признака — None; флаг не bool — None."""
    sections = kes11_sections()
    sections["KLPRSS_Components"] = _components(Firewall=_lock(True, locked=None), **{"Host Intrusion Prevention": _lock(False, locked=True)})
    fw = _firewall(sections)
    assert (fw.component_enabled, fw.locks.component, fw.hips_component_enabled, fw.locks.hips_component) == (True, None, False, True)
    sections["KLPRSS_Components"] = _components(Firewall=_lock(1), HIPS=_lock("да", locked=False), **{"Host Intrusion Prevention": _lock(True)})
    fw = _firewall(sections)
    assert (fw.component_enabled, fw.locks.component, fw.hips_component_enabled, fw.locks.hips_component) == (None, False, None, False)


def test_default_app_group_only_int() -> None:
    assert _firewall(kes11_sections(**{f"{HIPS}/hips.defaultAppGroupId": True})).default_app_group is None
    assert _firewall(kes11_sections(**{f"{HIPS}/hips.defaultAppGroupId": "1"})).default_app_group is None
    assert _firewall(kes11_sections(**{f"{HIPS}/hips.defaultAppGroupId": 3})).default_app_group == 3


def test_firewall_json_shape() -> None:
    d = firewall_to_json(_firewall(kes11_sections()))
    assert set(d) == {"enabled", "notify_only", "hips_enabled", "hips_notify_only", "component_enabled", "hips_component_enabled",
                      "default_app_group", "zones", "app_groups", "locks"}
    assert (d["component_enabled"], d["hips_component_enabled"], d["default_app_group"]) == (None, None, 1)
    assert d["zones"] == ({"name": "Тестовая сеть", "kind": 2,
                           "address": {"host": "", "ip": "192.0.2.0", "mask": 24, "ips": (), "hidden": ""}},)
    assert d["app_groups"][0]["access"] == ({"networks": 0, "allow": True, "inherited": False},)
    assert d["locks"] == {"packet": True, "networks": True, "app": True, "component": None, "hips_component": None}


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
