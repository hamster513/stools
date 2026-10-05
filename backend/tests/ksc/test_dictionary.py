"""Словарь KES для Windows: настройки политики по компонентам человеческим языком, нераспознанное — в «Прочее»."""
from __future__ import annotations

from typing import Any

import pytest

from api.modules.ksc.core.dictionary import (
    DICTIONARIES,
    Described,
    component_enabled,
    describe,
    dictionary_for,
    display_value,
)
from api.modules.ksc.core.dictionary.model import Entry
from api.modules.ksc.core.policy_contents import flat_settings, walk_settings
from tests.ksc.kes11 import kes11_export, kes11_sections
from tests.ksc.synthetic import build_export

#: Секции из таблицы плана «секция → компонент».
TABLE = {
    "1d3e35bd": "general", "852d0287": "trusted_zone", "4b741d57": "file_threat", "da3d6211": "web_threat", "265f2c1d": "mail_threat",
    "55b2467a": "network_threat", "a9084f82": "behavior", "49c71a58": "exploit", "e9221213": "remediation", "339e619d": "amsi",
    "ff7a5642": "ksn", "b96f0d22": "app_control", "aea3307": "device_control", "63e770b7": "web_control", "fe21e425": "log_inspection",
    "caf9927": "badusb", "44e2b601": "network_settings", "895edee6": "fde", "7ac1dbaa": "fle",
}


def _described(sections: dict[str, Any]) -> dict[tuple[str, str], Described]:
    result = describe("KES", sections)
    assert result is not None
    return {(d.section, d.path): d for d in result[0]}


def test_describe_known_settings() -> None:
    d = _described(kes11_sections())
    self_defence = d[("1d3e35bd", "selfDefense.enableSelfDefence")]
    assert (self_defence.component, self_defence.title, self_defence.value, self_defence.locked) == ("general", "Самозащита", "включено", True)
    assert self_defence.raw == "true" and self_defence.verified
    assert d[("cf9370d5", "firewall.enabled")].component == "firewall"
    assert d[("cf9370d5", "hips.enabled")].component == "hips"
    assert d[("cf9370d5", "firewall.notifyOnly")].title == "Только уведомлять (не блокировать)"
    assert d[("cf9370d5", "firewall.notifyOnly")].value == "выключено"
    heuristic = d[("4b741d57", "heuristicLevel")]
    assert (heuristic.component, heuristic.value, heuristic.verified) == ("file_threat", "средний", True)
    action = d[("4b741d57", "scanAction")]
    assert (action.value, action.verified) == ("код 0", False)
    assert d[("1d3e35bd", "passwordProtection.areas.exitApplication")].title == "Защита паролем: завершение работы программы"
    assert d[("852d0287", "scanExclusionsAndTrustedZone.scanExclusions")].value == "записей: 3"
    assert d[("852d0287", "scanExclusionsAndTrustedZone.trustedApplications")].value == "записей: 2"
    assert d[("cf9370d5", "firewall.networkPacketRules")].value == "записей: 5"
    assert d[("cf9370d5", "hips.appGroups")].value == "записей: 1"
    assert d[("1d3e35bd", "proxy.serverPort")].value == "3128"
    assert d[("1d3e35bd", "quarantineStorage.quarantineLimitMB")].value == "200 МБ"  # обёртка long снята
    assert d[("1d3e35bd", "proxy.userAccount")].value == "—"
    assert d[("caf9927", "enabled")].locked is False


def test_unrecognized_go_to_other() -> None:
    sections = kes11_sections()
    sections["4b741d57"]["madeUpKey"] = {"KLPRSS_Val": 1, "KLPRSS_Mnd": False}
    sections["0badc0de"] = {"anything": {"KLPRSS_Val": True}}
    result = describe("KES", sections)
    assert result is not None
    known, other = result
    keys = {(s.section, s.path) for s in other}
    assert ("4b741d57", "madeUpKey") in keys and ("0badc0de", "anything") in keys
    # Секция KES без компонента, уведомления, шаблоны сообщений, 4-уровневые пути и служебные дубли списков — тоже «Прочее».
    assert ("f8e8efda", "enableTrafficStatistics") in keys
    assert ("1d3e35bd", "notifications.defaultPreset.adaptiveAnomaliesControl.critical") in keys
    assert ("a9084f82", "messageTemplates.messageDeny") in keys and ("63e770b7", "denyMessageTemplate") in keys
    assert ("895edee6", "kasperskyFdeFixedDisksSettings.accountsGenerationSettings.allLocalProfiles.include") in keys
    assert ("852d0287", "scanExclusionsAndTrustedZone.scanExclusions_merging_crutch") in keys
    assert len(known) + len(other) == len(flat_settings(sections))
    assert not keys & {(d.section, d.path) for d in known}


def test_describe_order_follows_dictionary() -> None:
    result = describe("KES", kes11_sections())
    assert result is not None
    order = list(DICTIONARIES["KES"].components)
    ranks = [order.index(d.component) for d in result[0]]
    assert ranks == sorted(ranks)


def test_no_dictionary() -> None:
    assert describe("kesl", kes11_sections()) is None
    assert dictionary_for("kesl") is None and dictionary_for("KES") is DICTIONARIES["KES"]
    assert component_enabled("kesl", kes11_sections(), "file_threat") is None


def test_component_enabled() -> None:
    assert component_enabled("KES", kes11_sections(), "file_threat") is True
    assert component_enabled("KES", kes11_sections(), "firewall") is True
    assert component_enabled("KES", kes11_sections(**{"4b741d57/enabled": False}), "file_threat") is False
    assert component_enabled("KES", kes11_sections(**{"cf9370d5/hips.enabled": False}), "hips") is False
    assert component_enabled("KES", kes11_sections(**{"cf9370d5/hips.enabled": False}), "firewall") is True
    assert component_enabled("KES", kes11_sections(), "ksn") is None  # признака включённости нет
    sections = kes11_sections()
    del sections["4b741d57"]
    assert component_enabled("KES", sections, "file_threat") is None  # секции нет в политике
    assert component_enabled("KES", kes11_sections(**{"4b741d57/enabled": 1}), "file_threat") is None  # не булево — не угадываем


@pytest.mark.parametrize(("entry", "value", "shown"), [
    (Entry("a", "A"), True, "включено"),
    (Entry("a", "A"), False, "выключено"),
    (Entry("a", "A", kind="enum", enum={1: "лёгкий", 2: "средний"}), 2, "средний"),
    (Entry("a", "A", kind="enum", enum={1: "лёгкий"}), 7, "код 7"),
    (Entry("a", "A", kind="enum", verified=False), 0, "код 0"),
    (Entry("a", "A", kind="number", unit="МБ"), 8, "8 МБ"),
    (Entry("a", "A", kind="number"), 3128, "3128"),
    (Entry("a", "A", kind="text"), "", "—"),
    (Entry("a", "A", kind="text"), "<скрыто>", "<скрыто>"),
    (Entry("a", "A", kind="text"), "proxy.example.test", "proxy.example.test"),
    (Entry("a", "A", kind="list"), [1, 2, 3], "записей: 3"),
    (Entry("a", "A", kind="list"), {"x": 1}, "записей: 1"),
    (Entry("a", "A", kind="list"), [], "записей: 0"),
    # Значение не того вида не подменяется догадкой.
    (Entry("a", "A"), 1, "1"),
    (Entry("a", "A", kind="enum"), True, "true"),
    (Entry("a", "A", kind="number"), "<скрыто>", "<скрыто>"),
    (Entry("a", "A", kind="list"), None, "null"),
])
def test_display_value(entry: Entry, value: Any, shown: str) -> None:
    assert display_value(entry, value) == shown


def test_dictionary_structure() -> None:
    kes = DICTIONARIES["KES"]
    assert kes.product == "KES"
    assert set(kes.sections) == set(TABLE) | {"cf9370d5"}
    for name, component in TABLE.items():
        assert kes.sections[name].component == component
        assert all(e.component in ("", component) for e in kes.sections[name].entries)
    assert {e.component for e in kes.sections["cf9370d5"].entries} == {"hips", "firewall"}
    assert {e.component for e in kes.sections["cf9370d5"].entries if e.path.startswith("hips.")} == {"hips"}
    assert list(kes.components)[:4] == ["general", "trusted_zone", "hips", "firewall"]
    assert set(kes.components) == set(TABLE.values()) | {"hips", "firewall"}
    assert set(kes.enabled_paths) == set(kes.components) - {"general", "trusted_zone", "ksn", "network_settings", "fde", "fle"}
    assert kes.enabled_paths["hips"] == ("cf9370d5", "hips.enabled") and kes.enabled_paths["firewall"] == ("cf9370d5", "firewall.enabled")
    for name, section in kes.sections.items():
        paths = [e.path for e in section.entries]
        assert len(paths) == len(set(paths)), name
        for e in section.entries:
            assert e.kind in ("bool", "enum", "number", "text", "list"), (name, e.path)
            assert e.path.count(".") <= 2, (name, e.path)  # до третьего уровня
            assert not e.path.startswith("notifications."), (name, e.path)
            assert e.title, (name, e.path)
    for component, (name, path) in kes.enabled_paths.items():
        entry = next(e for e in kes.sections[name].entries if e.path == path)
        assert entry.kind == "bool" and (entry.component or kes.sections[name].component) == component


def test_every_dictionary_path_is_walked() -> None:
    """Каждый путь словаря — лист, который `flat_settings` отдаёт на синтетике формы KES 11 (ловит опечатки); при
    контейнерах на уровне листа это и пути контейнеров `walk_settings`."""
    declared = {(name, e.path) for name, section in DICTIONARIES["KES"].sections.items() for e in section.entries}
    assert sorted(declared - {(s.section, s.path) for s in walk_settings(kes11_sections())}) == []
    assert sorted(declared - {(s.section, s.path) for s in flat_settings(kes11_sections())}) == []


@pytest.mark.parametrize("container", ["top", "section"])
def test_describe_does_not_depend_on_container_level(container: str) -> None:
    """Те же настройки с контейнерами `KLPRSS_Val` на ключах верхнего уровня или на всю секцию читаются так же, как
    с контейнерами на листьях: скелет эти формы не различает."""
    def view(sections: dict[str, Any]) -> tuple[list[tuple[Any, ...]], list[tuple[Any, ...]]]:
        result = describe("KES", sections)
        assert result is not None
        known = [(d.section, d.path, d.component, d.title, d.value, d.raw, d.locked, d.verified) for d in result[0]]
        return known, sorted((s.section, s.path, s.locked) for s in result[1])

    leaf, other = view(kes11_sections())
    assert view(kes11_sections(container)) == (leaf, other)
    assert len(leaf) == 424 and {k[6] for k in leaf} == {True, False}
    assert len(walk_settings(kes11_sections(container))) < len(walk_settings(kes11_sections()))  # контейнеров и правда меньше
    for component in DICTIONARIES["KES"].components:
        assert component_enabled("KES", kes11_sections(container), component) == component_enabled("KES", kes11_sections(), component)
    assert component_enabled("KES", kes11_sections(container, **{"4b741d57/enabled": False}), "file_threat") is False
    with pytest.raises(ValueError):
        kes11_sections("leaves")


def test_kes11_overrides_and_export() -> None:
    assert kes11_sections(**{"4b741d57/enabled": False})["4b741d57"]["enabled"] == {"KLPRSS_Val": False, "KLPRSS_Mnd": True}
    assert kes11_sections()["4b741d57"]["enabled"]["KLPRSS_Val"] is True
    with pytest.raises(KeyError):
        kes11_sections(**{"4b741d57/enabeld": False})
    export = kes11_export()
    assert export["policy_contents"]["1"]["product"] == "KES" and export["policy_contents"]["1"]["sections"] == kes11_sections()
    assert export["policy_contents"]["3"] == build_export()["policy_contents"]["3"]
