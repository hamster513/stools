from __future__ import annotations

from typing import Any

import pytest

from api.modules.ksc.core.policy_model import (
    EXTRACTORS,
    Exclusion,
    NetRule,
    PolicyObjects,
    covered_by,
    exclusion_key,
    extract,
    net_rule_key,
)


def test_exclusion_key_ignores_case_spaces_policy_and_profile() -> None:
    a = Exclusion("path", "C:\\Tools\\A.exe")
    b = Exclusion("path", "c:\\tools\\a.exe ", profile="Ноутбуки", comment="другой")
    assert exclusion_key(a) == exclusion_key(b) and len(exclusion_key(a)) == 32
    assert exclusion_key(Exclusion("mask", "C:\\Tools\\A.exe")) != exclusion_key(a)


def test_net_rule_key_ignores_case_position_and_profile() -> None:
    a = NetRule("packet", 0, "Allow DNS", "allow", "out", "UDP", "", "53", "10.0.0.1")
    b = NetRule("PACKET", 5, "allow dns", "block", "OUT", "udp", "", "53", "10.0.0.1", profile="Ноутбуки")
    assert net_rule_key(a) == net_rule_key(b) and len(net_rule_key(a)) == 32
    assert net_rule_key(NetRule("packet", 0, "Allow DNS", "allow", "in", "UDP", "", "53", "10.0.0.1")) != net_rule_key(a)


TARGET = Exclusion("path", "C:\\Tools\\a.exe")


@pytest.mark.parametrize(("other", "covered"), [
    (Exclusion("path", "C:\\Tools"), True),
    (Exclusion("path", "C:\\Tools\\"), True),
    (Exclusion("path", "c:/tools/"), False),           # другой разделитель — не тот каталог
    (Exclusion("mask", "C:\\Tools\\*.exe"), True),
    (Exclusion("mask", "c:\\tools\\?.EXE"), True),
    (Exclusion("path", "C:\\Tool"), False),
    (Exclusion("path", "C:\\Tools\\a.exe"), False),     # равное значение — не перекрытие
    (Exclusion("path", "C:\\Tools", enabled=False), False),
    (Exclusion("hash", "C:\\Tools"), False),
    (Exclusion("path", "C:\\Tools", ("объект: not-a-virus:Test*",)), False),  # сужено именем объекта — касается одной угрозы
    (Exclusion("path", "C:\\Tools", ("объект: *",)), True),
])
def test_covered_by_cases(other: Exclusion, covered: bool) -> None:
    assert (covered_by(TARGET, [TARGET, other]) == other) is covered


@pytest.mark.parametrize(("value", "other", "covered"), [
    ("C:\\Tools\\", "C:\\Tools", False),          # тот же каталог с замыкающим разделителем — не шире
    ("C:\\Tools", "C:\\Tools\\", False),
    ("C:\\Tools/", "C:\\Tools\\", False),
    ("C:\\Tools\\Sub\\", "C:\\Tools", True),     # подкаталог с замыкающим разделителем — покрыт
    ("C:\\Tools\\Sub", "C:\\Tools\\", True),
])
def test_covered_by_trailing_separator(value: str, other: str, covered: bool) -> None:
    e, o = Exclusion("path", value), Exclusion("path", other)
    assert (covered_by(e, [e, o]) == o) is covered


def test_covered_by_not_self_and_hash_not_by_mask() -> None:
    assert covered_by(TARGET, [TARGET]) is None
    assert covered_by(Exclusion("hash", "abc123"), [Exclusion("mask", "*")]) is None
    # Первое подходящее из нескольких.
    wide, wider = Exclusion("path", "C:\\Tools"), Exclusion("path", "C:\\")
    assert covered_by(TARGET, [wide, wider]) == wide


def test_extract_registry(monkeypatch: Any) -> None:
    assert extract("kesl", {}) is None
    monkeypatch.delitem(EXTRACTORS, "KES")  # реестр без KES: продукт не описан
    assert extract("KES", {}) is None
    objs = PolicyObjects(exclusions=[Exclusion("path", "C:\\Tools")], consumed={("S", "a.b")})
    seen: list[dict[str, Any]] = []

    def fake(sections: dict[str, Any]) -> PolicyObjects:
        seen.append(sections)
        return objs

    monkeypatch.setitem(EXTRACTORS, "KES", fake)
    assert extract("KES", {"S": {}}) is objs and seen == [{"S": {}}]
    assert extract("1103", {}) is None
