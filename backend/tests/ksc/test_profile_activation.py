"""Условие активации профиля: разбор формы KSC и вычисление по тегам хоста (принятая трактовка: И внутри группы, ИЛИ между)."""
from __future__ import annotations

from typing import Any

from api.modules.ksc.core.profile_activation import Activation, Condition, evaluate, parse_condition
from tests.ksc.synthetic import activation, condition_group, tag_condition


def test_non_dict_attributes_and_empty_group_are_undetermined() -> None:
    """Атрибуты профиля не словарь и группа без условий — «не определить», а не ошибка и не ложное «нет»."""
    for bad in ([], "x", None):
        groups = parse_condition(bad)  # type: ignore[arg-type]
        assert len(groups) == 1 and groups[0][0].field == "unknown"
        assert evaluate(groups, ["VIP"]).active is None
    groups = parse_condition({"EXPRESSION": activation({"ARGS": [], "LOP": 1})})
    assert groups == ((Condition("unknown", "группа без условий", {"ARGS": [], "LOP": 1}),),)
    assert evaluate(groups, ["VIP"]).active is None
    assert evaluate(groups, []).active is None


def _nla(value: str) -> dict[str, Any]:
    return {"OP": 7, "name": "NGTPP_sNlaLocation", "val": value}


def _attrs(*groups: dict[str, Any]) -> dict[str, Any]:
    return {"KLSSPOL_PRF_ENABLED": True, "EXPRESSION": activation(*groups)}


def _fields(groups: tuple[tuple[Condition, ...], ...]) -> list[list[str]]:
    return [[c.field for c in g] for g in groups]


# --- разбор ---------------------------------------------------------------------------------------


def test_parse_single_tag_group() -> None:
    groups = parse_condition(_attrs(condition_group(tag_condition("VIP"), name="VIP")))
    assert groups == ((Condition("tag", "тег «VIP»", "VIP"),),)


def test_parse_two_groups_and_mixed_fields() -> None:
    groups = parse_condition(_attrs(condition_group(tag_condition("VIP"), _nla("Office")), condition_group(tag_condition("Server"))))
    assert _fields(groups) == [["tag", "nla"], ["tag"]]
    nla = groups[0][1]
    assert nla.text == "сетевое расположение «Office»" and nla.value == "Office"
    assert groups[1][0].value == "Server"


def test_parse_cpus_unknown_field_and_other_tag_op() -> None:
    groups = parse_condition(_attrs(condition_group(
        {"OP": 7, "name": "NGTPP_nCpus", "val": 4}, {"OP": 1, "name": "NGTPP_sFoo", "val": "bar"}, tag_condition("VIP", op=3),
    )))
    assert _fields(groups) == [["cpus", "unknown", "unknown"]]
    cpus, foo, tag = groups[0]
    assert cpus.text == "число процессоров 4" and cpus.value == 4
    assert foo.text == "поле NGTPP_sFoo = bar" and foo.value == "bar"
    # Тег с нерасшифрованным кодом условия — не «равно», решить нельзя.
    assert "VIP" in tag.text and "3" in tag.text and tag.value == "VIP"


def test_parse_empty_condition() -> None:
    assert parse_condition(_attrs()) == ()
    assert parse_condition({"KLSSPOL_PRF_ENABLED": True, "EXPRESSION": {"KLPRSS_Val": [{}]}}) == ()
    assert parse_condition({"KLSSPOL_PRF_ENABLED": False}) == ()
    assert parse_condition({}) == ()


def test_parse_without_container_and_through_typed_values() -> None:
    # Без контейнера `KLPRSS_Val` (уже «голый» список) и с типизированными значениями, как приходят из KSC.
    bare = {"EXPRESSION": [{"ARGS": [{"ARGS": [{"OP": {"type": "long", "value": 9}, "name": "NGTPP_sHostTag", "val": "VIP"}], "LOP": 1}], "LOP": 2}]}
    assert parse_condition(bare) == ((Condition("tag", "тег «VIP»", "VIP"),),)


def test_parse_garbage_is_unknown_group() -> None:
    for expression in ("junk", ["junk"], [{"ARGS": ["junk"], "LOP": 2}], [{"ARGS": [{"ARGS": ["junk"], "LOP": 1}], "LOP": 2}], [{"ARGS": [{"LOP": 1}], "LOP": 2}]):
        groups = parse_condition({"EXPRESSION": {"KLPRSS_Val": expression}})
        assert len(groups) == 1 and len(groups[0]) == 1 and groups[0][0].field == "unknown", expression
        assert groups[0][0].text


# --- вычисление -----------------------------------------------------------------------------------


def _eval(tags: list[str] | None, *groups: dict[str, Any]) -> Activation:
    return evaluate(parse_condition(_attrs(*groups)), tags)


def test_tag_match_is_case_insensitive_and_keeps_host_spelling() -> None:
    a = _eval(["Vip", "Бухгалтерия"], condition_group(tag_condition("VIP")))
    assert a.active is True and a.matched_tags == ("Vip",) and a.reason == "по тегу Vip"
    assert a.groups == ((Condition("tag", "тег «VIP»", "VIP"),),)


def test_and_inside_group() -> None:
    both = condition_group(tag_condition("VIP"), tag_condition("Server"))
    missing = _eval(["VIP"], both)
    assert missing.active is False and missing.matched_tags == () and missing.reason == "нет подходящего тега"
    full = _eval(["Server", "VIP"], both)
    assert full.active is True and full.matched_tags == ("VIP", "Server") and full.reason == "по тегам VIP, Server"


def test_or_between_groups() -> None:
    a = _eval(["VIP"], condition_group(tag_condition("Server")), condition_group(tag_condition("VIP")))
    assert a.active is True and a.matched_tags == ("VIP",) and a.reason == "по тегу VIP"
    none = _eval(["Бухгалтерия"], condition_group(tag_condition("Server")), condition_group(tag_condition("VIP")))
    assert none.active is False and none.reason == "нет подходящего тега"


def test_non_tag_field_in_only_group_is_undetermined() -> None:
    a = _eval(["VIP"], condition_group(tag_condition("VIP"), _nla("Office")))
    assert a.active is None and a.matched_tags == () and a.reason == "условие не по тегам"
    assert _eval([], condition_group(_nla("Office"))).active is None
    assert _eval([], condition_group({"OP": 1, "name": "NGTPP_sFoo", "val": "bar"})).reason == "условие не по тегам"


def test_tag_mismatch_decides_group_despite_non_tag_field() -> None:
    a = _eval(["Бухгалтерия"], condition_group(tag_condition("VIP"), _nla("Office")))
    assert a.active is False and a.reason == "нет подходящего тега"


def test_other_group_solved_by_tags_wins_over_undetermined() -> None:
    a = _eval(["VIP"], condition_group(_nla("Office")), condition_group(tag_condition("VIP")))
    assert a.active is True and a.matched_tags == ("VIP",)
    # Группа «не определить» и группа «нет» — в целом не определить.
    mixed = _eval(["Бухгалтерия"], condition_group(_nla("Office")), condition_group(tag_condition("VIP")))
    assert mixed.active is None and mixed.reason == "условие не по тегам"


def test_tags_not_collected() -> None:
    a = _eval(None, condition_group(tag_condition("VIP")))
    assert a.active is None and a.matched_tags == () and a.reason == "теги хоста не собраны"
    assert _eval(None, condition_group(tag_condition("VIP")), condition_group(_nla("Office"))).reason == "теги хоста не собраны"
    assert _eval(None, condition_group(_nla("Office"))).reason == "условие не по тегам"


def test_empty_condition_never_activates() -> None:
    for tags in (["VIP"], [], None):
        a = _eval(tags)
        assert a.active is False and a.matched_tags == () and a.groups == () and a.reason == "правил активации нет"
