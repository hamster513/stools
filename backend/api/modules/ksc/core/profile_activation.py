"""Условие активации профиля политики и его вычисление по тегам хоста.

Форма условия (`KscProfile.condition_json` — атрибуты профиля как пришли из KSC): `EXPRESSION.KLPRSS_Val` — список с
одним элементом `{"ARGS": [<группа>…], "LOP": 2}`, группа — `{"ARGS": [<условие>…], "LOP": 1, "Name": "…"}`, условие —
`{"OP": <код>, "name": "<поле>", "val": <значение>}`. Известные поля: `NGTPP_sHostTag` (тег хоста, OP 9),
`NGTPP_sNlaLocation` (сетевое расположение, OP 7), `NGTPP_nCpus` (число процессоров, OP 7). Пустое условие —
`KLPRSS_Val: [{}]`.

Принятая трактовка (с консолью KSC не сверена): внутри группы все условия должны выполниться (И), профиль активен,
если выполнена хоть одна группа (ИЛИ); условие по тегу выполняется, если у хоста есть тег с таким значением (без учёта
регистра). Коды `OP` не расшифрованы: у тега код 9 считается «равно», другой код — «не определить». Поле не из списка
известных и не-теговые поля решить нельзя: группа с таким условием — «не определить», если тег в ней не отверг её.
Профиль без правил активации в KSC не активируется.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from api.modules.ksc.core.export import unwrap

TAG_FIELD = "NGTPP_sHostTag"
TAG_EQUALS_OP = 9
REASON_NO_RULES = "правил активации нет"
REASON_TAGS_NOT_COLLECTED = "теги хоста не собраны"
REASON_NOT_BY_TAGS = "условие не по тегам"
REASON_NO_TAG = "нет подходящего тега"
REASON_DISABLED = "профиль выключен"


@dataclass(frozen=True)
class Condition:
    #: tag | nla | cpus | unknown
    field: str
    #: Человекочитаемо: «тег «X»», «сетевое расположение «…»», «число процессоров N», «поле NGTPP_… = …».
    text: str
    value: Any


@dataclass(frozen=True)
class Activation:
    #: None — не определить.
    active: bool | None
    #: Теги хоста (в его написании), по которым профиль активен.
    matched_tags: tuple[str, ...]
    #: Группы условий — для показа условия словами.
    groups: tuple[tuple[Condition, ...], ...]
    reason: str


def _unknown(text: str, value: Any) -> Condition:
    return Condition("unknown", text, value)


def _condition(item: Any) -> Condition:
    if not isinstance(item, dict) or "name" not in item:
        return _unknown("условие не разобрано", item)
    name, value, op = str(item.get("name")), item.get("val"), item.get("OP")
    if name == TAG_FIELD:
        if op == TAG_EQUALS_OP:
            return Condition("tag", f"тег «{value}»", value)
        return _unknown(f"тег «{value}», код условия {op} не расшифрован", value)
    if name == "NGTPP_sNlaLocation":
        return Condition("nla", f"сетевое расположение «{value}»", value)
    if name == "NGTPP_nCpus":
        return Condition("cpus", f"число процессоров {value}", value)
    return _unknown(f"поле {name} = {value}", value)


def _group(item: Any) -> tuple[Condition, ...]:
    if not isinstance(item, dict) or not isinstance(item.get("ARGS"), list):
        return (_unknown("группа условий не разобрана", item),)
    return tuple(_condition(c) for c in item["ARGS"])


def parse_condition(condition: dict[str, Any]) -> tuple[tuple[Condition, ...], ...]:
    """Группы условий из атрибутов профиля; пустой кортеж — правил активации нет."""
    expression = unwrap(condition.get("EXPRESSION"))
    if isinstance(expression, dict) and "KLPRSS_Val" in expression:
        expression = expression["KLPRSS_Val"]
    if expression is None:
        return ()
    if not isinstance(expression, list):
        return ((_unknown("условие не разобрано", expression),),)
    groups: list[tuple[Condition, ...]] = []
    for top in expression:
        if isinstance(top, dict) and not top:
            continue  # пустое условие `[{}]`
        if not isinstance(top, dict) or not isinstance(top.get("ARGS"), list):
            groups.append((_unknown("условие не разобрано", top),))
            continue
        groups.extend(_group(g) for g in top["ARGS"])
    return tuple(groups)


def _group_result(group: tuple[Condition, ...], tags: list[str]) -> tuple[bool | None, list[str]]:
    """Результат группы и теги хоста, которыми она решена. Несовпавший тег отвергает группу, что бы ни стояло рядом;
    нетеговое условие при совпавших тегах — «не определить»."""
    lower = {t.lower(): t for t in tags}
    matched: list[str] = []
    undetermined = False
    for c in group:
        if c.field != "tag":
            undetermined = True
            continue
        own = lower.get(str(c.value).lower())
        if own is None:
            return False, []
        if own not in matched:
            matched.append(own)
    return (None if undetermined else True), matched


def evaluate(groups: tuple[tuple[Condition, ...], ...], tags: list[str] | None) -> Activation:
    """Активен ли профиль на хосте с тегами `tags` (None — теги не собраны)."""
    if not groups:
        return Activation(False, (), groups, REASON_NO_RULES)
    if tags is None:
        by_tag = any(c.field == "tag" for g in groups for c in g)
        return Activation(None, (), groups, REASON_TAGS_NOT_COLLECTED if by_tag else REASON_NOT_BY_TAGS)
    matched: list[str] = []
    undetermined = False
    for group in groups:
        result, own = _group_result(group, tags)
        if result is True:
            matched.extend(t for t in own if t not in matched)
        elif result is None:
            undetermined = True
    if matched:
        reason = f"по тегу {matched[0]}" if len(matched) == 1 else "по тегам " + ", ".join(matched)
        return Activation(True, tuple(matched), groups, reason)
    if undetermined:
        return Activation(None, (), groups, REASON_NOT_BY_TAGS)
    return Activation(False, (), groups, REASON_NO_TAG)
