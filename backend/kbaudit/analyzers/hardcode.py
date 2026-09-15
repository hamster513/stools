"""Поиск средовых значений, зашитых в тела правил вместо табличных списков.

Судит по полю, а не по виду литерала. Полярность обязательна: без неё
примерно половина находок ложные — утвердительное сравнение часто и есть
предмет детекта, а отрицание почти всегда whitelist, которому место
в табличном списке (ТЗ §4.1).
"""
from __future__ import annotations

import re
from collections.abc import Iterator

from kbaudit.analyzers.fields import DEFAULT_POLICY, FieldPolicy
from kbaudit.models import Comparison, Finding, KbObject, Polarity

RE_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
RE_CIDR = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b")
RE_FQDN = re.compile(r"\b[\w-]+(?:\.[\w-]+)*\.(?:local|internal|corp|lan|ru)\b", re.IGNORECASE)
RE_SID = re.compile(r"^S-1-5-21-", re.IGNORECASE)

_FUNC = r"(?:(?:lower|upper|trim|to_lower|to_upper)\s*\(\s*)?"
#: Точка в имени поля необязательна — `datafield1`/`datafield2` из ENV_FIELDS
#: пишутся без точки. Захват произвольных идентификаторов без точки не
#: страшен: отсев несредовых/нетехнических значений делает classify().
_FIELD = r"([a-z_][\w]*(?:\.[a-z_][\w]*)*)"

#: RE_CMP — отдельно от _FUNC/_FIELD выше: закрывающая скобка обязана
#: сработать ровно тогда, когда сработала открывающая обёртка функции, а не
#: сама по себе «может быть, может не быть» (как в остальных трёх regex'ах
#: с _FUNC — там развязанная `\)?` не создавала риска, поскольку после поля
#: там разделитель `,`/`)` от in_list/regex, а не сравнение, где скобка от
#: постороннего вызова легко спутать со сравнением голого поля). Группа 1 —
#: необязательный маркер того, что обёртка открылась (символы пробелов
#: сразу после «(», возможно пустая строка — важно не её содержимое, а сам
#: факт участия группы в матче); группа 2 — поле. Условие `(?(1)\s*\))`
#: требует закрывающую скобку тогда и только тогда, когда группа 1
#: сработала — так что ни посторонний вызов произвольной функции, ни
#: артефакт вида "x, correlation_name)" без открывающей скобки не пройдут.
RE_CMP = re.compile(
    r"(?:(?:lower|upper|trim|to_lower|to_upper)\s*\((\s*))?"
    r"([a-z_][\w]*(?:\.[a-z_][\w]*)*)"
    r'(?(1)\s*\))\s*(==|!=)\s*"([^"]*)"',
    re.IGNORECASE,
)
RE_CMP_REV = re.compile(r'"([^"]*)"\s*(==|!=)\s*' + _FUNC + _FIELD, re.IGNORECASE)
RE_IN_LIST = re.compile(
    r"(not\s+)?in_list\(\s*\[([^\]]*)\]\s*,\s*" + _FUNC + _FIELD, re.IGNORECASE
)
RE_REGEX_CALL = re.compile(
    r"(not\s+)?regex\(\s*" + _FUNC + _FIELD + r'\s*\)?\s*,\s*"([^"]*)"', re.IGNORECASE
)
RE_STR = re.compile(r'"([^"]*)"')

#: Класс 3 требует минимум трёх значений в отрицаемом списке.
LIST_THRESHOLD = 3
EXCERPT_RADIUS = 120


def _polarity(op_or_not: str | None) -> Polarity:
    return Polarity.NEGATION if op_or_not and op_or_not.strip() else Polarity.ASSERTION


def scan_comparisons(text: str) -> Iterator[Comparison]:
    """Все сравнения поля с литералом в теле объекта."""
    for m in RE_CMP.finditer(text):
        yield Comparison(
            field=m.group(2).lower(),
            value=m.group(4),
            polarity=Polarity.NEGATION if m.group(3) == "!=" else Polarity.ASSERTION,
        )
    for m in RE_CMP_REV.finditer(text):
        yield Comparison(
            field=m.group(3).lower(),
            value=m.group(1),
            polarity=Polarity.NEGATION if m.group(2) == "!=" else Polarity.ASSERTION,
        )
    for m in RE_IN_LIST.finditer(text):
        items = RE_STR.findall(m.group(2))
        field = m.group(3).lower()
        polarity = _polarity(m.group(1))
        for item in items:
            yield Comparison(
                field=field, value=item, count=len(items), polarity=polarity
            )
    for m in RE_REGEX_CALL.finditer(text):
        pattern = m.group(3)
        if _shape(pattern):
            yield Comparison(
                field=m.group(2).lower(), value=pattern, polarity=_polarity(m.group(1))
            )


def _shape(value: str) -> str | None:
    if RE_CIDR.search(value):
        return "cidr"
    if RE_IP.search(value):
        return "ip"
    if RE_FQDN.search(value):
        return "fqdn"
    return None


def classify(
    comparison: Comparison,
    in_table: bool,
    policy: FieldPolicy = DEFAULT_POLICY,
) -> int | None:
    """Класс находки 1..5 или None, если находки нет.

    Классы взаимоисключающи и проверяются строго по порядку: первый
    подошедший выигрывает (спека §5.1). Исключения — раньше всех классов.
    """
    value = comparison.value
    if policy.is_builtin_account(value):
        return None

    shape = _shape(value)
    environmental = policy.is_environment_field(comparison.field)
    if not shape and not environmental:
        return None
    if not shape and not value.strip():
        return None

    if in_table:
        return 1
    if shape:
        return 2
    if comparison.polarity is Polarity.NEGATION and comparison.count >= LIST_THRESHOLD:
        return 3
    if RE_SID.match(value.strip()):
        return 4
    return 5


def _excerpt(text: str, value: str) -> str | None:
    position = text.find(value)
    if position < 0:
        return None
    start = max(0, position - EXCERPT_RADIUS)
    end = min(len(text), position + len(value) + EXCERPT_RADIUS)
    return text[start:end]


def _owning_tables(value: str, values_by_table: dict[str, set[str]]) -> str | None:
    """Все списки, где встречается значение. Их может быть больше одного —
    и это само по себе плохой знак."""
    owners = sorted(
        name for name, values in values_by_table.items() if value in values
    )
    return ", ".join(owners) if owners else None


def analyze_hardcode(
    bodies: list[KbObject],
    table_values: set[str],
    values_by_table: dict[str, set[str]] | None = None,
    policy: FieldPolicy = DEFAULT_POLICY,
) -> list[Finding]:
    """Находки по всем телам. Пара (поле, значение) внутри одного тела
    учитывается один раз."""
    owners = values_by_table or {}
    findings: list[Finding] = []
    for body in bodies:
        seen: set[tuple[str, str]] = set()
        for comparison in scan_comparisons(body.body_text):
            key = (comparison.field, comparison.value)
            if key in seen:
                continue
            seen.add(key)
            normalized = comparison.value.strip().lower()
            in_table = normalized in table_values
            kind = classify(comparison, in_table, policy)
            if kind is None:
                continue
            findings.append(
                Finding(
                    object_type=body.object_type,
                    object_uuid=body.uuid,
                    object_name=body.name,
                    kind=kind,
                    field=comparison.field,
                    value=comparison.value,
                    polarity=comparison.polarity,
                    in_table=in_table,
                    table_name=_owning_tables(normalized, owners) if in_table else None,
                    shape=_shape(comparison.value),
                    body_excerpt=_excerpt(body.body_text, comparison.value),
                )
            )
    return findings
