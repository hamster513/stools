"""Извлечение фактов из тела правила регулярными выражениями.

Полноценный грамматический разбор языка правил — оверинжиниринг под задачу
инвентаризации (ТЗ §8). Регулярки проверены на эталонной выгрузке.
"""
from __future__ import annotations

import hashlib
import re

from kbaudit.models import RuleBody

RE_EVENT = re.compile(r"^\s*event\s+([A-Za-z_]\w*)\s*:", re.MULTILINE)
RE_FILTER_REF = re.compile(r"filter::([A-Za-z_]\w*)")
RE_QUERY_FROM = re.compile(r"\bfrom\s+([A-Za-z_]\w*)")
RE_INSERT_INTO = re.compile(r"\binsert_into\s+([A-Za-z_]\w*)")
RE_MSGID_EQ = re.compile(r'msgid\s*==?\s*"([^"]+)"')
RE_IN_LIST_MSGID = re.compile(r'in_list\(\s*\[([^\]]*)\]\s*,\s*msgid\s*\)')
RE_STR = re.compile(r'"([^"]*)"')
RE_TOKEN = re.compile(r"\b([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)+)\b")

#: Ссылающееся поле — голое correlation_name либо явно обёрнутое одной из
#: этих функций с обеих сторон: lower(correlation_name), upper(...), trim(...).
#: В выгрузке встречается lower(correlation_name) == "..." — без учёта
#: обёртки ссылка на родителя терялась бы молча. Альтернатива записана явно
#: (а не как необязательная открывающая/закрывающая скобка по отдельности),
#: чтобы не совпасть ни на постороннем вызове произвольной функции, ни на
#: артефакте вида "x, correlation_name)" без открывающей скобки вовсе.
#:
#: Голая ветка держит \b явно: без соседства с "==" (как в RE_CORR_EQ) или
#: с обязательной ")" сразу после (как в обёрнутой ветке) сопоставление
#: correlation_name ничем справа не ограничено — совпало бы и с префиксом
#: более длинного идентификатора вроде correlation_name_extra. Обёрнутая
#: ветка отдельного \b не требует: \s*\) после correlation_name уже
#: требует, чтобы сразу за именем шли только пробелы и закрывающая скобка —
#: любой словообразующий символ (тот самый "_extra") туда не пройдёт,
#: так что граница слова там избыточна, а не пропущена по недосмотру.
_CORR_NAME = (
    r"(?:(?:lower|upper|trim|to_lower|to_upper)\s*\(\s*correlation_name\s*\)"
    r"|correlation_name\b)"
)
RE_CORR_EQ = re.compile(_CORR_NAME + r'\s*==\s*"([^"]+)"', re.IGNORECASE)
RE_IN_LIST_CORR = re.compile(
    r"in_list\(\s*\[([^\]]*)\]\s*,\s*" + _CORR_NAME, re.IGNORECASE
)

#: correlation_name == "null" встречается в выгрузке и зависимостью не является.
NOT_A_NAME = {"null", "none", ""}


def body_hash(text: str) -> str:
    """Хеш тела: показывает, что правило не просто есть в двух снапшотах,
    а не менялось."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_rule_body(text: str, taxonomy_fields: set[str]) -> RuleBody:
    msgids = set(RE_MSGID_EQ.findall(text))
    for group in RE_IN_LIST_MSGID.findall(text):
        msgids.update(RE_STR.findall(group))

    corr_refs = set(RE_CORR_EQ.findall(text))
    for group in RE_IN_LIST_CORR.findall(text):
        corr_refs.update(RE_STR.findall(group))
    corr_refs = {c for c in corr_refs if c.strip().lower() not in NOT_A_NAME}

    fields = {t for t in RE_TOKEN.findall(text) if t in taxonomy_fields}

    return RuleBody(
        events=sorted(set(RE_EVENT.findall(text))),
        msgids=sorted(msgids),
        corr_refs=sorted(corr_refs),
        taxonomy_fields=sorted(fields),
        filter_refs=sorted(set(RE_FILTER_REF.findall(text))),
        table_reads=sorted(set(RE_QUERY_FROM.findall(text))),
        table_writes=sorted(set(RE_INSERT_INTO.findall(text))),
        line_count=text.count("\n") + 1,
    )
