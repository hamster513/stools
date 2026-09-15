"""Содержимое табличных списков.

Это чувствительные данные: whitelist'ы, адреса, учётные записи. Наружу
не уходят никогда; используются для сверки с телами правил и как блоклист
для будущей LLM-разметки (ТЗ §5.2).
"""
from __future__ import annotations

import json
import zipfile
from pathlib import PurePosixPath
from typing import Any

from kbaudit.models import TableList

#: Слишком короткие значения дают ложные совпадения, слишком длинные —
#: это не значения списка, а тексты.
MIN_LEN = 2
MAX_LEN = 120

#: Колонки, которые человек пишет для себя, а не для сравнения в правиле.
#: Самая частая колонка эталонной выгрузки — `description`: она есть
#: в 86 списках из 170. В сверке и в блоклисте они остаются наравне
#: с остальными (описания содержат в том числе внутренние подсети),
#: но при показе смешивать их со значениями нельзя: по идентификатору,
#: имени узла и человеческому комментарию принимают разные решения.
COMMENT_COLUMNS = frozenset(
    {"description", "descr", "comment", "note", "описание", "комментарий"}
)


def _defaults_docs(zf: zipfile.ZipFile) -> list[Any]:
    docs: list[Any] = []
    for name in zf.namelist():
        if PurePosixPath(name).name != "correlation_defaults.json":
            continue
        try:
            docs.append(json.loads(zf.read(name).decode("utf-8-sig")))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
    return docs


def _strings_in(node: Any) -> list[str]:
    out: list[str] = []
    stack = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
        elif isinstance(current, str) and MIN_LEN < len(current) < MAX_LEN:
            out.append(current.strip().lower())
    return out


def load_table_values(zf: zipfile.ZipFile) -> set[str]:
    """Плоское множество всех значений всех списков — для сверки с телами."""
    values: set[str] = set()
    for doc in _defaults_docs(zf):
        values.update(_strings_in(doc))
    return values


def load_values_by_table(zf: zipfile.ZipFile) -> dict[str, set[str]]:
    """Значения, разложенные по именам списков.

    load_table_values даёт плоское множество и отвечает на «есть ли значение
    вообще». Здесь — ответ на «в каком списке», без которого находку класса 1
    нельзя взять в работу.
    """
    by_table: dict[str, set[str]] = {}
    for doc in _defaults_docs(zf):
        if not isinstance(doc, dict):
            continue
        for name, content in doc.items():
            by_table.setdefault(name, set()).update(_strings_in(content))
    return by_table


def load_table_rows(zf: zipfile.ZipFile) -> dict[str, list[dict[str, str]]]:
    """Строки списков с колонками, как они лежат в выгрузке.

    Плоское множество значений отвечает на вопрос «есть ли значение
    в списках», и для сверки этого хватает. Человеку же надо увидеть
    список таким, какой он есть: где идентификатор, где имя узла,
    а где комментарий, написанный для себя.
    """
    out: dict[str, list[dict[str, str]]] = {}
    for doc in _defaults_docs(zf):
        if not isinstance(doc, dict):
            continue
        for name, content in doc.items():
            if not isinstance(content, list):
                continue
            rows = [
                {k: str(v) for k, v in row.items() if isinstance(v, str | int | float)}
                for row in content
                if isinstance(row, dict)
            ]
            if rows:
                out.setdefault(name, []).extend(rows)
    return out


def columns_of(rows: list[dict[str, str]]) -> list[str]:
    """Колонки списка в порядке первого появления.

    Порядок берётся из данных, а не сортируется: в выгрузке колонки идут
    так, как их задумал автор списка, и `description` почти всегда
    последняя — это осмысленный порядок, и ломать его незачем.
    """
    out: list[str] = []
    for row in rows:
        for key in row:
            if key not in out:
                out.append(key)
    return out


def load_table_lists(zf: zipfile.ZipFile) -> list[TableList]:
    """Списки по именам с числом значений — для виджета состояния (спека §7.4)."""
    lists: list[TableList] = []
    for doc in _defaults_docs(zf):
        if not isinstance(doc, dict):
            continue
        for name, content in doc.items():
            lists.append(TableList(name=name, value_count=len(_strings_in(content))))
    return sorted(lists, key=lambda t: t.name)
