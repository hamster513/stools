"""Эталонная разметка — чужая таблица «правило → техника ATT&CK».

Нужна затем, что качество разметки иначе обсуждается примерами. С эталоном
на руках видно число: столько-то правил размечено так же, столько-то иначе.

Формат чужой и меняться будет: у заказчика это выгрузка из Excel с колонками
«ID условия», «Описание», «MITREID». Поэтому колонки ищутся по названию, а не
по номеру, а идентификаторы техник вынимаются из ячейки регулярным выражением:
в одной клетке их бывает несколько через запятую.

XLSX разбирается стандартной библиотекой. Это тридцать строк против новой
зависимости в образе ради одного экрана — обмен невыгодный.
"""
from __future__ import annotations

import csv
import io
import re
import zipfile
from xml.etree import ElementTree as ET

from pydantic import BaseModel, Field

from kbaudit import safe_io

_NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
_T = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t"

#: Идентификатор техники или подтехники ATT&CK внутри произвольного текста.
RE_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

#: Названия колонок, по которым ищутся ключ, описание и техники. Сравнение
#: без учёта регистра и по вхождению: «MITREID», «MITRE ID» и «mitre_id» —
#: одно и то же, и требовать точного совпадения значит ломаться на пробеле.
_KEY_HINTS = ("id условия", "id правила", "rule", "правило", "условие", "id")
_TECHNIQUE_HINTS = ("mitre", "attack", "техник", "technique")
_NOTE_HINTS = ("описание", "description", "коммент", "note")


class ReferenceRow(BaseModel):
    """Строка эталона: чем размечено правило по мнению человека."""

    key: str
    techniques: list[str] = Field(default_factory=list)
    note: str = ""


class ParsedReference(BaseModel):
    rows: list[ReferenceRow] = Field(default_factory=list)
    #: Строки, где идентификатор правила есть, а техник нет. Не ошибка,
    #: но и не разметка: человек мог просто не дойти до этой строки.
    without_techniques: int = 0
    columns: dict[str, str] = Field(default_factory=dict)


def _pick_columns(header: list[str]) -> dict[str, int]:
    """Найти колонки ключа, техник и описания по названиям.

    Техники ищутся первыми и исключаются из кандидатов на ключ: заголовок
    «MITREID» содержит «id» и иначе перетянул бы ключ на себя.
    """
    lowered = [(index, (name or "").strip().lower()) for index, name in enumerate(header)]
    out: dict[str, int] = {}
    for index, name in lowered:
        if any(h in name for h in _TECHNIQUE_HINTS):
            out.setdefault("techniques", index)
    for index, name in lowered:
        if index == out.get("techniques"):
            continue
        if "techniques" in out and any(h in name for h in _NOTE_HINTS):
            out.setdefault("note", index)
    for index, name in lowered:
        if index in (out.get("techniques"), out.get("note")):
            continue
        if any(h in name for h in _KEY_HINTS):
            out.setdefault("key", index)
            break
    return out


def rows_from_xlsx(data: bytes) -> list[list[str]]:
    """Ячейки первого листа как таблица строк.

    Члены xlsx распаковываются с потолком (`kbaudit.safe_io`): превышение —
    `ValueError`, вызывающий показывает его как ошибку разбора.
    """
    limit = safe_io.ZIP_MEMBER_LIMIT
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        safe_io.check_zip_sizes(archive, limit, safe_io.ZIP_TOTAL_LIMIT)
        shared: list[str] = []
        if "xl/sharedStrings.xml" in archive.namelist():
            root = ET.fromstring(safe_io.read_zip_member(archive, "xl/sharedStrings.xml", limit))
            shared = ["".join(t.text or "" for t in si.iter(_T)) for si in root.findall("m:si", _NS)]
        sheets = sorted(n for n in archive.namelist() if n.startswith("xl/worksheets/sheet"))
        if not sheets:
            return []
        root = ET.fromstring(safe_io.read_zip_member(archive, sheets[0], limit))

    table: list[list[str]] = []
    data_node = root.find("m:sheetData", _NS)
    for row in data_node if data_node is not None else []:
        cells: dict[int, str] = {}
        for cell in row.findall("m:c", _NS):
            reference = cell.get("r") or ""
            letters = re.match(r"[A-Z]+", reference)
            if not letters:
                continue
            index = 0
            for char in letters.group(0):
                index = index * 26 + (ord(char) - 64)
            value_node = cell.find("m:v", _NS)
            kind = cell.get("t")
            if kind == "s" and value_node is not None and value_node.text is not None:
                position = int(value_node.text)
                value = shared[position] if position < len(shared) else ""
            elif kind == "inlineStr":
                value = "".join(t.text or "" for t in cell.iter(_T))
            else:
                value = value_node.text if value_node is not None and value_node.text else ""
            cells[index - 1] = value
        width = max(cells) + 1 if cells else 0
        table.append([cells.get(i, "") for i in range(width)])
    return table


def rows_from_csv(data: bytes) -> list[list[str]]:
    text = data.decode("utf-8-sig", errors="replace")
    # Разделитель угадывается: выгрузки из Excel в русской локали идут
    # с точкой с запятой, всё остальное — с запятой.
    sample = text[:4096]
    delimiter = ";" if sample.count(";") > sample.count(",") else ","
    return [row for row in csv.reader(io.StringIO(text), delimiter=delimiter)]


def parse(data: bytes, filename: str = "") -> ParsedReference:
    """Разобрать таблицу эталона.

    Пустой результат — законный ответ на файл не того формата: решение,
    что с этим делать, принимает вызывающий.
    """
    table = rows_from_xlsx(data) if data[:2] == b"PK" else rows_from_csv(data)
    table = [row for row in table if any((cell or "").strip() for cell in row)]
    if not table:
        return ParsedReference()

    header = table[0]
    columns = _pick_columns(header)
    if "key" not in columns or "techniques" not in columns:
        return ParsedReference(columns={})

    def cell(row: list[str], name: str) -> str:
        index = columns.get(name)
        if index is None or index >= len(row):
            return ""
        return (row[index] or "").strip()

    rows: list[ReferenceRow] = []
    empty = 0
    for row in table[1:]:
        key = cell(row, "key")
        if not key:
            continue
        found = RE_TECHNIQUE.findall(cell(row, "techniques"))
        if not found:
            empty += 1
            continue
        rows.append(
            ReferenceRow(key=key, techniques=sorted(set(found)), note=cell(row, "note"))
        )
    return ParsedReference(
        rows=rows,
        without_techniques=empty,
        columns={name: header[index] for name, index in columns.items() if index < len(header)},
    )


def code_key(name: str) -> str:
    """Ключ сопоставления — код правила без автора и без имени.

    `JC-AC-020-001` и `DEMO_AC_020_001_Same_Account_Authentication` — одно
    и то же правило: у заказчика в таблице свой префикс, а в выгрузке свой.
    Общее — категория, группа и номер, они и берутся.

    Ключ не уникален: на 187 правил выгрузки приходится 14 совпадающих
    кодов (`..._copy` и переименованные копии). Разбираться с этим — дело
    сопоставления, а не разбора.
    """
    parts = [p for p in re.split(r"[^0-9A-Za-z]+", name.upper()) if p]
    if len(parts) < 4:
        return ""
    return "_".join(parts[1:4])
