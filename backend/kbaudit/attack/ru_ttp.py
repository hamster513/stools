"""Выгрузка «техника → процедура» с применяемостью в России.

Мировая статистика MITRE меряет то, что аналитики MITRE прочитали в
отчётах. Для заказчика здесь она смещена: техника, которой в мировых
данных нет вовсе, может быть рабочим инструментом группировок, которые
ходят именно сюда. Выгрузка даёт вторую точку зрения, и обе показываются
рядом, не сливаясь в один балл.

Формат чужой и меняться будет, поэтому колонки ищутся по названию.
XLSX разбирается стандартной библиотекой — тем же кодом, что и эталон.

Колонка тактик не берётся: она избыточна. Словарь тактик в файле тот же,
что в матрице 19.2 (`Stealth` и `Defense Impairment` — названия MITRE,
не выдумка выгрузки), и на всех 13 525 строках набор тактик строки в
точности равен тактикам техники по матрице: ни одного расхождения, ни
одного уточнения до конкретной тактики процедуры. Хранить такую копию
значит держать два источника одной правды — при обновлении матрицы копия
разойдётся с оригиналом. Тактики считаются от идентификатора техники.

Связи нельзя делить по запятой: внутри значений есть свои. Значения
выделяются по префиксам, а `attack:` и `darkweb:` — это заголовки
отчётов, а не действующие лица, и в сущности не попадают.
"""
from __future__ import annotations

import re

from pydantic import BaseModel, Field

from kbaudit.attack.reference import RE_TECHNIQUE, rows_from_csv, rows_from_xlsx

#: Названия колонок. Сравнение без учёта регистра и по вхождению:
#: «Командная строка» и «command line» — одно и то же.
_HINTS = {
    "technique": ("id",),
    "name": ("техник", "technique"),
    "procedure": ("процедур", "procedure", "описание", "description"),
    "command": ("командн", "command", "команда"),
    "links": ("связ", "link"),
}

#: Сущность в колонке связей: префикс и значение до следующего префикса.
#: Именно до следующего, а не до запятой — запятые есть и внутри значений.
_KINDS = ("adversary", "malware", "tool", "attack", "darkweb")
RE_LINK = re.compile(
    r"\b(" + "|".join(_KINDS) + r")\s*:\s*(.+?)(?=,\s*(?:" + "|".join(_KINDS) + r")\s*:|$)",
    re.DOTALL,
)


class RuProcedure(BaseModel):
    """Одна процедура: как именно применяли технику."""

    technique_id: str
    technique_name: str = ""
    procedure: str = ""
    #: Команда, как её видели. Ради неё выгрузку и загружают: непокрытой
    #: технике это готовый материал для правила.
    command_line: str = ""
    actors: list[str] = Field(default_factory=list)
    malware: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)


class ParsedRuTtp(BaseModel):
    rows: list[RuProcedure] = Field(default_factory=list)
    #: Строки, где идентификатора техники не нашлось. Не ошибка, но и не
    #: данные: молча терять их нельзя, иначе расхождение с тем, что человек
    #: видит в Excel, он воспримет как потерю — и будет прав.
    without_technique: int = 0
    columns: dict[str, str] = Field(default_factory=dict)


def _pick_columns(header: list[str]) -> dict[str, int]:
    """Найти колонки по названиям.

    Идентификатор ищется первым и исключается из кандидатов: заголовок
    «Technique ID» подходит и под него, и под название техники.
    """
    lowered = [(index, (name or "").strip().lower()) for index, name in enumerate(header)]
    out: dict[str, int] = {}
    for role, hints in _HINTS.items():
        for index, name in lowered:
            if index in out.values():
                continue
            if any(hint in name for hint in hints):
                out[role] = index
                break
    return out


def _entities(cell: str) -> dict[str, list[str]]:
    """Действующие лица из колонки связей."""
    found: dict[str, list[str]] = {"adversary": [], "malware": [], "tool": []}
    for kind, value in RE_LINK.findall(cell):
        if kind not in found:
            continue
        name = value.strip().strip(",").strip()
        if name and name not in found[kind]:
            found[kind].append(name)
    return found


def parse(data: bytes, filename: str = "") -> ParsedRuTtp:
    """Разобрать выгрузку.

    Пустой результат — законный ответ на файл не того формата: решение,
    что с этим делать, принимает вызывающий.
    """
    table = rows_from_xlsx(data) if data[:2] == b"PK" else rows_from_csv(data)
    table = [row for row in table if any((cell or "").strip() for cell in row)]
    if not table:
        return ParsedRuTtp()

    header = table[0]
    columns = _pick_columns(header)
    # Одного идентификатора мало: без процедур и связей это список техник,
    # а не выгрузка применяемости, и показывать по нему нечего.
    if "technique" not in columns or not (columns.keys() & {"procedure", "links"}):
        return ParsedRuTtp()

    def cell(row: list[str], name: str) -> str:
        index = columns.get(name)
        if index is None or index >= len(row):
            return ""
        return (row[index] or "").strip()

    rows: list[RuProcedure] = []
    without = 0
    for row in table[1:]:
        found = RE_TECHNIQUE.search(cell(row, "technique"))
        if not found:
            without += 1
            continue
        entities = _entities(cell(row, "links"))
        rows.append(
            RuProcedure(
                technique_id=found.group(0),
                technique_name=cell(row, "name"),
                procedure=cell(row, "procedure"),
                command_line=cell(row, "command"),
                actors=entities["adversary"],
                malware=entities["malware"],
                tools=entities["tool"],
            )
        )
    return ParsedRuTtp(
        rows=rows,
        without_technique=without,
        columns={name: header[index] for name, index in columns.items() if index < len(header)},
    )
