"""Выгрузка списков в CSV и XLSX (спека §2.1): одна точка для всех модулей.

Ручка отдаёт колонки (подписи — как в таблице на экране) и итератор строк-словарей с теми же
фильтрами и сортировкой, что у списка; формат выбирает пользователь.

CSV — для Excel в русской локали: BOM, `;`, CRLF; идёт потоком, строки читаются, пока ответ
уходит, и не ограничены. Строки проходят `csv_safe` (аудит L2): имена хостов, логины, пути —
чужой ввод, и Excel не должен исполнить их как формулу.

XLSX — с потолком `XLSX_MAX_ROWS`: книга write-only всё равно собирается целиком до отдачи
(zip пишется при закрытии), и без потолка выгрузка миллионов пар VM съела бы память процесса.
100 000 строк — десятки МБ, это допустимо; дальше — строка-предупреждение. Ячейки
типизированы, поэтому апостроф перед «=» не нужен: строка записывается строкой, а не формулой.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote
from zoneinfo import ZoneInfo

from fastapi import HTTPException, status
from fastapi.responses import StreamingResponse
from openpyxl import Workbook
from openpyxl.cell import WriteOnlyCell
from openpyxl.cell.cell import ERROR_CODES, ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Font
from openpyxl.utils import get_column_letter

from api.settings import get_settings


@dataclass(frozen=True)
class Column:
    key: str
    #: Подпись — как в таблице на экране.
    title: str


XLSX_MAX_ROWS = 100_000
TRUNCATED_NOTE = "Выгружены первые 100 000 строк — сузьте фильтры"
FORMATS = ("csv", "xlsx")
MEDIA_TYPES = {
    "csv": "text/csv; charset=utf-8",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


def csv_safe(value: str) -> str:
    """Excel исполняет ячейки, начинающиеся с =, +, -, @ (и табуляции, перевода строки):
    такой строке — ведущий апостроф."""
    if value and value[0] in "=+-@\t\r":
        return "'" + value
    return value


def _tz() -> ZoneInfo:
    return ZoneInfo(get_settings().tz)


def export_filename(module: str, name: str, fmt: str, now: dt.datetime | None = None) -> str:
    """stools-vm-vulns-20261013-1540.csv; время — местное (STOOLS_TZ), как его видит владелец."""
    at = now or dt.datetime.now(_tz())
    return f"stools-{module}-{name}-{at:%Y%m%d-%H%M}.{fmt}"


def _local(value: dt.datetime, tz: ZoneInfo) -> dt.datetime:
    """Без микросекунд; время с поясом — в поясе STOOLS_TZ (по умолчанию UTC)."""
    if value.tzinfo is not None:
        value = value.astimezone(tz)
    return value.replace(microsecond=0)


def _csv_cell(value: Any, tz: ZoneInfo) -> Any:
    if value is None:
        return ""
    if isinstance(value, dt.datetime):
        return _local(value, tz).isoformat()
    if isinstance(value, dt.date):
        return value.isoformat()
    if isinstance(value, (int, float)):
        return value
    return csv_safe(str(value))


def _csv_body(columns: Sequence[Column], rows: Iterable[Mapping[str, Any]], tz: ZoneInfo) -> Iterator[bytes]:
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";", lineterminator="\r\n")
    writer.writerow([c.title for c in columns])
    yield ("﻿" + buf.getvalue()).encode("utf-8")
    for row in rows:
        buf.seek(0)
        buf.truncate()
        writer.writerow([_csv_cell(row.get(c.key), tz) for c in columns])
        yield buf.getvalue().encode("utf-8")


def _xlsx_cell(sheet: Any, value: Any, tz: ZoneInfo) -> Any:
    if value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, dt.datetime):
        # Excel не знает поясов: openpyxl отвергает время с поясом, пишем местное.
        return _local(value, tz).replace(tzinfo=None)
    if isinstance(value, dt.date):
        return value
    # Управляющие символы (бывают в логах и выгрузках) openpyxl отвергает исключением.
    text = ILLEGAL_CHARACTERS_RE.sub("", str(value))
    if text.startswith("=") or text in ERROR_CODES:
        cell = WriteOnlyCell(sheet, value=text)
        cell.data_type = "s"  # иначе openpyxl запишет формулу или ячейку-ошибку (#N/A)
        return cell
    return text


def _xlsx_body(columns: Sequence[Column], rows: Iterable[Mapping[str, Any]], tz: ZoneInfo) -> bytes:
    book = Workbook(write_only=True)
    sheet = book.create_sheet("Данные")
    bold = Font(bold=True)
    header = []
    for c in columns:
        cell = WriteOnlyCell(sheet, value=c.title)
        cell.font = bold
        header.append(cell)
    sheet.append(header)
    written = 0
    for row in rows:
        if written == XLSX_MAX_ROWS:
            sheet.append([TRUNCATED_NOTE])
            break
        sheet.append([_xlsx_cell(sheet, row.get(c.key), tz) for c in columns])
        written += 1
    # Хвост листа (и фильтр) пишется при сохранении — диапазон уже известен; строку-предупреждение
    # под фильтр не берём.
    sheet.auto_filter.ref = f"A1:{get_column_letter(max(len(columns), 1))}{written + 1}"
    out = io.BytesIO()
    book.save(out)
    return out.getvalue()


def export_response(
    fmt: str, columns: Sequence[Column], rows: Iterable[Mapping[str, Any]], *, module: str, name: str,
) -> StreamingResponse:
    """`fmt` — csv или xlsx, иначе 422. CSV читает `rows` потоком при отдаче (источник должен жить
    до конца ответа); XLSX собирается здесь же, в ручке, и отдаётся готовым телом."""
    if fmt not in FORMATS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"формат выгрузки: csv или xlsx, а не {fmt}")
    tz = _tz()
    filename = export_filename(module, name, fmt)
    headers = {"Content-Disposition": f"attachment; filename=\"{filename}\"; filename*=UTF-8''{quote(filename)}"}
    body: Iterable[bytes]
    if fmt == "csv":
        body = _csv_body(columns, rows, tz)
    else:
        body = iter([_xlsx_body(columns, rows, tz)])
    return StreamingResponse(body, media_type=MEDIA_TYPES[fmt], headers=headers)
