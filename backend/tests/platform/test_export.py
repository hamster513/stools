"""Общий экспорт списков (спека §2.1): CSV для Excel в русской локали и XLSX с потолком строк."""
from __future__ import annotations

import asyncio
import csv
import datetime as dt
import io
import re
import zipfile
from collections.abc import Iterator
from typing import Any

import openpyxl
import pytest
from fastapi import HTTPException
from fastapi.responses import StreamingResponse

from api.platform.export import (
    TRUNCATED_NOTE,
    XLSX_MAX_ROWS,
    Column,
    csv_safe,
    export_filename,
    export_response,
)
from kbaudit.attack.reference import rows_from_xlsx

COLUMNS = [Column("name", "Имя"), Column("count", "Число"), Column("at", "Когда")]
AT = dt.datetime(2026, 10, 13, 12, 40, 5, 123456, tzinfo=dt.UTC)
ROWS: list[dict[str, Any]] = [
    {"name": "=1+1", "count": 42, "at": AT},
    {"name": "srv01", "count": 1.5, "at": None},
    {"name": None, "count": None, "at": dt.date(2026, 10, 1)},
]


def body(response: StreamingResponse) -> bytes:
    async def collect() -> bytes:
        return b"".join([chunk if isinstance(chunk, bytes) else chunk.encode() async for chunk in response.body_iterator])

    return asyncio.run(collect())


def test_csv_for_excel_in_russian_locale() -> None:
    response = export_response("csv", COLUMNS, iter(ROWS), module="vm", name="vulns")
    assert response.media_type == "text/csv; charset=utf-8"
    disposition = response.headers["content-disposition"]
    assert re.search(r"filename\*=UTF-8''stools-vm-vulns-\d{8}-\d{4}\.csv", disposition)
    raw = body(response)
    assert raw.startswith("﻿".encode())
    text = raw.decode("utf-8-sig")
    assert text.split("\r\n")[0] == "Имя;Число;Когда"
    rows = list(csv.reader(io.StringIO(text), delimiter=";"))
    assert rows[1] == ["'=1+1", "42", "2026-10-13T12:40:05+00:00"]
    assert rows[2] == ["srv01", "1.5", ""]
    assert rows[3] == ["", "", "2026-10-01"]
    assert '"42"' not in text  # числа — без кавычек


def test_csv_is_streamed_lazily_and_never_truncated() -> None:
    pulled = 0

    def rows() -> Iterator[dict[str, Any]]:
        nonlocal pulled
        for i in range(XLSX_MAX_ROWS + 5):
            pulled += 1
            yield {"name": f"h{i}", "count": i, "at": None}

    response = export_response("csv", COLUMNS, rows(), module="vm", name="vulns")
    assert pulled == 0  # строки читаются, когда ответ уходит, а не в ручке
    lines = body(response).decode("utf-8-sig").split("\r\n")
    assert lines[-1] == "" and len(lines) == 1 + XLSX_MAX_ROWS + 5 + 1
    assert TRUNCATED_NOTE not in lines[-2]


def test_xlsx_reads_back_with_titles_and_types() -> None:
    response = export_response("xlsx", COLUMNS, iter(ROWS), module="settings", name="audit")
    assert response.media_type == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    assert re.search(r"filename\*=UTF-8''stools-settings-audit-\d{8}-\d{4}\.xlsx", response.headers["content-disposition"])
    data = body(response)
    table = rows_from_xlsx(data)
    assert table[0] == ["Имя", "Число", "Когда"]
    # Строка с «=» — текст, а не формула: в XLSX ячейка типизирована, апостроф не нужен.
    assert table[1][:2] == ["=1+1", "42"]
    assert len(table) == 1 + len(ROWS)

    sheet = openpyxl.load_workbook(io.BytesIO(data)).active
    assert sheet is not None and sheet.title == "Данные"
    assert sheet["A1"].font.b and sheet.auto_filter.ref == "A1:C4"
    assert sheet["A2"].data_type == "s" and sheet["B2"].value == 42 and sheet["B3"].value == 1.5
    # Даты — датами; Excel не знает поясов, поэтому время местное (STOOLS_TZ, в тестах UTC).
    assert sheet["C2"].is_date and sheet["C2"].value == AT.replace(microsecond=0, tzinfo=None)
    assert sheet["C4"].is_date and sheet["A4"].value is None


def test_times_are_shown_in_stools_tz(monkeypatch: pytest.MonkeyPatch) -> None:
    """CSV — со смещением, XLSX — местным временем без пояса; момент один и тот же."""
    monkeypatch.setenv("STOOLS_TZ", "Europe/Moscow")
    columns, rows = [Column("at", "Когда")], [{"at": AT}]
    text = body(export_response("csv", columns, iter(rows), module="m", name="n")).decode("utf-8-sig")
    assert text.split("\r\n")[1] == "2026-10-13T15:40:05+03:00"
    data = body(export_response("xlsx", columns, iter(rows), module="m", name="n"))
    sheet = openpyxl.load_workbook(io.BytesIO(data)).active
    assert sheet is not None and sheet["A2"].value == dt.datetime(2026, 10, 13, 15, 40, 5)  # noqa: DTZ001


def test_xlsx_drops_characters_excel_forbids() -> None:
    """Управляющие символы в строке (бывают в логах и выгрузках) openpyxl отвергает исключением."""
    response = export_response("xlsx", [Column("name", "Имя")], iter([{"name": "a\x00b\x07c"}]), module="m", name="n")
    assert rows_from_xlsx(body(response))[1] == ["abc"]


def test_xlsx_stops_at_the_cap_with_a_note() -> None:
    rows = ({"name": f"h{i}"} for i in range(XLSX_MAX_ROWS + 1))
    response = export_response("xlsx", [Column("name", "Имя")], rows, module="vm", name="vulns")
    table = rows_from_xlsx(body(response))
    assert len(table) == 1 + XLSX_MAX_ROWS + 1
    assert table[XLSX_MAX_ROWS] == [f"h{XLSX_MAX_ROWS - 1}"]
    assert table[-1] == [TRUNCATED_NOTE]


def test_xlsx_exactly_at_the_cap_has_no_note() -> None:
    rows = ({"name": f"h{i}"} for i in range(XLSX_MAX_ROWS))
    data = body(export_response("xlsx", [Column("name", "Имя")], rows, module="vm", name="vulns"))
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert TRUNCATED_NOTE.encode() not in archive.read("xl/worksheets/sheet1.xml")
        assert TRUNCATED_NOTE.encode() not in archive.read("xl/sharedStrings.xml") if "xl/sharedStrings.xml" in archive.namelist() else True


def test_unknown_format_is_422() -> None:
    with pytest.raises(HTTPException) as caught:
        export_response("pdf", COLUMNS, iter(ROWS), module="vm", name="vulns")
    assert caught.value.status_code == 422


def test_export_filename() -> None:
    at = dt.datetime(2026, 10, 13, 15, 40, tzinfo=dt.UTC)
    assert export_filename("vm", "vulns", "csv", now=at) == "stools-vm-vulns-20261013-1540.csv"
    assert export_filename("settings", "audit", "xlsx", now=at) == "stools-settings-audit-20261013-1540.xlsx"


@pytest.mark.parametrize(
    ("raw", "safe"),
    [("=1+1", "'=1+1"), ("+7", "'+7"), ("-x", "'-x"), ("@SUM", "'@SUM"), ("\tx", "'\tx"), ("plain", "plain"), ("", "")],
)
def test_csv_safe(raw: str, safe: str) -> None:
    assert csv_safe(raw) == safe
