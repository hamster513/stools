"""Разбор чужой таблицы «правило → техника»."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from kbaudit import safe_io
from kbaudit.attack.reference import code_key, parse


def _xlsx(rows: list[list[str]]) -> bytes:
    """Минимальный XLSX с одним листом и общими строками."""
    shared: list[str] = []
    for row in rows:
        for cell in row:
            if cell not in shared:
                shared.append(cell)
    cells = []
    for index, row in enumerate(rows, start=1):
        parts = []
        for column, cell in enumerate(row):
            letter = chr(ord("A") + column)
            parts.append(
                f'<c r="{letter}{index}" t="s"><v>{shared.index(cell)}</v></c>'
            )
        cells.append(f'<row r="{index}">{"".join(parts)}</row>')
    sheet = (
        '<?xml version="1.0"?><worksheet '
        'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<sheetData>{"".join(cells)}</sheetData></worksheet>'
    )
    strings = "".join(f"<si><t>{s}</t></si>" for s in shared)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("xl/worksheets/sheet1.xml", sheet)
        archive.writestr(
            "xl/sharedStrings.xml",
            '<?xml version="1.0"?><sst '
            'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            f"{strings}</sst>",
        )
    return buf.getvalue()


def test_columns_are_found_by_name_not_position() -> None:
    """Формат чужой и меняться будет: порядок колонок не гарантирован.

    Ловушка здесь одна: заголовок «MITREID» содержит «id» и при наивном
    поиске перетягивает на себя колонку ключа.
    """
    data = _xlsx(
        [
            ["Описание", "MITREID", "ID Условия"],
            ["Дамп LSASS", "T1003.001", "JC-HC-002-005"],
        ]
    )
    parsed = parse(data, "x.xlsx")
    assert parsed.columns["key"] == "ID Условия"
    assert parsed.columns["techniques"] == "MITREID"
    assert parsed.rows[0].key == "JC-HC-002-005"
    assert parsed.rows[0].techniques == ["T1003.001"]
    assert parsed.rows[0].note == "Дамп LSASS"


def test_several_techniques_in_one_cell() -> None:
    """В одной клетке их бывает несколько — в файле заказчика до четырёх."""
    data = _xlsx(
        [
            ["ID Условия", "MITREID"],
            ["JC-HC-002-001", "T1053, T1036, T1053.003, T1112"],
            ["JC-HC-002-002", "T1204.002,  T1566.001"],
        ]
    )
    parsed = parse(data, "x.xlsx")
    assert parsed.rows[0].techniques == ["T1036", "T1053", "T1053.003", "T1112"]
    assert parsed.rows[1].techniques == ["T1204.002", "T1566.001"]


def test_rows_without_techniques_are_counted_not_dropped_silently() -> None:
    """Строка без техники — не разметка, но и не мусор: её надо посчитать."""
    data = _xlsx(
        [
            ["ID Условия", "MITREID"],
            ["JC-HC-002-001", "T1053"],
            ["JC-HC-002-002", ""],
            ["JC-HC-002-003", "не знаю"],
        ]
    )
    parsed = parse(data, "x.xlsx")
    assert len(parsed.rows) == 1
    assert parsed.without_techniques == 2


def test_csv_is_read_too() -> None:
    """Выгрузка из Excel в русской локали идёт с точкой с запятой."""
    data = "ID Условия;Описание;MITREID\nJC-AC-020-001;Вход;T1078\n".encode()
    parsed = parse(data, "x.csv")
    assert parsed.rows[0].key == "JC-AC-020-001"
    assert parsed.rows[0].techniques == ["T1078"]


def test_file_of_the_wrong_shape_gives_nothing_rather_than_guesses() -> None:
    data = "колонка;другая\nзначение;ещё\n".encode()
    assert parse(data, "x.csv").rows == []


def test_code_key_ignores_vendor_prefix_and_rule_name() -> None:
    """`JC-AC-020-001` и `DEMO_AC_020_001_Long_Name` — одно правило.

    У заказчика в таблице свой префикс, а в выгрузке свой; общее —
    категория, группа и номер.
    """
    assert code_key("JC-AC-020-001") == code_key("DEMO_AC_020_001_Same_Account_Auth")
    assert code_key("JC-HC-002-005") == "HC_002_005"
    assert code_key("короткое") == ""


def test_shipped_sample_parses_as_intended() -> None:
    """Образец, который аналитик скачивает с экрана сверки, должен разбираться
    ровно так, как обещает: иначе заполненный по нему файл не загрузится."""
    sample = (
        Path(__file__).resolve().parents[3]
        / "frontend" / "public" / "samples" / "attack-reference-sample.csv"
    )
    parsed = parse(sample.read_bytes(), sample.name)
    assert [row.key for row in parsed.rows] == [
        "JC-AC-020-001", "JC-AC-021-003", "JC-PS-105-002",
    ]
    assert parsed.rows[1].techniques == ["T1110.001", "T1110.003"]
    assert parsed.rows[1].note.startswith("Подбор пароля")
    assert parsed.without_techniques == 1


def test_xlsx_member_over_limit_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Аудит H2: xlsx — тот же zip, и распаковывается с тем же потолком."""
    monkeypatch.setattr(safe_io, "ZIP_MEMBER_LIMIT", 1024 * 1024)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("xl/sharedStrings.xml", " " * (2 * 1024 * 1024))
        archive.writestr("xl/worksheets/sheet1.xml", "<worksheet/>")
    with pytest.raises(ValueError, match="распакованный размер больше лимита"):
        parse(buf.getvalue(), "t.xlsx")
