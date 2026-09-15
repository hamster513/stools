"""Разбор выгрузки «техника → процедура» с применяемостью в России."""
from __future__ import annotations

from kbaudit.attack.ru_ttp import parse
from tests.attack.test_reference import _xlsx

_HEADER = ["ID", "Техника", "Тактика", "Процедура", "Командная строка", "Связи"]


def test_columns_are_found_by_name_not_position() -> None:
    """Формат чужой и меняться будет: порядок колонок не гарантирован."""
    data = _xlsx(
        [
            ["Связи", "Процедура", "Тактика", "Техника", "ID", "Командная строка"],
            ["adversary:Fair Werewolf", "Дамп LSASS", "Credential Access", "LSASS Memory", "T1003.001", "procdump -ma lsass.exe"],
        ]
    )
    parsed = parse(data, "x.xlsx")
    assert parsed.columns["technique"] == "ID"
    assert parsed.columns["name"] == "Техника"
    assert parsed.rows[0].technique_id == "T1003.001"
    assert parsed.rows[0].technique_name == "LSASS Memory"
    assert parsed.rows[0].procedure == "Дамп LSASS"
    assert parsed.rows[0].command_line == "procdump -ma lsass.exe"
    assert parsed.rows[0].actors == ["Fair Werewolf"]


def test_tactic_column_is_ignored() -> None:
    """Колонка тактик избыточна: она повторяет тактики техники из матрицы.

    Словарь тот же, что у MITRE 19.2, и на всех строках файла набор равен
    матричному — своего знания в колонке нет. Копия же разойдётся с
    оригиналом при обновлении матрицы.
    """
    data = _xlsx(
        [
            _HEADER,
            ["T1055", "Process Injection", "Stealth;\nPrivilege Escalation", "Внедрение в процесс", "", ""],
        ]
    )
    parsed = parse(data, "x.xlsx")
    assert "tactic" not in parsed.columns
    assert not any("Stealth" in value for value in parsed.rows[0].model_dump().values() if isinstance(value, str))


def test_links_are_split_by_prefix_not_by_comma() -> None:
    """Внутри значений есть свои запятые.

    «attack: …уязвимость, отслеживаемая как CVE-…» при делении по запятой
    даёт сущность с именем «отслеживаемая как CVE-…». Значения выделяются
    по префиксам, а сами `attack:` и `darkweb:` — это заголовки отчётов,
    а не действующие лица, и в сущности не попадают.
    """
    links = (
        "adversary:Chanting Werewolf, malware:Strela Stealer, "
        "attack:Обнаружена уязвимость обхода защиты в Windows BitLocker, "
        "отслеживаемая как CVE-2026-50507, tool:Cobalt Strike"
    )
    data = _xlsx([_HEADER, ["T1059.001", "PowerShell", "Execution", "Запуск", "", links]])
    row = parse(data, "x.xlsx").rows[0]
    assert row.actors == ["Chanting Werewolf"]
    assert row.malware == ["Strela Stealer"]
    assert row.tools == ["Cobalt Strike"]


def test_identifier_is_taken_out_of_a_messy_cell() -> None:
    """В клетке идентификатора бывает не только идентификатор."""
    data = _xlsx([_HEADER, ["T1059.003 (Windows Command Shell)", "", "", "cmd /c", "", ""]])
    assert parse(data, "x.xlsx").rows[0].technique_id == "T1059.003"


def test_rows_without_a_technique_are_counted_not_dropped_silently() -> None:
    """Строка без идентификатора — не ошибка файла, но и не данные.

    Молча терять её нельзя: расхождение числа строк с тем, что видит
    человек в Excel, он воспримет как потерю данных, и будет прав.
    """
    data = _xlsx(
        [
            _HEADER,
            ["T1105", "Ingress Tool Transfer", "Command and Control", "Загрузка", "curl", ""],
            ["", "", "", "Строка без техники", "", ""],
        ]
    )
    parsed = parse(data, "x.xlsx")
    assert len(parsed.rows) == 1
    assert parsed.without_technique == 1


def test_one_technique_keeps_every_procedure() -> None:
    """Процедуры не схлопываются: ради них выгрузку и загружают."""
    data = _xlsx(
        [
            _HEADER,
            ["T1486", "Data Encrypted for Impact", "Impact", "Шифрует диск", "", "malware:Nova"],
            ["T1486", "Data Encrypted for Impact", "Impact", "Удаляет теневые копии", "vssadmin delete shadows", "malware:Nova"],
        ]
    )
    parsed = parse(data, "x.xlsx")
    assert [r.procedure for r in parsed.rows] == ["Шифрует диск", "Удаляет теневые копии"]


def test_foreign_file_gives_an_empty_result() -> None:
    """Пустой результат — законный ответ на файл не того формата.

    Решение, что с этим делать, принимает вызывающий.
    """
    data = _xlsx([["Правило", "Описание"], ["JC-HC-002-005", "Дамп LSASS"]])
    parsed = parse(data, "x.xlsx")
    assert parsed.rows == []
    assert parsed.columns == {}
