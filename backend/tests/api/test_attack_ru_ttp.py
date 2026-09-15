"""Слой применяемости техник в России поверх мировых данных."""
from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.api.test_attack_markup import _grouped_zip, upload_and_wait
from tests.attack.test_reference import _xlsx

_HEADER = ["ID", "Техника", "Тактика", "Процедура", "Командная строка", "Связи"]


@pytest.fixture
def snapshot_id(auth_client: TestClient) -> int:
    return int(upload_and_wait(auth_client, _grouped_zip())["snapshot_id"])


def _upload(client: TestClient, rows: list[list[str]]) -> dict[str, Any]:
    response = client.post(
        "/api/attack/ru-ttp",
        files={
            "file": (
                "bizone.xlsx",
                _xlsx([_HEADER, *rows]),
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_upload_reports_what_was_taken(auth_client: TestClient) -> None:
    body = _upload(
        auth_client,
        [
            ["T1059.001", "PowerShell", "Execution", "Запуск скрипта", "powershell -enc", "adversary:Fair Werewolf"],
            ["T1486", "Data Encrypted for Impact", "Impact", "Шифрует диск", "", "malware:Nova"],
        ],
    )
    assert body["rows"] == 2
    assert body["techniques"] == 2
    assert body["unknown"] == []
    # Колонка тактик не берётся: она повторяет тактики техники из матрицы.
    assert "tactic" not in body["columns"]


def test_second_upload_replaces_the_first(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Выгрузка — один документ на дату.

    Слияние двух её версий дало бы картину, которой нет ни в одной из них.
    """
    _upload(auth_client, [["T1486", "", "Impact", "Шифрует", "", "malware:Nova"]])
    _upload(auth_client, [["T1105", "", "Command and Control", "Загрузка", "curl", ""]])
    body = auth_client.get("/api/attack/matrix").json()
    cells = {c["technique_id"]: c for t in body["tactics"] for c in t["techniques"]}
    assert cells["T1105"]["ru"]["procedures"] == 1
    assert cells["T1486"]["ru"] is None


def test_state_separates_four_cases_not_two(auth_client: TestClient) -> None:
    """«Только мир» не значит «здесь не применяют», и наоборот.

    T1496 Resource Hijacking мировая статистика не знает вовсе — это и
    есть техника, вес которой она занижает.
    """
    _upload(
        auth_client,
        [
            ["T1496", "Resource Hijacking", "Impact", "Майнер", "", "adversary:Dune Werewolf"],
            ["T1059.001", "PowerShell", "Execution", "Запуск", "powershell", "adversary:Fair Werewolf"],
        ],
    )
    state = auth_client.get("/api/attack/ru-ttp").json()
    assert state["counts"]["ru_only"] >= 1
    assert state["counts"]["both"] >= 1
    assert state["counts"]["world_only"] > 0
    assert [i["technique_id"] for i in state["ru_only"]] == ["T1496"]
    assert state["source"]["source"] == "bizone.xlsx"


def test_matrix_carries_the_layer_and_says_whose_it_is(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Показывать чужую аналитику как безымянный факт нельзя."""
    _upload(
        auth_client,
        [["T1059.001", "PowerShell", "Execution", "Запуск", "powershell", "adversary:Fair Werewolf"]],
    )
    body = auth_client.get("/api/attack/matrix").json()
    cells = {c["technique_id"]: c for t in body["tactics"] for c in t["techniques"]}
    # Разметка подтехникой засчитывается родителю — в матрице клетка одна.
    assert cells["T1059"]["ru"]["actors"] == 1
    assert cells["T1059"]["ru"]["commands"] == 1
    assert body["ru_source"]["source"] == "bizone.xlsx"


def test_without_the_layer_cells_stay_empty_not_zero(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Ноль читался бы как «здесь не применяют», а никто не отчитывался."""
    body = auth_client.get("/api/attack/matrix").json()
    cells = {c["technique_id"]: c for t in body["tactics"] for c in t["techniques"]}
    assert cells["T1059"]["ru"] is None
    assert body["ru_source"] is None


def test_technique_card_shows_procedures_with_commands_first(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Ради процедур выгрузку и загружают: это материал для правила."""
    _upload(
        auth_client,
        [
            ["T1059.001", "PowerShell", "Execution", "Без команды", "", "adversary:Fair Werewolf"],
            ["T1059.001", "PowerShell", "Execution", "С командой", "powershell -enc SQBFAFgA", "adversary:Fair Werewolf"],
        ],
    )
    body = auth_client.get("/api/attack/technique/T1059").json()
    assert [p["procedure"] for p in body["ru_procedures"]] == ["С командой", "Без команды"]
    assert body["ru_procedures"][0]["actors"] == ["Fair Werewolf"]


def test_subtechniques_seen_here_come_first(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Человек уточняет разметку ради своей инфраструктуры.

    T1059.003 в мировых данных распространённее, чем T1059.008, но если
    здесь замечена именно восьмая — начинать надо с неё.
    """
    _upload(
        auth_client,
        [["T1059.008", "Network Device CLI", "Execution", "Команды на маршрутизаторе", "", "adversary:Dune Werewolf"]],
    )
    body = auth_client.get("/api/attack/technique/T1059").json()
    assert body["subtechniques"][0]["technique_id"] == "T1059.008"


def test_drop_removes_the_layer_only(auth_client: TestClient, snapshot_id: int) -> None:
    _upload(auth_client, [["T1486", "", "Impact", "Шифрует", "", "malware:Nova"]])
    assert auth_client.delete("/api/attack/ru-ttp").status_code == 204
    assert auth_client.get("/api/attack/ru-ttp").json()["source"] is None
    # Мировые данные на месте: слой снят, матрица работает как раньше.
    body = auth_client.get("/api/attack/matrix").json()
    cells = {c["technique_id"]: c for t in body["tactics"] for c in t["techniques"]}
    assert cells["T1486"]["actor_groups"] > 0


def test_foreign_file_is_refused_with_a_readable_reason(auth_client: TestClient) -> None:
    """Отказ должен объяснять, чего не хватило, а не сообщать код."""
    response = auth_client.post(
        "/api/attack/ru-ttp",
        files={"file": ("rules.xlsx", _xlsx([["Правило", "Описание"], ["JC-HC-002", "Дамп"]]), "x")},
    )
    assert response.status_code == 422
    assert "техник" in response.json()["detail"]
