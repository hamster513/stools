"""Табличные списки: состав отдаётся только по явному запросу.

Содержимое списков — самое чувствительное, что есть в выгрузке: это и
есть инвентарь внутренней инфраструктуры. Тесты сторожат именно это,
а не форму ответа.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def test_list_of_tables_carries_no_values(auth_client: TestClient, snapshot_id: int) -> None:
    """В перечне списков только числа: значения не должны появляться там,
    где их никто не запрашивал."""
    body = auth_client.get(f"/api/siem/tables?snapshot_id={snapshot_id}").json()
    assert body["total"] > 0
    item = body["items"][0]
    assert set(item) == {"name", "value_count", "is_empty", "read_by"}
    assert "srv99" not in auth_client.get(f"/api/siem/tables?snapshot_id={snapshot_id}").text


def test_values_come_only_on_explicit_request(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Без состава решение принять нельзя: перечень критичных узлов и
    справочник соответствий по имени неотличимы."""
    body = auth_client.get(
        f"/api/siem/tables/values?name=DEMO_Critical_Hosts_by_Rule&snapshot_id={snapshot_id}"
    ).json()
    assert body["total"] == 1
    assert body["rows"] == [{"host": "srv99"}]


def test_columns_are_not_flattened_into_one_heap(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """В списке рядом лежат идентификатор, имя узла и комментарий,
    написанный человеком для себя. Слитые в одну колонку, они не говорят
    ничего: по ним принимают разные решения."""
    body = auth_client.get(
        f"/api/siem/tables/values?name=DEMO_Hosts_with_notes&snapshot_id={snapshot_id}"
    ).json()
    assert body["columns"] == ["host", "description"]
    assert body["comment_columns"] == ["description"]
    assert body["rows"][0] == {"host": "srv01", "description": "согласовано, тикет 4242"}


def test_values_are_capped(auth_client: TestClient, snapshot_id: int) -> None:
    """Списки бывают в тысячи строк. Человеку нужно понять, что это
    за список, а не получить его копию."""
    response = auth_client.get(
        f"/api/siem/tables/values?name=DEMO_Critical_Hosts_by_Rule"
        f"&snapshot_id={snapshot_id}&limit=999"
    )
    assert response.status_code == 422, "предел количества задан жёстко"


def test_unknown_table_is_a_404(auth_client: TestClient, snapshot_id: int) -> None:
    assert (
        auth_client.get(
            f"/api/siem/tables/values?name=НЕТ_ТАКОГО&snapshot_id={snapshot_id}"
        ).status_code
        == 404
    )


def test_readers_show_which_rules_the_decision_affects(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Отметить список ограничивающим — значит объявить, что все читающие
    его правила работают не шире его содержимого."""
    body = auth_client.get(
        f"/api/siem/tables/readers?name=DEMO_Critical_Hosts_by_Rule&snapshot_id={snapshot_id}"
    ).json()
    assert body["total"] >= 1
    assert all("name" in r and "uuid" in r for r in body["items"])


def test_tables_require_a_session(client: TestClient, snapshot_id: int) -> None:
    """Проверка на всякий случай: состав списков — не то, что стоит
    отдавать без сессии по недосмотру в подключении роутера."""
    client.post("/api/auth/logout")
    assert client.get(f"/api/siem/tables?snapshot_id={snapshot_id}").status_code == 401
    assert (
        client.get(f"/api/siem/tables/values?name=X&snapshot_id={snapshot_id}").status_code == 401
    )
