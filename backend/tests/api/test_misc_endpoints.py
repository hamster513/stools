"""Беглая проверка остальных ручек — не полное покрытие каждой ветки,
а страховка от явных ошибок сборки ответа (опечатка в поле, забытый JOIN)."""
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient


def test_rules_list_and_detail(auth_client: TestClient, snapshot_id: int) -> None:
    listing = auth_client.get("/api/siem/rules", params={"snapshot_id": snapshot_id})
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] == 2
    names = {r["name"] for r in body["items"]}
    assert names == {"DEMO_HC_002_029_Impacket", "DEMO_HC_002_030_Other"}
    impacket = next(r for r in body["items"] if r["name"] == "DEMO_HC_002_029_Impacket")
    assert impacket["finding_count"] == 1
    assert "DEMO_Critical_Hosts_by_Rule" in impacket["table_reads"]

    detail = auth_client.get(
        f"/api/siem/rules/{impacket['uuid']}", params={"snapshot_id": snapshot_id}
    )
    assert detail.status_code == 200
    detail_body = detail.json()
    assert detail_body["body"] is not None and "srv99" in detail_body["body"]
    assert len(detail_body["findings"]) == 1


def test_rule_detail_tells_which_read_lists_are_missing_or_empty(
    auth_client: TestClient, snapshot_id: int, db_session: Any
) -> None:
    """Правило, читающее отсутствующий или пустой список, не сработает ни
    на чём. Карточка должна сказать это рядом с телом, а не только в
    профиле инсталляции, где правило ещё надо найти."""
    from api.db.models import RuleTableRef, TableListRow

    impacket = next(
        r
        for r in auth_client.get("/api/siem/rules", params={"snapshot_id": snapshot_id}).json()["items"]
        if r["name"] == "DEMO_HC_002_029_Impacket"
    )
    db_session.add_all(
        [
            RuleTableRef(
                snapshot_id=snapshot_id, rule_uuid=impacket["uuid"],
                table_name="DEMO_Empty_List", direction="read",
            ),
            RuleTableRef(
                snapshot_id=snapshot_id, rule_uuid=impacket["uuid"],
                table_name="DEMO_Missing_List", direction="read",
            ),
            TableListRow(snapshot_id=snapshot_id, name="DEMO_Empty_List", value_count=0),
        ]
    )
    db_session.commit()

    detail = auth_client.get(
        f"/api/siem/rules/{impacket['uuid']}", params={"snapshot_id": snapshot_id}
    ).json()
    tables = {t["name"]: t for t in detail["tables"]}
    assert tables["DEMO_Critical_Hosts_by_Rule"] == {
        "name": "DEMO_Critical_Hosts_by_Rule", "exists": True, "value_count": 1,
    }
    assert tables["DEMO_Empty_List"] == {"name": "DEMO_Empty_List", "exists": True, "value_count": 0}
    assert tables["DEMO_Missing_List"] == {
        "name": "DEMO_Missing_List", "exists": False, "value_count": None,
    }
    assert [t["name"] for t in detail["tables"]] == detail["table_reads"]


def test_rules_list_item_has_no_body(auth_client: TestClient, snapshot_id: int) -> None:
    listing = auth_client.get("/api/siem/rules", params={"snapshot_id": snapshot_id}).json()
    for item in listing["items"]:
        assert "body" not in item


def test_divergences(auth_client: TestClient, snapshot_id: int) -> None:
    response = auth_client.get("/api/siem/divergences", params={"snapshot_id": snapshot_id})
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["items"][0]["hardcoded_in"] == "DEMO_HC_002_029_Impacket"
    assert "value" not in body["items"][0]


def test_clones_empty_for_two_unrelated_rules(auth_client: TestClient, snapshot_id: int) -> None:
    response = auth_client.get("/api/siem/clones", params={"snapshot_id": snapshot_id})
    assert response.status_code == 200
    assert response.json() == []


def test_graph_has_no_edges_for_independent_rules(auth_client: TestClient, snapshot_id: int) -> None:
    response = auth_client.get("/api/siem/graph", params={"snapshot_id": snapshot_id})
    assert response.status_code == 200
    body = response.json()
    assert body["edges"] == []
    assert body["unresolved"] == {}


def test_profile_suggest_and_put_recomputes_scoped_count(
    auth_client: TestClient, snapshot_id: int
) -> None:
    suggest = auth_client.get("/api/siem/profile/suggest", params={"snapshot_id": snapshot_id})
    assert suggest.status_code == 200

    before = auth_client.get(f"/api/siem/snapshots/{snapshot_id}").json()
    assert before["scoped_count"] == 0
    assert before["profile_confirmed"] is False

    put = auth_client.put(
        "/api/siem/profile",
        json={
            "snapshot_id": snapshot_id,
            "tables": {"scoping": ["DEMO_Critical_Hosts_by_Rule"], "watched": []},
        },
    )
    assert put.status_code == 204

    after = auth_client.get(f"/api/siem/snapshots/{snapshot_id}").json()
    assert after["scoped_count"] == 1, "правило, читающее scoping-список, должно стать scoped"
    assert after["profile_confirmed"] is True

    rules = auth_client.get("/api/siem/rules", params={"snapshot_id": snapshot_id}).json()
    impacket = next(r for r in rules["items"] if r["name"] == "DEMO_HC_002_029_Impacket")
    assert impacket["scoped"] is True


def test_fields_show_which_ones_have_no_role(auth_client: TestClient, snapshot_id: int) -> None:
    """Поле без роли не анализируется вовсе: захардкоженное в нём значение
    проходит мимо молча. На эталонной выгрузке роли нет у 97 полей из 123,
    и без такого сопоставления об этом не догадаться."""
    body = auth_client.get(f"/api/siem/profile/fields?snapshot_id={snapshot_id}").json()
    assert body["total"] > 0
    by_field = {i["field"]: i for i in body["items"]}
    assert by_field["subject.account.name"]["role"] == "environmental"
    # msgid сюда не попадает намеренно: он собирается отдельно как
    # требование к событию, а не как поле, с которым сравнивают литерал.
    assert "msgid" not in by_field
    assert all(i["from_profile"] is False for i in body["items"]), "профиль пуст"


def test_field_role_from_profile_is_marked_as_such(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Роль, заданную человеком, надо отличать от встроенной: снять
    можно только свою."""
    auth_client.put(
        "/api/siem/profile",
        json={
            "snapshot_id": snapshot_id,
            "tables": {"scoping": [], "watched": []},
            "builtin_accounts": [],
            "field_roles": {"environmental": ["dst.ip"], "technical": []},
        },
    )
    body = auth_client.get(f"/api/siem/profile/fields?snapshot_id={snapshot_id}").json()
    row = next(i for i in body["items"] if i["field"] == "dst.ip")
    assert row["role"] == "environmental"
    assert row["from_profile"] is True


def test_preview_shows_the_cost_without_saving(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Одно поле на эталонной выгрузке добавляет до семидесяти замечаний.
    Принимать такое решение вслепую, а потом искать, откуда взялась сотня
    новых находок, — плохой порядок."""
    before = auth_client.get(f"/api/siem/snapshots/{snapshot_id}").json()["finding_count"]

    body = auth_client.post(
        "/api/siem/profile/preview",
        json={
            "snapshot_id": snapshot_id,
            "tables": {"scoping": ["DEMO_Critical_Hosts_by_Rule"], "watched": []},
            "builtin_accounts": [],
            "field_roles": {"environmental": [], "technical": []},
        },
    ).json()
    assert body["scoped_count"] >= 1, "отметка списка меняет число ограниченных правил"

    # Предпросмотр ничего не сохраняет: снапшот остался прежним.
    after = auth_client.get(f"/api/siem/snapshots/{snapshot_id}").json()["finding_count"]
    assert after == before
    assert auth_client.get(f"/api/siem/profile?snapshot_id={snapshot_id}").json()[
        "tables"
    ]["scoping"] == []


def test_declaring_an_account_builtin_removes_its_findings(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Служебная учётка организации — не то же самое, что SYSTEM: одна
    встроена везде, вторая только здесь, и решает это человек."""
    plain = auth_client.post(
        "/api/siem/profile/preview",
        json={
            "snapshot_id": snapshot_id,
            "tables": {"scoping": [], "watched": []},
            "builtin_accounts": [],
            "field_roles": {"environmental": [], "technical": []},
        },
    ).json()["finding_count"]

    with_account = auth_client.post(
        "/api/siem/profile/preview",
        json={
            "snapshot_id": snapshot_id,
            "tables": {"scoping": [], "watched": []},
            "builtin_accounts": ["srv99"],
            "field_roles": {"environmental": [], "technical": []},
        },
    ).json()["finding_count"]
    assert with_account < plain
