"""Загрузка эталона и сверка с ним."""
from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.api.test_attack_markup import _grouped_zip, upload_and_wait


@pytest.fixture
def snapshot_id(auth_client: TestClient) -> int:
    return int(upload_and_wait(auth_client, _grouped_zip())["snapshot_id"])


def _csv(lines: list[str]) -> bytes:
    return ("ID Условия;MITREID\n" + "\n".join(lines) + "\n").encode()


def _upload(client: TestClient, snapshot_id: int, data: bytes) -> dict[str, Any]:
    response = client.post(
        f"/api/siem/attack/reference?snapshot_id={snapshot_id}",
        files={"file": ("mapping.csv", data, "text/csv")},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_rules_are_matched_by_code_across_vendor_prefixes(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Префикс в таблице свой, в выгрузке свой — сопоставление по коду.

    В файле заказчика правила названы `JC-HC-002-000`, а в выгрузке —
    `DEMO_HC_002_000_Rule`. Требовать совпадения имён значит не сопоставить
    ничего.
    """
    body = _upload(auth_client, snapshot_id, _csv(["JC-HC-002-000;T1059.001"]))
    assert body["matched_rules"] == 1
    assert body["matched_by"] == {"code": 1}
    assert body["unmatched_keys"] == []


def test_unmatched_rows_are_reported_not_swallowed(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """«В вашей таблице правило, которого нет в выгрузке» — это находка."""
    body = _upload(
        auth_client, snapshot_id, _csv(["JC-HC-002-000;T1059.001", "JC-ZZ-999-999;T1078"])
    )
    assert body["matched_rules"] == 1
    assert body["unmatched_keys"] == ["JC-ZZ-999-999"]

    compare = auth_client.get(
        f"/api/siem/attack/reference/compare?snapshot_id={snapshot_id}"
    ).json()
    assert [u["source_key"] for u in compare["unmatched"]] == ["JC-ZZ-999-999"]
    # И обратная сторона: правила выгрузки, которых нет в эталоне.
    assert compare["rules_without_reference"] == 11


def test_revoked_techniques_are_migrated_on_import(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Эталон размечен на прошлой версии ATT&CK — это не расхождение.

    В таблице заказчика 17 ссылок на семейство T1562, отозванное
    в 19-й версии. Без переноса каждая читалась бы как спор с моделью,
    хотя техника просто переехала.
    """
    body = _upload(auth_client, snapshot_id, _csv(["JC-HC-002-000;T1562.001"]))
    assert body["migrated_techniques"] == 1
    assert body["unknown_techniques"] == []

    compare = auth_client.get(
        f"/api/siem/attack/reference/compare?snapshot_id={snapshot_id}"
    ).json()
    item = compare["items"][0]
    assert item["theirs"] == ["T1685"]
    # Исходное значение сохранено: перенос должен быть виден, а не молчалив.
    assert item["original"] == ["T1562.001"]


def test_verdicts_separate_disagreement_from_depth(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Разная глубина — не спор.

    Наш `T1059` и эталонный `T1059.001` описывают одно и то же с разной
    точностью; считать это расхождением значит утопить настоящие споры
    в шуме.
    """
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    rules = auth_client.get(
        f"/api/siem/attack/group?snapshot_id={snapshot_id}&group={groups['items'][0]['group']}"
    ).json()["rules"]

    auth_client.post(
        "/api/siem/attack/confirm",
        json={"snapshot_id": snapshot_id, "rule_uuid": rules[0]["uuid"], "techniques": ["T1059"]},
    )
    auth_client.post(
        "/api/siem/attack/confirm",
        json={"snapshot_id": snapshot_id, "rule_uuid": rules[1]["uuid"], "techniques": ["T1047"]},
    )
    from api.modules.siem.services.reference import code_key

    _upload(
        auth_client,
        snapshot_id,
        _csv(
            [
                f"JC-{code_key(rules[0]['name']).replace('_', '-')};T1059.001",
                f"JC-{code_key(rules[1]['name']).replace('_', '-')};T1078",
            ]
        ),
    )
    compare = auth_client.get(
        f"/api/siem/attack/reference/compare?snapshot_id={snapshot_id}"
    ).json()
    by_rule = {i["uuid"]: i for i in compare["items"]}
    assert by_rule[rules[0]["uuid"]]["verdict"] == "reference_finer"
    assert by_rule[rules[1]["uuid"]]["verdict"] == "different"


def test_import_replaces_rather_than_merges(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Эталон — один документ целиком.

    Слияние двух версий таблицы дало бы разметку, которой нет ни в одной
    из них, и объяснить её происхождение стало бы нечем.
    """
    _upload(auth_client, snapshot_id, _csv(["JC-HC-002-000;T1059.001"]))
    _upload(auth_client, snapshot_id, _csv(["JC-HC-002-001;T1078"]))
    compare = auth_client.get(
        f"/api/siem/attack/reference/compare?snapshot_id={snapshot_id}"
    ).json()
    assert [i["source_key"] for i in compare["items"]] == ["JC-HC-002-001"]


def test_file_without_recognisable_columns_is_refused_with_a_reason(
    auth_client: TestClient, snapshot_id: int
) -> None:
    response = auth_client.post(
        f"/api/siem/attack/reference?snapshot_id={snapshot_id}",
        files={"file": ("x.csv", b"one;two\nvalue;other\n", "text/csv")},
    )
    assert response.status_code == 422
    assert "T1059" in response.json()["detail"]


def test_reference_never_becomes_our_markup(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Эталон — мнение, с которым сверяются, а не запись, которую пишут.

    Молча подменить разметку чужой таблицей значит лишить продукт
    возможности показать разницу — ради которой эталон и грузят.
    """
    _upload(auth_client, snapshot_id, _csv(["JC-HC-002-000;T1059.001"]))
    coverage = auth_client.get(f"/api/siem/attack/coverage?snapshot_id={snapshot_id}").json()
    assert coverage["confirmed"] == 0
    assert coverage["techniques_covered"] == 0

    compare = auth_client.get(
        f"/api/siem/attack/reference/compare?snapshot_id={snapshot_id}"
    ).json()
    assert compare["items"][0]["verdict"] == "no_markup"


def test_reference_can_be_dropped_without_touching_markup(
    auth_client: TestClient, snapshot_id: int
) -> None:
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    auth_client.post(
        "/api/siem/attack/confirm",
        json={
            "snapshot_id": snapshot_id,
            "group": groups["items"][0]["group"],
            "techniques": ["T1047"],
        },
    )
    _upload(auth_client, snapshot_id, _csv(["JC-HC-002-000;T1059.001"]))
    assert auth_client.delete("/api/siem/attack/reference").status_code == 204

    compare = auth_client.get(
        f"/api/siem/attack/reference/compare?snapshot_id={snapshot_id}"
    ).json()
    assert compare["loaded"] is False
    assert compare["items"] == []
    coverage = auth_client.get(f"/api/siem/attack/coverage?snapshot_id={snapshot_id}").json()
    assert coverage["confirmed"] > 0


def test_reference_can_be_accepted_as_markup(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Эталон можно принять — но только по явной команде.

    Это работа аналитиков заказчика, и она точнее модели. Но подмена
    должна быть решением человека, а не побочным действием загрузки
    файла: иначе сверять станет не с чем.
    """
    _upload(auth_client, snapshot_id, _csv(["JC-HC-002-000;T1059.001"]))
    before = auth_client.get(f"/api/siem/attack/coverage?snapshot_id={snapshot_id}").json()
    assert before["confirmed"] == 0

    result = auth_client.post(
        "/api/siem/attack/reference/apply", json={"snapshot_id": snapshot_id}
    ).json()
    assert result["applied"] == 1

    after = auth_client.get(f"/api/siem/attack/coverage?snapshot_id={snapshot_id}").json()
    assert after["confirmed"] == 1
    # Разметка относится к правилу, а не унаследована от группы.
    assert after["inherited"] == 0

    compare = auth_client.get(
        f"/api/siem/attack/reference/compare?snapshot_id={snapshot_id}"
    ).json()
    item = compare["items"][0]
    assert item["verdict"] == "same"
    assert item["ours"] == ["T1059.001"]


def test_accepted_reference_records_where_it_came_from(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Источник `reference`, а не `manual`.

    Решение принимал человек, но в чужом документе. Через полгода это
    единственный способ вспомнить, откуда у правила взялась техника.
    """
    _upload(auth_client, snapshot_id, _csv(["JC-HC-002-000;T1059.001"]))
    auth_client.post("/api/siem/attack/reference/apply", json={"snapshot_id": snapshot_id})

    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    technique = next(
        t
        for g in groups["items"]
        for t in g["techniques"]
        if t["technique_id"] == "T1059.001"
    )
    assert technique["source"] == "reference"
    assert "mapping.csv" in technique["evidence"]


def test_accepted_reference_survives_a_model_run(
    auth_client: TestClient, snapshot_id: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Прогон модели не затирает принятый эталон.

    Он записан подтверждённым, а подтверждённое человеком — единственное
    в системе, что стоит человеко-часов, и модель его не трогает.
    """
    import api.modules.siem.services.attack as service

    def fake_embed(self: Any, texts: list[str]) -> list[list[float]]:
        return [[1.0, 0.0] for _ in texts]

    def fake_complete(self: Any, prompt: str, schema: Any) -> str:
        import json as _json

        first = schema["properties"]["techniques"]["items"]["properties"]["technique_id"]["enum"][0]
        return _json.dumps(
            {"techniques": [{"technique_id": first, "confidence": "низкая", "evidence": "т"}]}
        )

    monkeypatch.setattr(service.OllamaEmbedder, "embed", fake_embed)
    monkeypatch.setattr(service.OllamaCompletion, "complete", fake_complete)

    _upload(auth_client, snapshot_id, _csv(["JC-HC-002-000;T1059.001"]))
    auth_client.post("/api/siem/attack/reference/apply", json={"snapshot_id": snapshot_id})
    auth_client.put(
        "/api/settings/llm", json={"base_url": "http://x.invalid:11434", "enabled": True}
    )
    auth_client.put("/api/siem/settings", json={"attack": {"top_k": 5}})
    job_id = auth_client.post(
        "/api/siem/attack/run", json={"snapshot_id": snapshot_id}
    ).json()["job_id"]
    assert auth_client.get(f"/api/siem/jobs/{job_id}").json()["status"] == "done"

    compare = auth_client.get(
        f"/api/siem/attack/reference/compare?snapshot_id={snapshot_id}"
    ).json()
    assert compare["items"][0]["ours"] == ["T1059.001"]


def test_only_selected_verdicts_are_accepted(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Принять можно выборочно — например только там, где мы промолчали."""
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    rules = auth_client.get(
        f"/api/siem/attack/group?snapshot_id={snapshot_id}&group={groups['items'][0]['group']}"
    ).json()["rules"]
    auth_client.post(
        "/api/siem/attack/confirm",
        json={"snapshot_id": snapshot_id, "rule_uuid": rules[0]["uuid"], "techniques": ["T1047"]},
    )
    from api.modules.siem.services.reference import code_key

    _upload(
        auth_client,
        snapshot_id,
        _csv(
            [
                f"JC-{code_key(rules[0]['name']).replace('_', '-')};T1078",
                f"JC-{code_key(rules[1]['name']).replace('_', '-')};T1078",
            ]
        ),
    )
    result = auth_client.post(
        "/api/siem/attack/reference/apply",
        json={"snapshot_id": snapshot_id, "verdicts": ["no_markup"]},
    ).json()
    assert result["applied"] == 1

    compare = auth_client.get(
        f"/api/siem/attack/reference/compare?snapshot_id={snapshot_id}"
    ).json()
    by_rule = {i["uuid"]: i for i in compare["items"]}
    # Наше решение по первому правилу не тронуто: там мы не молчали.
    assert by_rule[rules[0]["uuid"]]["ours"] == ["T1047"]
    assert by_rule[rules[1]["uuid"]]["ours"] == ["T1078"]
