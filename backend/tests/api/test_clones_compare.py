"""Сравнение пары клонов: сигнатура и тело бок о бок."""
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from api.db.models import ClonePairRow, RuleField, RuleFilterRef, RuleMsgid, RuleRow

BODY_A = 'event Start:\n    key: src.ip\n    filter {\n        msgid == "4624"\n        and subject.name != null\n    }\n'
BODY_B = 'event Start:\n    key: src.ip\n    filter {\n        msgid == "4625"\n        and subject.name != null\n    }\n    within 1h\n'


def _rule(snapshot_id: int, uuid: str, name: str, body: str | None) -> RuleRow:
    return RuleRow(snapshot_id=snapshot_id, uuid=uuid, name=name, body_text=body, title_ru=f"Заголовок {name}")


def _seed(db_session: Any, snapshot_id: int, body_b: str | None = BODY_B) -> None:
    db_session.add_all(
        [
            _rule(snapshot_id, "a" * 32, "DEMO_A", BODY_A),
            _rule(snapshot_id, "b" * 32, "DEMO_B", body_b),
            RuleMsgid(snapshot_id=snapshot_id, rule_uuid="a" * 32, msgid="4624", inherited=False),
            RuleMsgid(snapshot_id=snapshot_id, rule_uuid="b" * 32, msgid="4625", inherited=False),
            RuleMsgid(snapshot_id=snapshot_id, rule_uuid="a" * 32, msgid="4688", inherited=False),
            RuleMsgid(snapshot_id=snapshot_id, rule_uuid="b" * 32, msgid="4688", inherited=False),
            RuleField(snapshot_id=snapshot_id, rule_uuid="a" * 32, field="subject.name"),
            RuleField(snapshot_id=snapshot_id, rule_uuid="b" * 32, field="subject.name"),
            RuleFilterRef(snapshot_id=snapshot_id, rule_uuid="b" * 32, filter_name="Whitelist"),
            ClonePairRow(snapshot_id=snapshot_id, rule_a="DEMO_A", rule_b="DEMO_B", similarity=0.85),
        ]
    )
    db_session.commit()


def test_compare_aligns_bodies_and_splits_signature(
    auth_client: TestClient, db_session: Any, snapshot_id: int
) -> None:
    _seed(db_session, snapshot_id)
    response = auth_client.get(
        "/api/siem/clones/compare",
        params={"snapshot_id": snapshot_id, "rule_a": "DEMO_A", "rule_b": "DEMO_B"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["similarity"] == 0.85
    assert body["a"]["name"] == "DEMO_A" and body["a"]["uuid"] == "a" * 32
    assert body["a"]["title"] == "Заголовок DEMO_A"

    sig = body["signature"]
    assert sig["msgids"] == {"common": ["4688"], "only_a": ["4624"], "only_b": ["4625"]}
    assert sig["fields"] == {"common": ["subject.name"], "only_a": [], "only_b": []}
    assert sig["filters"] == {"common": [], "only_a": [], "only_b": ["Whitelist"]}

    kinds = [line["kind"] for line in body["lines"]]
    assert kinds == ["equal", "equal", "equal", "replace", "equal", "equal", "insert"]
    replaced = body["lines"][3]
    assert replaced["a"] == '        msgid == "4624"' and replaced["b"] == '        msgid == "4625"'
    inserted = body["lines"][6]
    assert inserted["a"] is None and inserted["b"] == "    within 1h"
    assert body["changed_lines"] == 2


def test_compare_survives_missing_body(auth_client: TestClient, db_session: Any, snapshot_id: int) -> None:
    """Тело может отсутствовать (правило не разобрано) — сравнение сигнатур всё равно нужно."""
    _seed(db_session, snapshot_id, body_b=None)
    response = auth_client.get(
        "/api/siem/clones/compare",
        params={"snapshot_id": snapshot_id, "rule_a": "DEMO_A", "rule_b": "DEMO_B"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["b"]["body"] is None
    assert all(line["kind"] == "delete" for line in body["lines"])
    assert body["signature"]["msgids"]["only_b"] == ["4625"]


def test_compare_unknown_rule_is_404(auth_client: TestClient, db_session: Any, snapshot_id: int) -> None:
    _seed(db_session, snapshot_id)
    response = auth_client.get(
        "/api/siem/clones/compare",
        params={"snapshot_id": snapshot_id, "rule_a": "DEMO_A", "rule_b": "DEMO_NOPE"},
    )
    assert response.status_code == 404
