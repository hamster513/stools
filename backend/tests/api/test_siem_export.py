"""Выгрузка находок и правил SIEM (спека фильтров и экспорта §2.2). Правила фильтруются на странице, а
выгрузку собирает сервер: «внимание», «ограничено» и статус разметки ATT&CK он применяет сам — так же, как экран."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from api.db.models import RuleRow
from tests.api.conftest import _build_kb_zip, upload_and_wait
from tests.api.test_siem_findings_multi import (
    snap,  # noqa: F401 — фикстура синтетики с тремя находками
)
from tests.export_check import check_export, csv_rows

FINDINGS = ["№", "Класс", "Объект", "Поле", "Полярность", "В списке", "Статус", "Возраст"]
RULES = ["Имя", "Автор", "Категория", "msgid", "Внимание", "ATT&CK", "Ограничено"]


def test_findings(auth_client: TestClient, client_as: Callable[[str], TestClient], snap: int) -> None:  # noqa: F811
    url = "/api/siem/findings/export"
    rows = check_export(auth_client, url, FINDINGS, narrow={"kind": "1"}, snapshot_id=snap)
    listed = auth_client.get("/api/siem/findings", params={"snapshot_id": snap, "sort": "field", "order": "desc"}).json()
    by_field = csv_rows(auth_client, url, snapshot_id=snap, sort="field", order="desc")
    # Порядок — сортировка списка; «№» — порядковый номер; значения находок не выгружаются.
    assert [r[3] for r in by_field[1:]] == [i["field"] for i in listed["items"]]
    assert [r[0] for r in by_field[1:]] == ["1", "2", "3"]
    assert {r[4] for r in rows[1:]} <= {"отрицание", "утверждение"} and {r[5] for r in rows[1:]} <= {"да", "нет"}
    assert "10.20.30.41" not in "".join(";".join(r) for r in rows)
    assert client_as("auditor").get(url, params={"snapshot_id": snap}).status_code == 200


def _names(client: TestClient, **params: object) -> list[str]:
    r = client.get("/api/siem/rules", params={"limit": 2000, **params})
    assert r.status_code == 200, r.text
    return [i["name"] for i in r.json()["items"]]


@pytest.fixture
def rules_snap(auth_client: TestClient, db_session: Any) -> int:
    """Третье правило без находок — «чисто»: отбор «требует внимания» его убирает. Одно правило — ограничено
    списком (у синтетики таких нет), чтобы отбор «ограничено» было чем проверить."""
    snapshot_id = int(upload_and_wait(auth_client, _build_kb_zip(extra_rule=True))["snapshot_id"])
    db_session.execute(update(RuleRow).where(RuleRow.snapshot_id == snapshot_id, RuleRow.name == "DEMO_HC_002_031_Extra")
                       .values(scoped_by_list=True))
    db_session.commit()
    return snapshot_id


def test_rules_filters_match_screen(auth_client: TestClient, client_as: Callable[[str], TestClient], rules_snap: int) -> None:
    url = "/api/siem/rules/export"
    items = auth_client.get("/api/siem/rules", params={"snapshot_id": rules_snap, "limit": 2000}).json()["items"]
    # Правило клиента `attentionLevel`: не разобрано или есть открытые находки.
    attention = [i["name"] for i in items if i["parse_status"] != "ok" or i["open_finding_count"] > 0]
    assert 0 < len(attention) < len(items)
    rows = check_export(auth_client, url, RULES, narrow={"attention": "true"}, snapshot_id=rules_snap)
    assert [r[0] for r in rows[1:]] == [i["name"] for i in items]
    assert [r[0] for r in csv_rows(auth_client, url, snapshot_id=rules_snap, attention="true")[1:]] == attention
    assert _names(auth_client, snapshot_id=rules_snap, attention="true") == attention
    scoped = [i["name"] for i in items if i["scoped"]]
    assert 0 < len(scoped) < len(items)
    assert [r[0] for r in csv_rows(auth_client, url, snapshot_id=rules_snap, scoped="true")[1:]] == scoped
    # Разметки у синтетики нет: «не размечено» — все, «подтверждено» — никто.
    assert len(csv_rows(auth_client, url, snapshot_id=rules_snap, attack="unmapped")) == len(rows)
    assert len(csv_rows(auth_client, url, snapshot_id=rules_snap, attack="confirmed")) == 1
    assert auth_client.get(url, params={"snapshot_id": rules_snap, "attack": "bogus"}).status_code == 422
    cells = {r[0]: r for r in rows[1:]}
    assert cells[attention[0]][4].split()[0] in {"Не разобрано", "Разобрать", "Посмотреть"}
    assert client_as("auditor").get(url, params={"snapshot_id": rules_snap}).status_code == 200


def test_rules_without_category_print_slash(auth_client: TestClient, rules_snap: int, db_session: Any) -> None:
    """Категория и группа не заданы — «/», как на экране, а не «None/None»."""
    db_session.execute(update(RuleRow).where(RuleRow.snapshot_id == rules_snap, RuleRow.name == "DEMO_HC_002_031_Extra")
                       .values(type_id_cat=None, type_id_group=None))
    db_session.commit()
    rows = csv_rows(auth_client, "/api/siem/rules/export", snapshot_id=rules_snap)
    assert {r[0]: r[2] for r in rows[1:]}["DEMO_HC_002_031_Extra"] == "/"
