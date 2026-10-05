"""Оценка политики «плохая / нормальная / хорошая» по считаемым находкам: список, карточка, фильтр, находки политики, статусы."""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.modules.ksc.models import KscSnapshot
from api.modules.ksc.services.grade import GRADE_CHECKS
from tests.ksc.kes11 import kes11_export
from tests.ksc.synthetic import NOW, build_export
from tests.ksc.test_api import upload


def _imported(client: TestClient, raw: dict[str, Any]) -> int:
    assert upload(client, raw)["status"] == "done"
    return int(client.get("/api/ksc/snapshots").json()[0]["id"])


def _list(client: TestClient, snap: int, **params: Any) -> dict[str, Any]:
    r = client.get(f"/api/ksc/snapshots/{snap}/policy-list", params=params)
    assert r.status_code == 200, r.text
    return dict(r.json())


def _by_id(body: dict[str, Any]) -> dict[int, dict[str, Any]]:
    return {i["id"]: i for i in body["items"]}


def _policy_findings(client: TestClient, snap: int, policy_id: int) -> list[dict[str, Any]]:
    r = client.get(f"/api/ksc/snapshots/{snap}/policies/{policy_id}/findings")
    assert r.status_code == 200, r.text
    return list(r.json()["items"])


def test_grade_checks() -> None:
    assert {"POLICY_NO_LOCKS", "POLICY_WEAK_LOCKS", "POLICY_EXCLUSION_RISKY", "POLICY_COMPONENT_OFF", "POLICY_NOTIFY_ONLY",
            "POLICY_SELFDEFENSE_OFF", "POLICY_PASSWORD_OFF", "POLICY_THREAT_TYPES_OFF", "POLICY_LOCAL_EXCLUSIONS",
            "POLICY_KEY_UNLOCKED"} == GRADE_CHECKS


def test_grades_good_bad_none(auth_client: TestClient) -> None:
    snap = _imported(auth_client, kes11_export())
    items = _by_id(_list(auth_client, snap))
    # 1 — KES 11 без замечаний; 2 — агент, содержимое не собирается.
    assert (items[1]["grade"], items[1]["findings"]) == ("good", 0)
    assert items[1]["grade_reason"]
    assert (items[2]["grade"], items[2]["grade_reason"], items[2]["findings"]) == (None, "содержимое не собрано", 0)
    # 3 — KES этапа 1 с выдуманными секциями `KLPRSS_*`: словарь не узнал ни одной настройки — не «хорошая», а без оценки;
    # находка POLICY_NO_LOCKS (High) при этом считается.
    assert (items[3]["grade"], items[3]["grade_reason"], items[3]["findings"]) == (None, "настройки политики не распознаны словарём", 1)


def test_bad_on_high(auth_client: TestClient) -> None:
    snap = _imported(auth_client, kes11_export(**{"1d3e35bd/selfDefense.enableSelfDefence": False}))
    item = _by_id(_list(auth_client, snap))[1]
    assert (item["grade"], item["findings"]) == ("bad", 1)


def test_unrecognised_settings_not_good(auth_client: TestClient) -> None:
    """Синтетика этапа 1 (`build_export`): обе политики KES — со словарём продукта, но без единой распознанной настройки."""
    snap = _imported(auth_client, build_export())
    items = _by_id(_list(auth_client, snap))
    assert (items[1]["grade"], items[1]["grade_reason"], items[1]["findings"]) == (None, "настройки политики не распознаны словарём", 0)
    assert (items[3]["grade"], items[3]["grade_reason"], items[3]["findings"]) == (None, "настройки политики не распознаны словарём", 1)
    card = auth_client.get(f"/api/ksc/snapshots/{snap}/policies/1").json()
    assert (card["settings_known"], card["grade"], card["grade_reason"]) == (0, None, "настройки политики не распознаны словарём")


def test_grade_ok_on_medium_only(auth_client: TestClient) -> None:
    snap = _imported(auth_client, kes11_export(**{"852d0287/scanExclusionsAndTrustedZone.allowUseLocalTrustedApps": True}))
    item = _by_id(_list(auth_client, snap))[1]
    assert (item["grade"], item["findings"]) == ("ok", 1)


def test_grade_none_reasons(auth_client: TestClient, db_session: Session) -> None:
    raw = kes11_export()
    raw["policies"][2]["KLPOL_PRODUCT"] = "KESL"  # «KES lab» — продукт без словаря
    raw["policies"].append({**raw["policies"][0], "KLPOL_ID": 9, "KLPOL_DN": "KES retired", "KLPOL_ACTIVE": False})
    raw["policy_contents"]["9"] = dict(raw["policy_contents"]["1"])
    snap = _imported(auth_client, raw)
    items = _by_id(_list(auth_client, snap))
    assert (items[3]["grade"], items[3]["grade_reason"]) == (None, "структура продукта не описана")
    assert items[3]["findings"] == 1  # POLICY_NO_LOCKS считается, хотя оценки нет
    assert (items[9]["grade"], items[9]["grade_reason"]) == (None, "политика неактивна")

    row = db_session.get(KscSnapshot, snap)
    assert row is not None
    row.analyzer_version = "1"
    db_session.commit()
    item = _by_id(_list(auth_client, snap))[1]
    assert (item["grade"], item["grade_reason"]) == (None, "пересчитайте снапшот: оценка считается с версии анализатора 2")


def test_risk_accepted_improves_grade_and_policy_findings(auth_client: TestClient) -> None:
    raw = kes11_export(**{"1d3e35bd/selfDefense.enableSelfDefence": False,
                          "852d0287/scanExclusionsAndTrustedZone.allowUseLocalScanExclusions": True})
    snap = _imported(auth_client, raw)
    item = _by_id(_list(auth_client, snap))[1]
    assert (item["grade"], item["findings"]) == ("bad", 2)

    found = _policy_findings(auth_client, snap, 1)
    assert [(f["check"], f["severity"], f["status"], f["counted"]) for f in found] == [
        ("POLICY_SELFDEFENSE_OFF", "High", "new", True), ("POLICY_LOCAL_EXCLUSIONS", "Medium", "new", True),
    ]
    assert found[0]["check_title"] and found[0]["status_title"] == "Новая" and found[0]["details"]["policy_id"] == 1

    server_id = int(auth_client.get("/api/ksc/snapshots").json()[0]["server_id"])
    r = auth_client.put("/api/findings/state", json={"module": "ksc", "scope_id": server_id, "key": found[0]["key"],
                                                    "status": "risk_accepted", "comment": "стенд"})
    assert r.status_code == 200, r.text

    item = _by_id(_list(auth_client, snap))[1]
    assert (item["grade"], item["findings"]) == ("ok", 1)
    card = auth_client.get(f"/api/ksc/snapshots/{snap}/policies/1").json()
    assert (card["grade"], card["grade_reason"], card["findings"]) == (item["grade"], item["grade_reason"], 1)
    found = _policy_findings(auth_client, snap, 1)
    assert [(f["check"], f["status"], f["status_title"], f["counted"]) for f in found] == [
        ("POLICY_LOCAL_EXCLUSIONS", "new", "Новая", True), ("POLICY_SELFDEFENSE_OFF", "risk_accepted", "Принят риск", False),
    ]


def test_grade_filter_and_facet(auth_client: TestClient) -> None:
    snap = _imported(auth_client, kes11_export(**{"1d3e35bd/selfDefense.enableSelfDefence": False}))
    body = _list(auth_client, snap)
    assert body["facets"]["grade"] == {"bad": 1, "ok": 0, "good": 0, "none": 2}
    assert [i["id"] for i in _list(auth_client, snap, grade="bad")["items"]] == [1]
    assert [i["id"] for i in _list(auth_client, snap, grade="none")["items"]] == [2, 3]
    assert _list(auth_client, snap, grade="good")["items"] == []
    assert _list(auth_client, snap, grade="ok")["items"] == []
    assert _list(auth_client, snap, grade="bad")["facets"]["grade"] == {"bad": 1, "ok": 0, "good": 0, "none": 0}
    assert auth_client.get(f"/api/ksc/snapshots/{snap}/policy-list", params={"grade": "awful"}).status_code == 422


def test_policy_findings_route_404_and_empty(auth_client: TestClient) -> None:
    snap = _imported(auth_client, kes11_export())
    assert _policy_findings(auth_client, snap, 1) == []
    assert [f["check"] for f in _policy_findings(auth_client, snap, 3)] == ["POLICY_NO_LOCKS"]
    assert auth_client.get(f"/api/ksc/snapshots/{snap}/policies/77/findings").status_code == 404


def _state(client: TestClient, server_id: int, key: str) -> dict[str, Any]:
    r = client.get("/api/findings/state", params={"module": "ksc", "scope_id": server_id, "key": key})
    assert r.status_code == 200, r.text
    return dict(r.json())


def test_not_collected_contents_do_not_resolve_policy_findings(auth_client: TestClient, db_session: Session) -> None:
    """Не собрано ≠ пусто: у активной политики защиты нет содержимого (сбой или предел сбора) — её находки по содержимому
    не становятся «устранена»."""
    raw = kes11_export(**{"1d3e35bd/selfDefense.enableSelfDefence": False})
    snap1 = _imported(auth_client, raw)
    keys = [f["key"] for f in _policy_findings(auth_client, snap1, 1)]
    assert keys
    server_id = int(auth_client.get("/api/ksc/snapshots").json()[0]["server_id"])

    raw["server"]["collected_at"] = (NOW + dt.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    del raw["policy_contents"]["1"]
    snap2 = _imported(auth_client, raw)
    assert snap2 != snap1
    row = db_session.get(KscSnapshot, snap2)
    assert row is not None
    assert json.loads(row.stats_json)["policies"] == {"active_protection": 2, "without_contents": 1}
    for key in keys:
        assert _state(auth_client, server_id, key)["status"] != "resolved"


def test_collected_contents_resolve_fixed_policy_findings(auth_client: TestClient) -> None:
    """Контроль: содержимое собрано, самозащиту включили — находка «устранена» как обычно."""
    raw = kes11_export(**{"1d3e35bd/selfDefense.enableSelfDefence": False})
    snap1 = _imported(auth_client, raw)
    key = _policy_findings(auth_client, snap1, 1)[0]["key"]
    server_id = int(auth_client.get("/api/ksc/snapshots").json()[0]["server_id"])
    fixed = kes11_export()
    fixed["server"]["collected_at"] = (NOW + dt.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    _imported(auth_client, fixed)
    assert _state(auth_client, server_id, key)["status"] == "resolved"
