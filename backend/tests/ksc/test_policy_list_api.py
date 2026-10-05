"""Список политик, карточка, привязка, профили и плоский список задач: ручки `policy_list`."""
from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.ksc.models import KscChange, KscFinding
from api.modules.ksc.services.snapshots import snapshot_path
from tests.ksc.synthetic import build_export, without_new_sections
from tests.ksc.test_api import upload


def _imported(client: TestClient, raw: dict[str, Any] | None = None) -> int:
    assert upload(client, raw or build_export())["status"] == "done"
    return int(client.get("/api/ksc/snapshots").json()[0]["id"])


def _item(body: dict[str, Any], policy_id: int) -> dict[str, Any]:
    return next(i for i in body["items"] if i["id"] == policy_id)


def test_policy_list_items_facets_sort(auth_client: TestClient) -> None:
    snap = _imported(auth_client)
    body = auth_client.get(f"/api/ksc/snapshots/{snap}/policy-list").json()

    assert [i["id"] for i in body["items"]] == [2, 3, 1]  # все активны — по имени: Agent, KES lab, KES workstations
    assert body["profiles_collected"] is True
    assert body["facets"] == {"product": {"KES": 2, "1103": 1}, "active": {"true": 3, "false": 0}, "grade": {"bad": 0, "ok": 0, "good": 0, "none": 3}}

    kes = _item(body, 1)
    assert kes == {
        "id": 1, "name": "KES workstations", "product": "KES", "version": "12.0.0.0", "group": "Managed devices", "active": True,
        "accept_parent": True, "modified_at": kes["modified_at"], "has_contents": True, "contents_partial": False, "described": True, "groups": 2, "hosts": 11,
        "profiles": 2, "exclusions": kes["exclusions"], "net_rules": kes["net_rules"], "locks": kes["locks"], "grade": None,
        "grade_reason": "настройки политики не распознаны словарём", "findings": 0,
    }
    assert kes["modified_at"] is not None
    assert kes["locks"] == {"locked": 7, "with_lock_flag": 12}

    agent = _item(body, 2)  # политика агента: содержимое и профили не собираются
    assert agent["has_contents"] is False and agent["locks"] is None and agent["profiles"] is None
    assert agent["grade"] is None and agent["grade_reason"] == "содержимое не собрано"
    assert (agent["groups"], agent["hosts"]) == (4, 13)

    lab = _item(body, 3)  # без единого замка — POLICY_NO_LOCKS (High) считается, оценки нет: настройки не распознаны
    assert lab["profiles"] == 0 and lab["locks"] == {"locked": 0, "with_lock_flag": 12}
    assert (lab["grade"], lab["findings"]) == (None, 1)


def test_policy_list_findings_counted_by_policy_id(auth_client: TestClient, db_session: Session) -> None:
    """`findings` — по `details.policy_id`, а не по имени: одноимённые политики не делят счёт."""
    raw = build_export()
    raw["policies"][0]["KLPOL_DN"] = "KES lab"  # у политик 1 и 3 одно имя
    snap = _imported(auth_client, raw)
    rows = db_session.execute(select(KscFinding).where(KscFinding.snapshot_id == snap, KscFinding.check == "POLICY_NO_LOCKS")).scalars().all()
    assert [(f.target, json.loads(f.details_json)["policy_id"]) for f in rows] == [("KES lab", 3)]
    body = auth_client.get(f"/api/ksc/snapshots/{snap}/policy-list").json()
    assert {i["id"]: i["findings"] for i in body["items"]} == {1: 0, 2: 0, 3: 1}


def test_policy_list_filters_and_inactive_grade_reason(auth_client: TestClient) -> None:
    raw = build_export()
    raw["policies"][2]["KLPOL_ACTIVE"] = False  # «KES lab» неактивна
    snap = _imported(auth_client, raw)
    url = f"/api/ksc/snapshots/{snap}/policy-list"

    body = auth_client.get(url).json()
    assert [i["id"] for i in body["items"]] == [2, 1, 3]  # неактивные в конце
    assert body["facets"]["active"] == {"true": 2, "false": 1}
    assert _item(body, 3)["grade_reason"] == "политика неактивна"

    assert [i["id"] for i in auth_client.get(url, params={"active": "false"}).json()["items"]] == [3]
    assert [i["id"] for i in auth_client.get(url, params={"active": "true"}).json()["items"]] == [2, 1]
    kes = auth_client.get(url, params={"product": "KES"}).json()
    assert [i["id"] for i in kes["items"]] == [1, 3]
    assert kes["facets"]["product"] == {"KES": 2}
    assert [i["id"] for i in auth_client.get(url, params={"q": "lab"}).json()["items"]] == [3]
    assert [i["id"] for i in auth_client.get(url, params={"q": "WORKSTATIONS"}).json()["items"]] == [1]
    assert auth_client.get(url, params={"q": "нет такой"}).json()["items"] == []


def test_policy_list_not_collected_profiles(auth_client: TestClient) -> None:
    snap = _imported(auth_client, without_new_sections(build_export()))
    body = auth_client.get(f"/api/ksc/snapshots/{snap}/policy-list").json()
    assert body["profiles_collected"] is False
    assert all(i["profiles"] is None for i in body["items"])
    prof = auth_client.get(f"/api/ksc/snapshots/{snap}/policies/1/profiles").json()
    assert prof == {"collected": False, "errors": [], "profiles": []}
    assert auth_client.get(f"/api/ksc/snapshots/{snap}/policies/1").json()["profiles"] is None


def test_policy_card(auth_client: TestClient, db_session: Session) -> None:
    snap = _imported(auth_client)
    db_session.add(KscChange(snapshot_id=snap, prev_snapshot_id=None, kind="setting", action="changed", policy_id=1, policy_name="KES workstations"))
    db_session.add(KscChange(snapshot_id=snap, prev_snapshot_id=None, kind="policy", action="added", policy_id=1, policy_name="KES workstations"))
    db_session.add(KscChange(snapshot_id=snap, prev_snapshot_id=None, kind="policy", action="added", policy_id=3, policy_name="KES lab"))
    db_session.commit()

    r = auth_client.get(f"/api/ksc/snapshots/{snap}/policies/1")
    assert r.status_code == 200
    body = r.json()
    listed = _item(auth_client.get(f"/api/ksc/snapshots/{snap}/policy-list").json(), 1)
    assert {k: v for k, v in body.items() if k not in ("settings_total", "settings_known", "errors", "changes")} == listed
    # Листья `flat_settings`: 13 контейнеров, у двух (`PasswordProtection`, `KLPRSS_Passwords.Exit`) значение — словарь из 3 ключей
    # (+4), и 3 значения вне контейнеров (`KLPRSS_Password.PASSWORD_HASH`, `KLPRSS_Secret`, лист `KLPRSS_Deep`).
    assert body["settings_total"] == 20 and body["settings_known"] == 0
    assert body["errors"] == []
    assert body["changes"] == 2
    assert auth_client.get(f"/api/ksc/snapshots/{snap}/policies/3").json()["changes"] == 1


def test_policy_card_errors_from_contents_and_profiles(auth_client: TestClient) -> None:
    raw = build_export()
    raw["policy_contents"]["3"]["errors"] = ["секция недоступна"]
    raw["policy_profiles"]["3"]["errors"] = ["профили не прочитаны"]
    snap = _imported(auth_client, raw)
    body = auth_client.get(f"/api/ksc/snapshots/{snap}/policies/3").json()
    assert body["errors"] == ["секция недоступна", "профили не прочитаны"]
    assert body["profiles"] is None  # чтение профилей отказало и ни одного не вернулось — «не собраны», не «ноль»


def test_policy_scope(auth_client: TestClient) -> None:
    snap = _imported(auth_client)
    body = auth_client.get(f"/api/ksc/snapshots/{snap}/policies/1/scope").json()
    assert body == {
        "groups": [
            {"group_id": 0, "path": "Managed devices", "own": True, "hosts": 0},
            {"group_id": 2, "path": "Managed devices/Workstations", "own": False, "hosts": 11},
        ],
        "hosts": 11,
    }
    lab = auth_client.get(f"/api/ksc/snapshots/{snap}/policies/3/scope").json()
    assert lab == {"groups": [{"group_id": 4, "path": "Managed devices/Workstations/Lab", "own": True, "hosts": 1}], "hosts": 1}


def test_policy_profiles_diff_condition_and_secret(auth_client: TestClient) -> None:
    snap = _imported(auth_client)
    r = auth_client.get(f"/api/ksc/snapshots/{snap}/policies/1/profiles")
    assert r.status_code == 200
    body = r.json()
    assert body["collected"] is True and body["errors"] == []
    assert [(p["name"], p["enabled"], p["priority"]) for p in body["profiles"]] == [("Ноутбуки", True, 0), ("Выключенный", False, 1)]

    notebooks, disabled = body["profiles"]
    assert notebooks["condition"]["KLSSPOL_PRF_ENABLED"] is True
    assert notebooks["condition"]["EXPRESSION"] == {"KLSSPOL_TAG": "Notebook"}
    assert notebooks["settings"] == 2 and notebooks["errors"] == []
    by_path = {(d["section"], d["path"]): d for d in notebooks["diff"]}
    assert set(by_path) == {("KLPRSS_Components", "Firewall.Enabled"), ("KLPRSS_Basic", "ProxyPassword")}
    firewall = by_path[("KLPRSS_Components", "Firewall.Enabled")]
    assert firewall["value"] == "false" and firewall["policy_value"] == "true" and firewall["locked"] is True
    secret = by_path[("KLPRSS_Basic", "ProxyPassword")]
    assert secret["value"] == '"<скрыто>"' and secret["locked"] is True
    assert "profile-secret" not in r.text

    assert disabled["settings"] == 0 and disabled["diff"] == []


def test_policy_profiles_none_for_policy_without_profiles(auth_client: TestClient) -> None:
    snap = _imported(auth_client)
    assert auth_client.get(f"/api/ksc/snapshots/{snap}/policies/3/profiles").json() == {"collected": True, "errors": [], "profiles": []}
    # агент: профили не читаются — «не собраны»
    assert auth_client.get(f"/api/ksc/snapshots/{snap}/policies/2/profiles").json() == {"collected": False, "errors": [], "profiles": []}


def test_policy_profiles_policy_value_absent(auth_client: TestClient) -> None:
    raw = build_export()
    del raw["policy_contents"]["1"]["sections"]["KLPRSS_Components"]
    snap = _imported(auth_client, raw)
    body = auth_client.get(f"/api/ksc/snapshots/{snap}/policies/1/profiles").json()
    diff = {(d["section"], d["path"]): d for d in body["profiles"][0]["diff"]}
    assert diff[("KLPRSS_Components", "Firewall.Enabled")]["policy_value"] is None


def test_tasks_flat_list_filters_facets(auth_client: TestClient) -> None:
    snap = _imported(auth_client)
    url = f"/api/ksc/snapshots/{snap}/tasks"
    body = auth_client.get(url).json()
    assert body["facets"] == {"type": {"Scan": 1, "Update": 1}}
    assert [i["id"] for i in body["items"]] == ["t-upd", "t-scan"]  # по группе, затем по имени
    upd = body["items"][0]
    assert upd["name"] == "Обновление" and upd["type"] == "Update" and upd["product"] == "KES" and upd["group"] == "Managed devices"
    assert (upd["ok"], upd["warning"], upd["failed"], upd["schedule"]) == (6, 1, 3, 1)
    assert upd["last_run_at"] is not None
    assert set(upd) == {"id", "name", "type", "product", "group", "schedule", "last_run_at", "ok", "warning", "failed"}

    assert [i["id"] for i in auth_client.get(url, params={"failed": "true"}).json()["items"]] == ["t-upd"]
    assert [i["id"] for i in auth_client.get(url, params={"type": "Scan"}).json()["items"]] == ["t-scan"]
    assert [i["id"] for i in auth_client.get(url, params={"q": "поиск"}).json()["items"]] == ["t-scan"]
    scan = auth_client.get(url, params={"type": "Scan"}).json()["items"][0]
    assert scan["group"] == "Managed devices/Workstations" and scan["failed"] == 0


def test_tasks_group_empty_for_device_set_task(auth_client: TestClient) -> None:
    raw = build_export()
    del raw["tasks"][1]["TASK_INFO_PARAMS"]["PRTS_TASK_GROUPID"]  # задача для набора устройств
    snap = _imported(auth_client, raw)
    items = auth_client.get(f"/api/ksc/snapshots/{snap}/tasks").json()["items"]
    assert next(i for i in items if i["id"] == "t-scan")["group"] == ""


@pytest.mark.parametrize("suffix", ["policy-list", "policies/1", "policies/1/scope", "policies/1/profiles", "tasks"])
def test_snapshot_not_found(auth_client: TestClient, suffix: str) -> None:
    r = auth_client.get(f"/api/ksc/snapshots/9999/{suffix}")
    assert r.status_code == 404 and r.json()["detail"] == "снапшот не найден"


@pytest.mark.parametrize("suffix", ["policies/99", "policies/99/scope", "policies/99/profiles"])
def test_policy_not_found(auth_client: TestClient, suffix: str) -> None:
    snap = _imported(auth_client)
    r = auth_client.get(f"/api/ksc/snapshots/{snap}/{suffix}")
    assert r.status_code == 404 and r.json()["detail"] == "политика не найдена"


def test_snapshot_file_missing_is_404(auth_client: TestClient, app_settings: Any) -> None:
    snap = _imported(auth_client)
    snapshot_path(app_settings.data_dir, snap).unlink()
    for suffix in ("policy-list", "policies/1", "policies/1/profiles", "tasks"):
        r = auth_client.get(f"/api/ksc/snapshots/{snap}/{suffix}")
        assert r.status_code == 404 and r.json()["detail"] == "файл выгрузки не найден", suffix


def test_requires_auth(client: TestClient) -> None:
    for suffix in ("policy-list", "policies/1", "policies/1/scope", "policies/1/profiles", "tasks"):
        assert client.get(f"/api/ksc/snapshots/1/{suffix}").status_code == 401, suffix

