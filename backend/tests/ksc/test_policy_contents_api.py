"""Ручка «Содержимое политики»: заголовок, сводка замков, секции, скрытие секретов, 404."""
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from api.modules.ksc.services.snapshots import snapshot_path
from tests.ksc.synthetic import build_export, expected_policy_contents
from tests.ksc.test_api import upload


def _snapshot_id(client: TestClient) -> int:
    return client.get("/api/ksc/snapshots").json()[0]["id"]


def test_policy_contents_summary_sections_locks(auth_client: TestClient) -> None:
    raw = build_export()
    raw["policy_contents"] = expected_policy_contents()
    assert upload(auth_client, raw)["status"] == "done"
    snap = _snapshot_id(auth_client)
    body = auth_client.get(f"/api/ksc/snapshots/{snap}/policies/1/contents").json()

    assert body["policy"] == {"id": 1, "name": "KES workstations", "product": "KES", "version": "12.0.0.0", "group": "Managed devices"}
    assert body["summary"] == {"total": 5, "locked": 3, "share": 0.6, "with_lock_flag": 5}
    assert body["errors"] == []

    section_names = {s["name"] for s in body["sections"]}
    # Секции-секреты целиком (KLPRSS_Password, KLPRSS_Secret) и голый AdminPassword внутри
    # KLPRSS_Basic не дают ни одной настройки walk_settings — секреты не попадают в ответ.
    assert section_names == {"KLPRSS_Basic", "KLPRSS_Components"}
    basic = next(s for s in body["sections"] if s["name"] == "KLPRSS_Basic")
    paths = {s["path"] for s in basic["settings"]}
    assert paths == {"EnableSelfProtection", "EnablePasswordProtection", "ReportsMaxSize"}
    assert "AdminPassword" not in paths

    inherited = next(s for s in basic["settings"] if s["path"] == "EnablePasswordProtection")
    assert inherited["locked"] is True and inherited["inherited_lock"] is True and inherited["lock_from"] == "KES root (Managed devices)"
    plain = next(s for s in basic["settings"] if s["path"] == "EnableSelfProtection")
    assert plain["locked"] is True and plain["inherited_lock"] is False and plain["lock_from"] == ""

    components = next(s for s in body["sections"] if s["name"] == "KLPRSS_Components")
    comp_paths = {s["path"] for s in components["settings"]}
    assert comp_paths == {"FileThreatProtection.Enabled", "Firewall.Enabled"}


def test_policy_contents_without_locks(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    snap = _snapshot_id(auth_client)
    body = auth_client.get(f"/api/ksc/snapshots/{snap}/policies/3/contents").json()
    assert body["policy"]["name"] == "KES lab" and body["policy"]["group"] == "Managed devices/Workstations/Lab"
    assert body["summary"] == {"total": 5, "locked": 0, "share": 0.0, "with_lock_flag": 5}


def test_policy_contents_without_lock_flags(auth_client: TestClient) -> None:
    """Ни у одной настройки нет `KLPRSS_Mnd` — `with_lock_flag == 0`, страница пишет «замки не распознаны»."""
    raw = build_export()
    raw["policy_contents"]["3"]["sections"] = {"Sec": {"A": {"KLPRSS_Val": True}, "B": {"KLPRSS_Val": 5}}}
    assert upload(auth_client, raw)["status"] == "done"
    snap = _snapshot_id(auth_client)
    body = auth_client.get(f"/api/ksc/snapshots/{snap}/policies/3/contents").json()
    assert body["summary"] == {"total": 2, "locked": 0, "share": 0.0, "with_lock_flag": 0}
    assert [s["locked"] for s in body["sections"][0]["settings"]] == [None, None]


def test_policy_contents_missing_returns_null_summary(auth_client: TestClient) -> None:
    """Политика есть (агент, id 2), но продукты агента в `policy_contents` не собираются."""
    assert upload(auth_client, build_export())["status"] == "done"
    snap = _snapshot_id(auth_client)
    body = auth_client.get(f"/api/ksc/snapshots/{snap}/policies/2/contents").json()
    assert body["policy"]["id"] == 2 and body["policy"]["name"] == "Agent"
    assert body["summary"] is None and body["sections"] == [] and body["errors"] == ["содержимое не собрано"]


def test_policy_contents_truncates_long_value(auth_client: TestClient) -> None:
    raw = build_export()
    raw["policy_contents"]["1"]["sections"]["KLPRSS_Basic"]["ReportsMaxSize"]["KLPRSS_Val"] = "x" * 500
    assert upload(auth_client, raw)["status"] == "done"
    snap = _snapshot_id(auth_client)
    body = auth_client.get(f"/api/ksc/snapshots/{snap}/policies/1/contents").json()
    basic = next(s for s in body["sections"] if s["name"] == "KLPRSS_Basic")
    setting = next(s for s in basic["settings"] if s["path"] == "ReportsMaxSize")
    assert setting["value"].endswith("… (обрезано)") and len(setting["value"]) < 550


def test_policy_contents_snapshot_not_found(auth_client: TestClient) -> None:
    assert auth_client.get("/api/ksc/snapshots/999/policies/1/contents").status_code == 404


def test_policy_contents_export_file_missing(auth_client: TestClient, app_settings: Any) -> None:
    """Снапшот есть, а файла выгрузки на диске нет — 404 «файл выгрузки не найден», не 500."""
    assert upload(auth_client, build_export())["status"] == "done"
    snap = _snapshot_id(auth_client)
    snapshot_path(app_settings.data_dir, snap).unlink()
    r = auth_client.get(f"/api/ksc/snapshots/{snap}/policies/1/contents")
    assert r.status_code == 404 and r.json()["detail"] == "файл выгрузки не найден"


def test_policy_contents_policy_not_found(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    snap = _snapshot_id(auth_client)
    assert auth_client.get(f"/api/ksc/snapshots/{snap}/policies/999/contents").status_code == 404


def test_policies_endpoint_reports_locks_and_has_contents(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    snap = _snapshot_id(auth_client)
    body = auth_client.get(f"/api/ksc/snapshots/{snap}/policies").json()
    root = next(g for g in body["groups"] if g["name"] == "Managed devices")
    ws_policy = next(p for p in root["policies"] if p["name"] == "KES workstations")
    assert ws_policy["has_contents"] is True and ws_policy["locks"] == {"total": 5, "locked": 3, "with_lock_flag": 5}
    # та же политика, унаследованная группой Workstations, — тот же свод из кэша запроса
    ws_group = next(g for g in body["groups"] if g["name"] == "Workstations")
    assert next(p for p in ws_group["policies"] if p["name"] == "KES workstations")["locks"] == ws_policy["locks"]
    agent_policy = next(p for p in root["policies"] if p["name"] == "Agent")
    assert agent_policy["has_contents"] is False and agent_policy["locks"] is None


def test_policies_endpoint_walks_each_policy_once(auth_client: TestClient, monkeypatch: Any) -> None:
    """«KES workstations» действует в двух группах (своя и унаследованная), «KES lab» — в одной:
    дерево настроек обходится один раз на политику за запрос, а не на каждую группу."""
    from api.modules.ksc.routers import policies as policies_router

    assert upload(auth_client, build_export())["status"] == "done"
    snap = _snapshot_id(auth_client)
    calls: list[int] = []
    real = policies_router.walk_settings

    def counting(sections: Any) -> Any:
        calls.append(1)
        return real(sections)

    monkeypatch.setattr(policies_router, "walk_settings", counting)
    assert auth_client.get(f"/api/ksc/snapshots/{snap}/policies").status_code == 200
    assert len(calls) == 2
