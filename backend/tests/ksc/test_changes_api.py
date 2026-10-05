"""API журнала изменений: фильтры, список снапшотов со сводом, свод на обзоре сервера."""
from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.modules.ksc.core.policy_model import EXTRACTORS
from tests.ksc.synthetic import build_export
from tests.ksc.test_api import upload


def _policy(raw: dict[str, Any], pid: int) -> dict[str, Any]:
    return next(p for p in raw["policies"] if p["KLPOL_ID"] == pid)


def _raw(collected_at: str, *, name: str = "KES workstations", lab_active: bool = True, max_size: int = 1024) -> dict[str, Any]:
    raw = build_export()
    raw["server"]["collected_at"] = collected_at
    _policy(raw, 1)["KLPOL_DN"] = name
    _policy(raw, 3)["KLPOL_ACTIVE"] = lab_active
    raw["policy_contents"]["1"]["sections"]["KLPRSS_Basic"]["ReportsMaxSize"]["KLPRSS_Val"] = max_size
    return raw


def _changes(client: TestClient, server_id: int, query: str = "") -> dict[str, Any]:
    r = client.get(f"/api/ksc/servers/{server_id}/changes?{query}")
    assert r.status_code == 200, r.text
    return dict(r.json())


def _setup(client: TestClient) -> tuple[int, dict[str, int]]:
    """Три снапшота: 14.09 — база; 15.09 — переименована политика 1, выключена 3, изменена настройка (3 записи); 16.09 — ещё раз переименована (1 запись)."""
    assert upload(client, _raw("2026-09-14T12:00:00Z"))["status"] == "done"
    assert upload(client, _raw("2026-09-15T12:00:00Z", name="KES workstations 2", lab_active=False, max_size=2048))["status"] == "done"
    assert upload(client, _raw("2026-09-16T12:00:00Z", name="KES workstations 3", lab_active=False, max_size=2048))["status"] == "done"
    snaps = client.get("/api/ksc/snapshots").json()
    return int(snaps[0]["server_id"]), {s["collected_at"][:10]: int(s["id"]) for s in snaps}


def test_changes_list_order_and_fields(auth_client: TestClient) -> None:
    server, ids = _setup(auth_client)
    body = _changes(auth_client, server)
    assert body["total"] == 4 and len(body["items"]) == 4
    # Снапшот по убыванию времени сбора, затем id.
    assert [i["snapshot_id"] for i in body["items"]] == [ids["2026-09-16"]] + [ids["2026-09-15"]] * 3
    assert [i["id"] for i in body["items"][1:]] == sorted(i["id"] for i in body["items"][1:])
    newest = body["items"][0]
    assert newest["collected_at"].startswith("2026-09-16T12:00:00")
    assert (newest["kind"], newest["action"], newest["policy_id"], newest["policy_name"], newest["profile"], newest["section"], newest["path"]) == (
        "policy", "changed", 1, "KES workstations 3", "", "", "name",
    )
    assert (newest["before"], newest["after"]) == ("KES workstations 2", "KES workstations 3")
    kinds = sorted((i["kind"], i["path"]) for i in body["items"][1:])
    assert [k for k, _ in kinds] == ["policy", "policy", "setting"] and {p for k, p in kinds if k == "policy"} == {"active", "name"}
    setting = next(i for i in body["items"] if i["kind"] == "setting")
    assert setting["section"] == "KLPRSS_Basic" and setting["policy_id"] == 1 and (setting["before"], setting["after"]) == ({"value": 1024}, {"value": 2048})


def test_changes_filters_facets_and_paging(auth_client: TestClient) -> None:
    server, ids = _setup(auth_client)
    assert _changes(auth_client, server, "kind=setting")["total"] == 1
    assert _changes(auth_client, server, "kind=policy")["total"] == 3
    assert _changes(auth_client, server, "kind=exclusion")["total"] == 0
    assert _changes(auth_client, server, "action=changed")["total"] == 4 and _changes(auth_client, server, "action=added")["total"] == 0
    only3 = _changes(auth_client, server, "policy_id=3")
    assert only3["total"] == 1 and only3["items"][0]["path"] == "active" and only3["items"][0]["snapshot_id"] == ids["2026-09-15"]
    assert _changes(auth_client, server, "policy_id=1")["total"] == 3
    mid = _changes(auth_client, server, f"snapshot_id={ids['2026-09-15']}")
    assert mid["total"] == 3 and {i["snapshot_id"] for i in mid["items"]} == {ids["2026-09-15"]}
    assert _changes(auth_client, server, f"snapshot_id={ids['2026-09-14']}")["total"] == 0
    assert _changes(auth_client, server, f"snapshot_id={ids['2026-09-16']}&kind=policy&policy_id=1")["total"] == 1

    first = _changes(auth_client, server, "limit=2")
    assert first["facets"] == {"kind": {"policy": 3, "setting": 1}, "action": {"changed": 4}}
    second = _changes(auth_client, server, "limit=2&offset=2")
    assert second["facets"] is None and second["total"] == 4
    assert [i["id"] for i in first["items"] + second["items"]] == [i["id"] for i in _changes(auth_client, server)["items"]]
    # Фасеты — по отфильтрованному набору.
    assert _changes(auth_client, server, "kind=setting")["facets"] == {"kind": {"setting": 1}, "action": {"changed": 1}}


def test_changes_snapshots_summary(auth_client: TestClient) -> None:
    server, ids = _setup(auth_client)
    snaps = _changes(auth_client, server)["snapshots"]
    assert [s["id"] for s in snaps] == [ids["2026-09-16"], ids["2026-09-15"], ids["2026-09-14"]]  # новые первыми
    last, mid, base = snaps
    assert last["collected_at"].startswith("2026-09-16") and last["prev"] == ids["2026-09-15"] and last["total"] == 1 and last["truncated"] is False
    assert mid["prev"] == ids["2026-09-14"] and mid["total"] == 3
    # Продукт KES описан извлекателем: сравнивалось всё, включая исключения и сетевые правила.
    assert last["compared"] == {"policy": True, "scope": True, "profile": True, "setting": True, "net_rule": True, "exclusion": True}
    assert last["reason"] is None
    # Первый снапшот: сравнивать не с чем — это не «0 изменений».
    assert base["prev"] is None and base["total"] == 0 and base["compared"] == {}


def test_changes_undescribed_product_records_not_compared(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(EXTRACTORS, "KES")  # реестр без KES: исключения и сетевые правила не сравнивались — «не описано»
    server, _ = _setup(auth_client)
    last = _changes(auth_client, server)["snapshots"][0]
    assert last["compared"] == {"policy": True, "scope": True, "profile": True, "setting": True, "net_rule": False, "exclusion": False}


def test_changes_snapshot_not_computed(auth_client: TestClient, db_session: Any) -> None:
    from api.modules.ksc.models import KscSnapshot

    server, ids = _setup(auth_client)
    snap = db_session.get(KscSnapshot, ids["2026-09-16"])
    snap.stats_json = '{"checks": {}}'  # снапшот до появления журнала изменений
    db_session.commit()
    row = next(s for s in _changes(auth_client, server)["snapshots"] if s["id"] == ids["2026-09-16"])
    assert row["total"] is None and row["prev"] is None and row["compared"] == {} and row["reason"]
    overview = auth_client.get(f"/api/ksc/servers/{server}/overview").json()
    assert overview["changes"]["total"] is None and overview["changes"]["reason"]


def test_overview_carries_changes_of_latest(auth_client: TestClient) -> None:
    server, ids = _setup(auth_client)
    changes = auth_client.get(f"/api/ksc/servers/{server}/overview").json()["changes"]
    assert changes == {
        "total": 1, "prev": ids["2026-09-15"], "truncated": False, "reason": None,
        "compared": {"policy": True, "scope": True, "profile": True, "setting": True, "net_rule": True, "exclusion": True},
    }


def test_overview_without_snapshots_changes_null(auth_client: TestClient) -> None:
    assert upload(auth_client, _raw("2026-09-14T12:00:00Z"))["status"] == "done"
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    assert auth_client.delete(f"/api/ksc/snapshots/{snap['id']}").status_code == 204
    overview = auth_client.get(f"/api/ksc/servers/{snap['server_id']}/overview").json()
    assert overview["snapshot"] is None and overview["changes"] is None


def test_changes_unknown_server(auth_client: TestClient) -> None:
    assert auth_client.get("/api/ksc/servers/999999/changes").status_code == 404
