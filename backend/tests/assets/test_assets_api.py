"""Ручки реестра: список с фильтрами и фасетами, карточка, ручные поля, объединение, отвязка, роли."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.modules.assets.models import AssetSettings
from tests.assets.synthetic import load_all


@pytest.fixture
def analyst(db_session: Session, app_settings: Any, client_as: Callable[[str], TestClient]) -> TestClient:
    """Аналитик и три источника, синхронизированные через ручку."""
    db_session.add(AssetSettings(data={"sync_after_import": False}))
    db_session.commit()
    load_all(db_session, Path(app_settings.data_dir), dt.datetime.now(dt.UTC))
    c = client_as("analyst")
    r = c.post("/api/assets/sync")
    assert r.status_code == 202, r.text
    job = c.get(f"/api/assets/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "done", job
    return c


def names(body: dict[str, Any]) -> set[str]:
    return {i["name"].lower() for i in body["items"]}


def by_name(c: TestClient, name: str) -> dict[str, Any]:
    items = c.get("/api/assets/assets", params={"q": name}).json()["items"]
    return next(i for i in items if i["name"].lower() == name)


def test_list_filters_and_facets(analyst: TestClient) -> None:
    body = analyst.get("/api/assets/assets").json()
    assert body["total"] == 4 and names(body) == {"msk1", "ws01", "srv01", "old01"}
    assert body["facets"]["source"] == {"vm": 2, "ksc": 2, "ad": 3, "scan": 0, "dns": 0}
    assert body["facets"]["code"]["conflict"] == 1 and body["facets"]["code"]["no_av"] == 2
    item = next(i for i in body["items"] if i["name"].lower() == "msk1")
    assert item["ip"] == "192.168.2.23" and item["discrepancy_count"] >= 1
    assert {s["source"] for s in item["sources"]} == {"vm", "ksc"}

    assert names(analyst.get("/api/assets/assets", params={"source_missing": "ksc"}).json()) == {"ws01", "old01"}
    assert names(analyst.get("/api/assets/assets", params={"source_has": "vm", "source_missing": "ad"}).json()) == {"msk1"}
    assert names(analyst.get("/api/assets/assets", params={"code": "conflict"}).json()) == {"msk1"}
    assert names(analyst.get("/api/assets/assets", params={"q": "srv"}).json()) == {"srv01"}
    assert names(analyst.get("/api/assets/assets", params={"q": "192.168.6.53"}).json()) == {"msk1"}  # старый адрес из VM
    page = analyst.get("/api/assets/assets", params={"limit": 1, "offset": 1}).json()
    assert page["total"] == 4 and len(page["items"]) == 1 and page["facets"] is None


def test_list_rejects_unknown_filter_values(analyst: TestClient) -> None:
    assert analyst.get("/api/assets/assets", params={"code": "nope"}).status_code == 422
    assert analyst.get("/api/assets/assets", params={"source_has": "nope"}).status_code == 422
    assert analyst.get("/api/assets/assets", params={"limit": 501}).status_code == 422


def test_detail_has_observations_discrepancies_and_links(analyst: TestClient) -> None:
    srv01 = analyst.get(f"/api/assets/assets/{by_name(analyst, 'srv01')['id']}").json()
    assert sorted(o["source"] for o in srv01["observations"]) == ["ad", "ksc", "vm"]
    links = srv01["links"]
    assert isinstance(links["ad_finding_count"], int) and links["ad_domain_id"] is not None and links["ad_query"] == "SRV01"
    assert links["ksc_host_id"] == "h-srv01" and links["ksc_server_id"] is not None
    assert isinstance(links["vm_host_id"], int)

    msk1 = analyst.get(f"/api/assets/assets/{by_name(analyst, 'msk1')['id']}").json()
    vm_obs = next(o for o in msk1["observations"] if o["source"] == "vm")
    assert vm_obs["marks"] == {"ip": "conflict"}
    assert any(d["code"] == "conflict" and d["value"] == "192.168.6.53" for d in msk1["discrepancies"])
    assert analyst.get("/api/assets/assets/999999").status_code == 404


def test_manual_fields(analyst: TestClient) -> None:
    asset_id = by_name(analyst, "ws01")["id"]
    r = analyst.patch(f"/api/assets/assets/{asset_id}", json={"criticality": "High", "tags": ["бухгалтерия", "vip"], "note": "стоит у кассы"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["criticality"], body["tags"], body["note"]) == ("High", ["бухгалтерия", "vip"], "стоит у кассы")
    assert names(analyst.get("/api/assets/assets", params={"criticality": "High"}).json()) == {"ws01"}
    assert names(analyst.get("/api/assets/assets", params={"tag": "vip"}).json()) == {"ws01"}
    assert analyst.patch(f"/api/assets/assets/{asset_id}", json={"criticality": "Urgent"}).status_code == 422
    # Синхронизация ручные поля не трогает.
    assert analyst.post("/api/assets/sync").status_code == 202
    again = analyst.get(f"/api/assets/assets/{asset_id}").json()
    assert (again["criticality"], again["tags"], again["note"]) == ("High", ["бухгалтерия", "vip"], "стоит у кассы")


def test_pin_field(analyst: TestClient) -> None:
    asset_id = by_name(analyst, "msk1")["id"]
    r = analyst.post(f"/api/assets/assets/{asset_id}/pin", json={"field": "ip", "pinned": True})
    assert r.status_code == 200, r.text
    assert r.json()["pinned"] == {"ip": True}
    assert analyst.post(f"/api/assets/assets/{asset_id}/pin", json={"field": "criticality", "pinned": True}).status_code == 422
    r = analyst.post(f"/api/assets/assets/{asset_id}/pin", json={"field": "ip", "pinned": False})
    assert r.json()["pinned"] == {}


def test_merge(analyst: TestClient) -> None:
    ws01, old01 = by_name(analyst, "ws01")["id"], by_name(analyst, "old01")["id"]
    analyst.patch(f"/api/assets/assets/{ws01}", json={"tags": ["a"], "note": "первый"})
    analyst.patch(f"/api/assets/assets/{old01}", json={"tags": ["b", "a"], "note": "второй", "criticality": "Low"})
    r = analyst.post(f"/api/assets/assets/{ws01}/merge", json={"other_id": old01})
    assert r.status_code == 200, r.text
    merged = r.json()
    assert len(merged["observations"]) == 2 and merged["tags"] == ["a", "b"]
    assert "первый" in merged["note"] and "второй" in merged["note"] and merged["criticality"] == "Low"
    body = analyst.get("/api/assets/assets").json()
    assert body["total"] == 3 and "old01" not in names(body)
    assert analyst.get(f"/api/assets/assets/{old01}").json()["merged_into"] == ws01
    # Повторная синхронизация объединение не разваливает: правило 1 держит наблюдения у первого.
    assert analyst.post("/api/assets/sync").status_code == 202
    assert analyst.get("/api/assets/assets").json()["total"] == 3
    assert analyst.post(f"/api/assets/assets/{ws01}/merge", json={"other_id": ws01}).status_code == 422
    assert analyst.post(f"/api/assets/assets/{ws01}/merge", json={"other_id": old01}).status_code == 409
    assert analyst.post(f"/api/assets/assets/{ws01}/merge", json={"other_id": 999999}).status_code == 404


def test_detach(analyst: TestClient) -> None:
    srv01 = analyst.get(f"/api/assets/assets/{by_name(analyst, 'srv01')['id']}").json()
    vm_obs = next(o for o in srv01["observations"] if o["source"] == "vm")
    r = analyst.post(f"/api/assets/observations/{vm_obs['id']}/detach")
    assert r.status_code == 200, r.text
    fresh = r.json()
    assert fresh["id"] != srv01["id"] and [o["id"] for o in fresh["observations"]] == [vm_obs["id"]]
    assert analyst.get("/api/assets/assets").json()["total"] == 5
    assert analyst.post("/api/assets/sync").status_code == 202
    assert analyst.get("/api/assets/assets").json()["total"] == 5
    # Единственное наблюдение отвязывать некуда.
    assert analyst.post(f"/api/assets/observations/{vm_obs['id']}/detach").status_code == 409
    assert analyst.post("/api/assets/observations/999999/detach").status_code == 404


def test_sync_status(analyst: TestClient) -> None:
    body = analyst.get("/api/assets/sync/status").json()
    assert body["last_sync_at"] is not None and body["running_job_id"] is None
    assert body["sources"]["ad"]["live"] == 3 and body["sources"]["vm"]["live"] == 2


def test_sync_conflicts_with_running_sync(analyst: TestClient, db_session: Session) -> None:
    from api.jobs import start_job
    from api.modules.assets.models import AssetJob

    start_job(db_session, AssetJob, "sync", "tester")
    assert analyst.post("/api/assets/sync").status_code == 409


def test_auditor_reads_but_cannot_write(analyst: TestClient, client_as: Callable[[str], TestClient]) -> None:
    asset_id = by_name(analyst, "srv01")["id"]
    auditor = client_as("auditor")
    assert auditor.get("/api/assets/assets").status_code == 200
    assert auditor.get(f"/api/assets/assets/{asset_id}").status_code == 200
    assert auditor.get("/api/assets/sync/status").status_code == 200
    assert auditor.patch(f"/api/assets/assets/{asset_id}", json={"note": "x"}).status_code == 403
    assert auditor.post(f"/api/assets/assets/{asset_id}/pin", json={"field": "ip", "pinned": True}).status_code == 403
    assert auditor.post(f"/api/assets/assets/{asset_id}/merge", json={"other_id": asset_id}).status_code == 403
    assert auditor.post("/api/assets/observations/1/detach").status_code == 403
    assert auditor.post("/api/assets/sync").status_code == 403
