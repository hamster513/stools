from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.modules.ksc.core import client as client_mod
from api.modules.ksc.core.client import KscClient, KscError
from api.modules.ksc.core.collector import collect
from api.modules.ksc.core.export import load_export
from tests.ksc.fake_ksc import PASSWORD, USER, FakeKsc, http_factory_for
from tests.ksc.synthetic import build_export


@pytest.fixture
def fake(monkeypatch: Any) -> FakeKsc:
    f = FakeKsc()
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(f))
    return f


def test_client_login_call_and_error(fake: FakeKsc) -> None:
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        assert c.call("HostGroup.GetStaticInfo", {"pValues": ["KLADMSRV_SERVER_HOSTNAME"]})["PxgRetVal"]["KLADMSRV_SERVER_HOSTNAME"] == "ksc01"
        fake.fail_after = "HostGroup.GetDomains"
        with pytest.raises(KscError, match="boom"):
            c.call("HostGroup.GetDomains")
    assert fake.calls[0] == "Session.StartSession" and fake.calls[-1] == "Session.EndSession"
    fake.fail_login = True
    with pytest.raises(KscError, match="вход отклонён"):
        KscClient("https://ksc01:13299", USER, "wrong").login()


def test_client_closes_http_on_failed_login(fake: FakeKsc) -> None:
    fake.fail_login = True
    c = KscClient("https://ksc01:13299", USER, "wrong")
    with pytest.raises(KscError), c:
        pass
    assert c._http.is_closed is True


def test_collect_matches_synthetic_export(fake: FakeKsc) -> None:
    seen: list[tuple[int, int]] = []
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, progress=lambda done, total: seen.append((done, total)), username=USER)
    export = load_export(__import__("json").dumps(raw).encode())
    expected = build_export()
    assert export.server.name == "ksc01" and export.server.collector == "online" and export.server.user == USER
    assert [h["KLHST_WKS_DN"] for h in export.hosts] == [h["KLHST_WKS_DN"] for h in expected["hosts"]]
    assert export.host_products == expected["host_products"] and export.host_components == expected["host_components"]
    assert export.policies == expected["policies"] and export.effective_policies == expected["effective_policies"]
    assert [t["TASK_UNIQUE_ID"] for t in export.tasks] == ["t-upd", "t-scan"] and all("statistics" in t for t in export.tasks)
    assert export.licenses == expected["licenses"] and export.domains == expected["domains"]
    assert seen and seen[-1] == (12, 12)  # прогресс по хостам с агентом
    assert "ChunkAccessor.Release" in fake.calls and "GroupSyncIterator.ReleaseIterator" in fake.calls


def test_collect_reads_typed_numbers(monkeypatch: Any) -> None:
    """KSC отдаёт числа и как 13, и как {"type": "long", "value": 13}."""
    data = build_export()
    for h in data["hosts"]:
        h["KLHST_WKS_STATUS"] = {"type": "long", "value": h["KLHST_WKS_STATUS"]}
    for g in data["groups"]:
        g["id"] = {"type": "long", "value": g["id"]}
    f = FakeKsc(data)
    monkeypatch.setattr(client_mod, "http_factory", http_factory_for(f))
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c)
    assert set(raw["host_products"]) == set(build_export()["host_products"])
    assert set(raw["effective_policies"]) == {"0", "1", "2", "3", "4"}


def test_collect_skip_products(fake: FakeKsc) -> None:
    with KscClient("https://ksc01:13299", USER, PASSWORD) as c:
        raw = collect(c, skip_products=True)
    assert raw["host_products"] == {} and "HostGroup.GetHostProducts" not in fake.calls


def test_connection_crud_hides_password(auth_client: TestClient) -> None:
    r = auth_client.post("/api/ksc/connections", json={"title": "KSC", "host": "ksc01.corp.local", "username": USER, "password": PASSWORD})
    assert r.status_code == 201
    body = r.json()
    assert body["password_set"] is True and "password" not in body and body["port"] == 13299 and body["internal"] is True
    cid = body["id"]
    r = auth_client.put(f"/api/ksc/connections/{cid}", json={"host": "ksc02.corp.local", "username": USER, "password": "", "internal": False, "domain": "CORP"})
    assert r.json()["host"] == "ksc02.corp.local" and r.json()["password_set"] is True and r.json()["domain"] == "CORP"
    assert auth_client.delete(f"/api/ksc/connections/{cid}").status_code == 204
    assert auth_client.get("/api/ksc/connections").json() == []


def test_test_and_collect_via_fake(auth_client: TestClient, fake: FakeKsc) -> None:
    cid = auth_client.post("/api/ksc/connections", json={"host": "ksc01.corp.local", "username": USER, "password": PASSWORD}).json()["id"]
    t = auth_client.post(f"/api/ksc/connections/{cid}/test").json()
    assert t["ok"] and t["server_name"] == "ksc01" and "15.1" in t["version"]
    r = auth_client.post(f"/api/ksc/connections/{cid}/collect")
    assert r.status_code == 202, r.text
    job = auth_client.get(f"/api/ksc/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "done", job
    snaps = auth_client.get("/api/ksc/snapshots").json()
    assert len(snaps) == 1 and snaps[0]["source"] == "online" and snaps[0]["hosts"] == 14
    assert auth_client.get("/api/ksc/connections").json()[0]["server_id"] == snaps[0]["server_id"]


def test_collect_failure_leaves_no_snapshot(auth_client: TestClient, fake: FakeKsc) -> None:
    fake.fail_after = "HostGroup.FindHosts"
    cid = auth_client.post("/api/ksc/connections", json={"host": "ksc01.corp.local", "username": USER, "password": PASSWORD}).json()["id"]
    r = auth_client.post(f"/api/ksc/connections/{cid}/collect")
    job = auth_client.get(f"/api/ksc/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "failed" and "boom" in job["error"]
    assert auth_client.get("/api/ksc/snapshots").json() == []
    fake.fail_login = True
    t = auth_client.post(f"/api/ksc/connections/{cid}/test").json()
    assert not t["ok"] and "вход отклонён" in t["message"]


def test_collect_without_password_and_when_busy(auth_client: TestClient, db_session: Any) -> None:
    cid = auth_client.post("/api/ksc/connections", json={"host": "ksc01.corp.local", "username": USER, "password": ""}).json()["id"]
    assert auth_client.post(f"/api/ksc/connections/{cid}/collect").status_code == 400
    from api.modules.ksc.models import KscConnection, KscJob

    db_session.get(KscConnection, cid).password = PASSWORD
    db_session.add(KscJob(kind="import_file", stage="parsing", status="running", started_by="x"))
    db_session.commit()
    assert auth_client.post(f"/api/ksc/connections/{cid}/collect").status_code == 409
