from __future__ import annotations

from typing import Any, ClassVar

from fastapi.testclient import TestClient

from api.modules.ad.services import connections as svc
from tests.ad.fake_ldap import FakeLdap


class _FakeConn:
    def __init__(self) -> None:
        self.fake = FakeLdap()

        class Info:
            other: ClassVar[dict[str, list[str]]] = {"defaultNamingContext": ["DC=corp,DC=local"], "configurationNamingContext": ["CN=Configuration,DC=corp,DC=local"], "schemaNamingContext": ["CN=Schema,CN=Configuration,DC=corp,DC=local"]}

        class Server:
            info = Info()

        self.server = Server()

    def unbind(self) -> None:
        pass


def test_connection_crud_hides_password(auth_client: TestClient) -> None:
    r = auth_client.post("/api/ad/connections", json={"title": "CORP", "host": "dc01.corp.local", "username": "CORP\\auditor", "password": "secret"})
    assert r.status_code == 201
    body = r.json()
    assert body["password_set"] is True and "password" not in body
    cid = body["id"]
    r = auth_client.put(f"/api/ad/connections/{cid}", json={"host": "dc02.corp.local", "username": "CORP\\auditor", "password": ""})
    assert r.json()["host"] == "dc02.corp.local" and r.json()["password_set"] is True
    assert len(auth_client.get("/api/ad/connections").json()) == 1
    assert auth_client.delete(f"/api/ad/connections/{cid}").status_code == 204
    assert auth_client.get("/api/ad/connections").json() == []


def test_collect_via_fake_ldap(auth_client: TestClient, monkeypatch: Any) -> None:
    fake_conn = _FakeConn()
    monkeypatch.setattr(svc, "ldap3_connection", lambda conn: fake_conn)
    monkeypatch.setattr(svc, "ldap3_searcher", lambda c: fake_conn.fake.search)
    monkeypatch.setattr(svc, "smb_reader", lambda host, u, p: fake_conn.fake.smb)
    r = auth_client.post("/api/ad/connections", json={"host": "dc01.corp.local", "username": "CORP\\auditor", "password": "secret"})
    cid = r.json()["id"]
    test = auth_client.post(f"/api/ad/connections/{cid}/test").json()
    assert test["ok"] and "DC=corp,DC=local" in test["message"]
    r = auth_client.post(f"/api/ad/connections/{cid}/collect")
    assert r.status_code == 202, r.text
    job = auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "done", job
    snaps = auth_client.get("/api/ad/snapshots").json()
    assert len(snaps) == 1 and snaps[0]["source"] == "ldap" and snaps[0]["findings"] > 20
    assert auth_client.get("/api/ad/connections").json()[0]["domain_id"] == snaps[0]["domain_id"]
    assert auth_client.post(f"/api/ad/connections/{cid}/collect").status_code == 202


def test_collector_script_download(auth_client: TestClient) -> None:
    r = auth_client.get("/api/ad/collector.ps1")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert "stools-ad/1" in r.text and "Get-ADRootDSE" in r.text


def test_collector_script_has_utf8_bom(auth_client: TestClient) -> None:
    # Windows PowerShell 5.1 без BOM читает файл в ANSI и ломает кириллицу в строках.
    r = auth_client.get("/api/ad/collector.ps1")
    assert r.content.startswith(b"\xef\xbb\xbf")
