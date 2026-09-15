from __future__ import annotations

from fastapi.testclient import TestClient

from tests.ksc.synthetic import build_export
from tests.ksc.test_api import upload


def test_policies_tree(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    body = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/policies").json()
    paths = [g["path"] for g in body["groups"]]
    assert paths == ["Managed devices", "Managed devices/Workstations", "Managed devices/Workstations/Lab", "Managed devices/Servers", "Unassigned devices"]
    servers = next(g for g in body["groups"] if g["name"] == "Servers")
    assert servers["hosts"] == 1 and [p["product"] for p in servers["policies"]] == ["1103"] and servers["policies"][0]["inherited"] is True
    assert {f["check"] for f in servers["findings"]} == {"POLICY_NONE", "TASK_NO_SCAN"}
    ws = next(g for g in body["groups"] if g["name"] == "Workstations")
    assert {t["type"] for t in ws["tasks"]} == {"Update", "Scan"} and next(t for t in ws["tasks"] if t["type"] == "Update")["inherited"] is True
    lab = next(g for g in body["groups"] if g["name"] == "Lab")
    assert lab["level"] == 2 and lab["policies"][0]["name"] == "KES lab" and lab["policies"][0]["accept_parent"] is False
    assert auth_client.get("/api/ksc/snapshots/999/policies").status_code == 404
