from __future__ import annotations

from fastapi.testclient import TestClient

from tests.ksc.synthetic import add_ws02_twin, build_export
from tests.ksc.test_api import upload


def test_hosts_list_facets_and_filters(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    body = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts").json()
    assert body["total"] == 14 and body["facets"]["protection"] == {"none": 4, "off": 1, "on": 9}
    assert body["facets"]["agent"] == {"none": 2, "silent": 1, "alive": 11} and body["facets"]["bases"] == {"fresh": 9, "old": 1, "unknown": 4}
    assert body["facets"]["in_ad"] == {} and body["facets"]["group"]["Managed devices/Workstations"] == 11
    ws02 = next(h for h in body["items"] if h["name"] == "WS02")
    assert ws02["protection"] == "off" and ws02["rtp_state"] == 1 and ws02["findings"] == 1 and ws02["ip"] == "192.168.1.3"
    off = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts?protection=off").json()
    assert [h["name"] for h in off["items"]] == ["WS02"]
    silent = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts?agent=silent").json()
    assert [h["name"] for h in silent["items"]] == ["WS05"]
    q = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts?q=srv").json()
    assert [h["name"] for h in q["items"]] == ["SRV01"]
    grp = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts?group=Managed devices/Servers").json()
    assert grp["total"] == 1
    page = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts?limit=5&offset=5").json()
    assert len(page["items"]) == 5 and page["facets"] is None


def test_host_detail_has_findings_and_components(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    detail = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts/h-ws11").json()
    assert detail["name"] == "WS11" and ["Firewall", 1] in detail["components"]
    assert [f["check"] for f in detail["findings"]] == ["COMPONENT_OFF"] and detail["findings"][0]["status"] == "persisting"
    assert auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts/nope").status_code == 404


def test_same_named_hosts_keep_their_own_findings(auth_client: TestClient) -> None:
    assert upload(auth_client, add_ws02_twin(build_export()))["status"] == "done"
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    body = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts?q=ws02").json()
    assert {h["host_id"]: h["findings"] for h in body["items"]} == {"h-ws02": 1, "h-ws02-dup": 1}
    for host_id in ("h-ws02", "h-ws02-dup"):
        detail = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts/{host_id}").json()
        assert [f["check"] for f in detail["findings"]] == ["RTP_OFF"]


def test_findings_list_and_detail(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    body = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/findings").json()
    assert body["total"] == snap["findings"] and body["items"][0]["severity"] == "Critical"
    assert body["facets"]["status"]["persisting"] == body["total"] and set(body["facets"]["check"]) >= {"RTP_OFF", "LICENSE", "POLICY_NONE"}
    assert body["check_titles"]["RTP_OFF"] == "Постоянная защита не работает"
    lic = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/findings?check=LICENSE").json()["items"][0]
    assert lic["host"] == "" and lic["target"] == "AAAA-BBBB" and lic["details"]["days_left"] == 15
    searched = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/findings?q=servers").json()
    assert {i["check"] for i in searched["items"]} == {"POLICY_NONE", "TASK_NO_SCAN"}
    detail = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/findings/{lic['key']}").json()
    assert detail["description"] and detail["history"][0]["snapshot_id"] == snap["id"] and detail["verdict"] is None
