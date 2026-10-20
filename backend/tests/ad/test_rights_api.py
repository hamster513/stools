"""Ручки «группы учётки» и «права через GPO» на синтетическом домене."""
from __future__ import annotations

import json
from typing import Any

from fastapi.testclient import TestClient

from api.modules.ad.services.snapshots import snapshot_path
from tests.ad.synthetic import DN, build_export, rid

WS = f"OU=Ws,{DN}"
SRV = f"OU=Srv,{DN}"
TIER0 = rid(1301)
ADMIN2 = rid(1102)
GPO_WS = f"CN={{22222222-2222-2222-2222-222222222222}},CN=Policies,CN=System,{DN}"
GPO_SRV = f"CN={{33333333-3333-3333-3333-333333333333}},CN=Policies,CN=System,{DN}"


def _gpo(dn: str, name: str) -> dict[str, Any]:
    guid = dn.split(",", 1)[0].removeprefix("CN=")
    return {"dn": dn, "class": "groupPolicyContainer", "cn": guid, "name": guid, "displayName": name,
            "gpcFileSysPath": f"\\\\corp.local\\SysVol\\corp.local\\Policies\\{guid}"}


def _pc(name: str, r: int, parent: str) -> dict[str, Any]:
    return {"dn": f"CN={name},{parent}", "class": "computer", "sid": rid(r), "sam": f"{name}$", "name": name,
            "uac": 4096, "dNSHostName": f"{name.lower()}.corp.local"}


def _export() -> dict[str, Any]:
    """Синтетика + две GPO: «Ws Admins» на OU=Ws (Tier0 в Administrators и Remote Desktop Users
    на PC1, PC2), «Srv RDP» на OU=Srv (Tier0 в Remote Desktop Users на SRV1)."""
    raw = build_export()
    raw["objects"] += [
        {"dn": WS, "class": "organizationalUnit", "gpLink": f"[LDAP://{GPO_WS};0]"},
        {"dn": SRV, "class": "organizationalUnit", "gpLink": f"[LDAP://{GPO_SRV};0]"},
        _pc("PC1", 1401, WS), _pc("PC2", 1402, WS), _pc("SRV1", 1403, SRV),
        _gpo(GPO_WS, "Ws Admins"), _gpo(GPO_SRV, "Srv RDP"),
    ]
    raw["sysvol"][GPO_WS] = {"GptTmpl.inf": f"[Group Membership]\n*S-1-5-32-544__Members = *{TIER0}\n*{TIER0}__Memberof = *S-1-5-32-555\n"}
    raw["sysvol"][GPO_SRV] = {"GptTmpl.inf": f"[Group Membership]\n*{TIER0}__Memberof = *S-1-5-32-555\n"}
    return raw


def _snapshot(client: TestClient) -> int:
    r = client.post("/api/ad/snapshots/file", files={"file": ("ad.json", json.dumps(_export()).encode(), "application/json")})
    assert r.status_code == 202, r.text
    job = client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "done", job
    snap_id: int = client.get("/api/ad/snapshots").json()[0]["id"]
    return snap_id


def test_account_groups(auth_client: TestClient) -> None:
    snap_id = _snapshot(auth_client)
    snap = auth_client.get(f"/api/ad/snapshots/{snap_id}").json()
    r = auth_client.get(f"/api/ad/snapshots/{snap_id}/account-groups/{ADMIN2}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["snapshot_id"], body["collected_at"], body["sid"], body["name"]) == (snap_id, snap["collected_at"], ADMIN2, "CORP\\admin2")
    by_sid = {g["sid"]: g for g in body["groups"]}
    assert by_sid[TIER0] == {"sid": TIER0, "name": "CORP\\Tier0", "direct": True, "primary": False}
    assert by_sid[rid(512)]["direct"] is False
    assert by_sid[rid(513)]["direct"] is True and by_sid[rid(513)]["primary"] is True
    assert body["notes"] == []
    r = auth_client.get(f"/api/ad/snapshots/{snap_id}/account-groups/{rid(9999)}")
    assert r.status_code == 404 and r.json()["detail"]
    assert auth_client.get(f"/api/ad/snapshots/999999/account-groups/{ADMIN2}").status_code == 404


def test_gpo_rights_filters_and_limit(auth_client: TestClient) -> None:
    snap_id = _snapshot(auth_client)
    snap = auth_client.get(f"/api/ad/snapshots/{snap_id}").json()
    url = f"/api/ad/snapshots/{snap_id}/gpo-rights"
    r = auth_client.get(url)
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["snapshot_id"], body["collected_at"]) == (snap_id, snap["collected_at"])
    assert body["links_known"] is True and body["files_known"] is True and isinstance(body["notes"], list)
    got = [(x["gpo"]["name"], x["local_group"], x["action"], x["hosts"], x["hosts_total"]) for x in body["rights"]]
    assert got == [
        ("Srv RDP", "Remote Desktop Users", "memberof", ["srv1.corp.local"], 1),
        ("Ws Admins", "Administrators", "member", ["pc1.corp.local", "pc2.corp.local"], 2),
        ("Ws Admins", "Remote Desktop Users", "memberof", ["pc1.corp.local", "pc2.corp.local"], 2),
    ]
    assert all(x["group_sid"] == TIER0 and x["group_name"] == "CORP\\Tier0" for x in body["rights"])

    cut = auth_client.get(url, params={"hosts_limit": 1}).json()["rights"]
    assert [(x["hosts"], x["hosts_total"]) for x in cut] == [(["srv1.corp.local"], 1), (["pc1.corp.local"], 2), (["pc1.corp.local"], 2)]
    none = auth_client.get(url, params={"hosts_limit": 0}).json()["rights"]
    assert [(x["hosts"], x["hosts_total"]) for x in none] == [([], 1), ([], 2), ([], 2)]
    # Обрезка ответа не трогает общие списки: следующий запрос снова видит все хосты.
    assert auth_client.get(url).json() == body

    # Хост ищется по полному списку, до обрезки.
    on_pc2 = auth_client.get(url, params={"host": "PC2.CORP.LOCAL", "hosts_limit": 1}).json()["rights"]
    assert [(x["gpo"]["name"], x["local_group"]) for x in on_pc2] == [("Ws Admins", "Administrators"), ("Ws Admins", "Remote Desktop Users")]
    on_pc1 = auth_client.get(url, params={"host": "PC1.CORP.LOCAL"}).json()["rights"]
    assert [x["gpo"]["name"] for x in on_pc1] == ["Ws Admins", "Ws Admins"]
    admins = auth_client.get(url, params={"local_group": "administrators"}).json()["rights"]
    assert [(x["gpo"]["name"], x["local_group"]) for x in admins] == [("Ws Admins", "Administrators")]
    rdp = auth_client.get(url, params={"local_group": "remote desktop users", "host": "srv1.corp.local"}).json()["rights"]
    assert [x["gpo"]["name"] for x in rdp] == ["Srv RDP"]
    assert len(auth_client.get(url, params={"group_sid": TIER0.lower()}).json()["rights"]) == 3
    assert auth_client.get(url, params={"group_sid": rid(512)}).json()["rights"] == []
    assert auth_client.get(url, params={"host": "nope.corp.local"}).json()["rights"] == []

    assert auth_client.get(url, params={"hosts_limit": 10001}).status_code == 422
    assert auth_client.get(url, params={"hosts_limit": -1}).status_code == 422
    assert auth_client.get(url, params={"hosts_limit": 10000}).status_code == 200
    assert auth_client.get("/api/ad/snapshots/999999/gpo-rights").status_code == 404


def test_missing_export_file_is_409(auth_client: TestClient, app_settings: Any) -> None:
    snap_id = _snapshot(auth_client)
    snapshot_path(app_settings.data_dir, snap_id).unlink()
    for url in (f"/api/ad/snapshots/{snap_id}/account-groups/{ADMIN2}", f"/api/ad/snapshots/{snap_id}/gpo-rights"):
        r = auth_client.get(url)
        assert r.status_code == 409 and r.json() == {"detail": "файл выгрузки снапшота недоступен"}


def test_broken_export_file_is_409(auth_client: TestClient, app_settings: Any) -> None:
    snap_id = _snapshot(auth_client)
    snapshot_path(app_settings.data_dir, snap_id).write_bytes(b"not json")
    r = auth_client.get(f"/api/ad/snapshots/{snap_id}/gpo-rights")
    assert r.status_code == 409 and r.json() == {"detail": "файл выгрузки снапшота недоступен"}


def test_requires_login(auth_client: TestClient) -> None:
    snap_id = _snapshot(auth_client)
    auth_client.cookies.clear()
    assert auth_client.get(f"/api/ad/snapshots/{snap_id}/account-groups/{ADMIN2}").status_code == 401
    assert auth_client.get(f"/api/ad/snapshots/{snap_id}/gpo-rights").status_code == 401
