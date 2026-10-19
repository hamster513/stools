"""Снапшоты, находки, сравнение и статусы находок через API на синтетическом домене."""
from __future__ import annotations

import datetime as dt
import gzip
import json
from typing import Any

from fastapi.testclient import TestClient

from api.modules.ad.services.snapshots import snapshot_path
from tests.ad.synthetic import NOW, build_export


def _upload(client: TestClient, raw: dict[str, Any], name: str = "ad.json") -> dict[str, Any]:
    r = client.post("/api/ad/snapshots/file", files={"file": (name, json.dumps(raw).encode(), "application/json")})
    assert r.status_code == 202, r.text
    return client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()


def test_upload_creates_domain_snapshot_and_findings(auth_client: TestClient) -> None:
    job = _upload(auth_client, build_export())
    assert job["status"] == "done", job
    domains = auth_client.get("/api/ad/domains").json()
    assert len(domains) == 1 and domains[0]["netbios"] == "CORP" and domains[0]["snapshots"] == 1
    snaps = auth_client.get(f"/api/ad/snapshots?domain_id={domains[0]['id']}").json()
    assert len(snaps) == 1 and snaps[0]["source"] == "file" and snaps[0]["objects"] > 20
    assert snaps[0]["by_severity"]["Critical"] == 1 and snaps[0]["new"] is None
    body = auth_client.get(f"/api/ad/snapshots/{snaps[0]['id']}/findings").json()
    assert body["total"] == snaps[0]["findings"] > 20
    assert body["items"][0]["severity"] == "Critical" and body["items"][0]["check"] == "DCSync"
    assert body["facets"]["delta"] == {"new": 0, "same": body["total"], "gone": 0} and body["facets"]["status"]["new"] == body["total"]
    assert set(body["facets"]["check"]) >= {"DCSync", "Kerberoast", "ADCS_ESC"}
    filtered = auth_client.get(f"/api/ad/snapshots/{snaps[0]['id']}/findings?check=Kerberoast").json()
    assert filtered["total"] == 1 and filtered["items"][0]["identity"] == "CORP\\svc_sql"
    searched = auth_client.get(f"/api/ad/snapshots/{snaps[0]['id']}/findings?q=helpdesk").json()
    assert searched["total"] >= 3
    overview = auth_client.get(f"/api/ad/domains/{domains[0]['id']}/overview").json()
    assert overview["snapshot"]["findings"] == body["total"]
    dcsync = next(c for c in overview["checks"] if c["code"] == "DCSync")
    assert dcsync["total"] == 4 and dcsync["by_severity"]["Critical"] == 1


def test_overview_has_categories_and_detail_has_guidance(auth_client: TestClient) -> None:
    assert _upload(auth_client, build_export())["status"] == "done"
    domain_id = auth_client.get("/api/ad/domains").json()[0]["id"]
    checks = auth_client.get(f"/api/ad/domains/{domain_id}/overview").json()["checks"]
    assert checks and all(c["category"] and c["category_title"] for c in checks)
    assert next(c for c in checks if c["code"] == "DCSync")["category_title"] == "Права на объекты"
    snap = auth_client.get(f"/api/ad/snapshots?domain_id={domain_id}").json()[0]["id"]
    item = auth_client.get(f"/api/ad/snapshots/{snap}/findings?check=Kerberoast").json()["items"][0]
    guidance = auth_client.get(f"/api/ad/snapshots/{snap}/findings/{item['key']}").json()["guidance"]
    assert "gMSA" in guidance["remediation"]
    assert guidance["references"] and all(r["title"] and r["url"].startswith("https://") for r in guidance["references"])


def test_bad_file_fails_job_with_message(auth_client: TestClient) -> None:
    r = auth_client.post("/api/ad/snapshots/file", files={"file": ("x.json", b'{"format": "other"}', "application/json")})
    job = auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "failed" and "не выгрузка" in job["error"]
    assert auth_client.get("/api/ad/domains").json() == []


def test_second_snapshot_compares_new_and_fixed(auth_client: TestClient, db_session: Any) -> None:
    assert _upload(auth_client, build_export())["status"] == "done"
    later = build_export(now=NOW + dt.timedelta(days=7))
    for o in later["objects"]:
        if o.get("sam") == "svc_sql":
            o["spn"] = []  # Kerberoast закрыт
        if o.get("sam") == "helpdesk":
            o["spn"] = ["HTTP/help.corp.local"]  # новый Kerberoast
    assert _upload(auth_client, later)["status"] == "done"
    domain_id = auth_client.get("/api/ad/domains").json()[0]["id"]
    snaps = auth_client.get(f"/api/ad/snapshots?domain_id={domain_id}").json()
    assert len(snaps) == 2 and snaps[0]["previous_id"] == snaps[1]["id"]
    assert snaps[0]["new"] == 1 and snaps[0]["fixed"] == 1
    new = auth_client.get(f"/api/ad/snapshots/{snaps[0]['id']}/findings?delta=new").json()
    assert new["total"] == 1 and new["items"][0]["identity"] == "CORP\\helpdesk" and new["items"][0]["status"] == "new"
    fixed = auth_client.get(f"/api/ad/snapshots/{snaps[0]['id']}/findings?status=resolved").json()
    assert fixed["total"] == 1 and fixed["items"][0]["identity"] == "CORP\\svc_sql" and fixed["items"][0]["status"] == "resolved"
    overview = auth_client.get(f"/api/ad/domains/{domain_id}/overview").json()
    assert overview["compared_to"]["new"] == 1 and overview["compared_to"]["fixed"] == 1
    kerb = next(c for c in overview["checks"] if c["code"] == "Kerberoast")
    assert kerb["new"] == 1 and kerb["resolved"] == 1


def test_accepted_risk_survives_next_snapshot_and_detail_has_history(auth_client: TestClient) -> None:
    assert _upload(auth_client, build_export())["status"] == "done"
    domain_id = auth_client.get("/api/ad/domains").json()[0]["id"]
    snap1 = auth_client.get(f"/api/ad/snapshots?domain_id={domain_id}").json()[0]["id"]
    item = auth_client.get(f"/api/ad/snapshots/{snap1}/findings?check=Kerberoast").json()["items"][0]
    ref = {"module": "ad", "scope_id": domain_id, "key": item["key"]}
    r = auth_client.put("/api/findings/state", json={**ref, "status": "risk_accepted", "comment": "сервисная учётка, пароль 32 символа"})
    assert r.status_code == 200, r.text
    assert _upload(auth_client, build_export(now=NOW + dt.timedelta(days=1)))["status"] == "done"
    snap2 = auth_client.get(f"/api/ad/snapshots?domain_id={domain_id}").json()[0]["id"]
    body = auth_client.get(f"/api/ad/snapshots/{snap2}/findings?check=Kerberoast&status=all").json()
    assert body["items"][0]["status"] == "risk_accepted" and body["facets"]["status"]["risk_accepted"] == 1
    assert auth_client.get(f"/api/ad/snapshots/{snap2}/findings?check=Kerberoast").json()["total"] == 0
    detail = auth_client.get(f"/api/ad/snapshots/{snap2}/findings/{item['key']}").json()
    assert detail["status"] == "risk_accepted" and len(detail["history"]) == 2
    assert detail["description"]
    state = auth_client.get("/api/findings/state", params=ref).json()
    assert state["reason"].startswith("сервисная") and state["updated_by"] == "tester"
    assert auth_client.put("/api/findings/state", json={**ref, "status": "new"}).status_code == 200
    assert auth_client.get(f"/api/ad/snapshots/{snap2}/findings?check=Kerberoast").json()["items"][0]["status"] == "new"


def test_reanalyze_with_new_rules_and_delete(auth_client: TestClient, app_settings: Any) -> None:
    assert _upload(auth_client, build_export())["status"] == "done"
    snap = auth_client.get("/api/ad/snapshots").json()[0]
    settings = auth_client.get("/api/ad/settings").json()
    assert len(settings["checks"]) == 52 and settings["config"]["user_inactivity_days"] == 90
    cfg = settings["config"]
    cfg["allowlist_short"].append("SVC_BACKUP")
    assert auth_client.put("/api/ad/settings", json=cfg).status_code == 200
    r = auth_client.post(f"/api/ad/snapshots/{snap['id']}/reanalyze")
    assert r.status_code == 202
    assert auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()["status"] == "done"
    after = auth_client.get(f"/api/ad/snapshots/{snap['id']}/findings?check=DCSync&q=svc_backup").json()
    assert all(i["allowlisted"] and i["severity"] == "Low" for i in after["items"]) and after["total"] == 2
    path = snapshot_path(app_settings.data_dir, snap["id"])
    assert path.exists()
    assert auth_client.delete(f"/api/ad/snapshots/{snap['id']}").status_code == 204
    assert not path.exists() and auth_client.get("/api/ad/snapshots").json() == []


def test_gzip_bomb_fails_job_without_snapshot(auth_client: TestClient, monkeypatch: Any) -> None:
    """Аудит H2: сжатая выгрузка, распаковка которой больше лимита, — задание
    failed с текстом про лимит, снапшот не создаётся."""
    from api.modules.ad.core import export

    monkeypatch.setattr(export, "MAX_UNPACKED", 1024 * 1024)
    padded = json.dumps(build_export()).encode() + b" " * (2 * 1024 * 1024)
    r = auth_client.post("/api/ad/snapshots/file", files={"file": ("ad.json.gz", gzip.compress(padded), "application/gzip")})
    job = auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "failed" and "распакованный размер больше лимита" in job["error"]
    assert auth_client.get("/api/ad/domains").json() == []
