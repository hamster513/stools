"""Серверы, снапшоты, обзор, пересчёт, удаление через API на синтетическом KSC."""
from __future__ import annotations

import datetime as dt
import gzip
import json
from typing import Any

from fastapi.testclient import TestClient

from api.modules.ksc.services.snapshots import snapshot_path
from tests.ad.synthetic import build_export as build_ad
from tests.ksc.synthetic import NOW, build_export


def upload(client: TestClient, raw: dict[str, Any], name: str = "ksc.json") -> dict[str, Any]:
    r = client.post("/api/ksc/snapshots/file", files={"file": (name, json.dumps(raw).encode(), "application/json")})
    assert r.status_code == 202, r.text
    return client.get(f"/api/ksc/jobs/{r.json()['job_id']}").json()


def test_upload_creates_server_snapshot_hosts_findings(auth_client: TestClient) -> None:
    job = upload(auth_client, build_export())
    assert job["status"] == "done", job
    servers = auth_client.get("/api/ksc/servers").json()
    assert len(servers) == 1 and servers[0]["name"] == "ksc01" and servers[0]["version"] == "15.1.0.11225" and servers[0]["snapshots"] == 1
    snaps = auth_client.get(f"/api/ksc/snapshots?server_id={servers[0]['id']}").json()
    assert len(snaps) == 1 and snaps[0]["source"] == "file" and snaps[0]["hosts"] == 14 and snaps[0]["new"] is None
    assert snaps[0]["by_severity"]["Critical"] == 2  # RTP_OFF на WS02, NO_PROTECTION на WS07
    overview = auth_client.get(f"/api/ksc/servers/{servers[0]['id']}/overview").json()
    assert overview["snapshot"]["findings"] == snaps[0]["findings"]
    cov = overview["coverage"]
    assert cov["ad_total"] is None and cov["ksc_total"] == 14 and cov["with_agent"] == 12 and cov["with_protection"] == 10
    assert cov["protection_on"] == 9 and cov["bases_fresh"] == 9
    rtp = next(c for c in overview["checks"] if c["code"] == "RTP_OFF")
    assert rtp["total"] == 1 and rtp["by_severity"]["Critical"] == 1
    assert not any(c["code"].startswith("COVER_") and c["total"] for c in overview["checks"])


def test_gzip_upload_and_bad_files(auth_client: TestClient) -> None:
    raw = gzip.compress(json.dumps(build_export()).encode())
    r = auth_client.post("/api/ksc/snapshots/file", files={"file": ("ksc.json.gz", raw, "application/gzip")})
    assert auth_client.get(f"/api/ksc/jobs/{r.json()['job_id']}").json()["status"] == "done"
    r = auth_client.post("/api/ksc/snapshots/file", files={"file": ("x.json", b'{"format": "stools-ad/1"}', "application/json")})
    job = auth_client.get(f"/api/ksc/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "failed" and "не выгрузка" in job["error"]
    assert len(auth_client.get("/api/ksc/snapshots").json()) == 1
    r = auth_client.post("/api/ksc/snapshots/file", files={"file": ("e.json", b"", "application/json")})
    assert r.status_code == 422


def test_upload_size_cap(auth_client: TestClient, monkeypatch: Any) -> None:
    from api.modules.ksc.routers import snapshots as router

    monkeypatch.setattr(router, "MAX_UPLOAD", 100)
    r = auth_client.post("/api/ksc/snapshots/file", files={"file": ("big.json", b"x" * 101, "application/json")})
    assert r.status_code == 413 and "МБ" in r.json()["detail"]


def test_second_snapshot_compares_new_and_fixed(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    later = build_export(now=NOW + dt.timedelta(days=7))
    for h in later["hosts"]:
        if h["KLHST_WKS_DN"] == "WS02":
            h["KLHST_WKS_RTP_STATE"] = 7  # RTP_OFF закрыт
        if h["KLHST_WKS_DN"] == "WS01":
            h["KLHST_WKS_RTP_STATE"] = 2  # новый RTP_OFF
    assert upload(auth_client, later)["status"] == "done"
    server_id = auth_client.get("/api/ksc/servers").json()[0]["id"]
    snaps = auth_client.get(f"/api/ksc/snapshots?server_id={server_id}").json()
    assert len(snaps) == 2 and snaps[0]["previous_id"] == snaps[1]["id"]
    assert snaps[0]["new"] == 1 and snaps[0]["fixed"] == 1
    overview = auth_client.get(f"/api/ksc/servers/{server_id}/overview").json()
    assert overview["compared_to"]["new"] == 1 and overview["compared_to"]["fixed"] == 1
    rtp = next(c for c in overview["checks"] if c["code"] == "RTP_OFF")
    assert rtp["new"] == 1 and rtp["fixed"] == 1


def test_coverage_uses_latest_ad_snapshot_and_reanalyze_refreshes(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    server_id = auth_client.get("/api/ksc/servers").json()[0]["id"]
    assert auth_client.get(f"/api/ksc/servers/{server_id}/overview").json()["coverage"]["ad_total"] is None
    r = auth_client.post("/api/ad/snapshots/file", files={"file": ("ad.json", json.dumps(build_ad()).encode(), "application/json")})
    assert auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()["status"] == "done"
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    r = auth_client.post(f"/api/ksc/snapshots/{snap['id']}/reanalyze")
    assert r.status_code == 202 and auth_client.get(f"/api/ksc/jobs/{r.json()['job_id']}").json()["status"] == "done"
    cov = auth_client.get(f"/api/ksc/servers/{server_id}/overview").json()["coverage"]
    assert cov["ad_total"] == 2 and cov["both"] == 2 and cov["ad_only"] == 0 and cov["ksc_only"] == 12
    hosts = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/hosts?in_ad=both").json()
    assert {h["name"] for h in hosts["items"]} == {"WS01", "SRV01"}


def test_settings_reanalyze_with_allowlist_and_delete(auth_client: TestClient, app_settings: Any) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    settings = auth_client.get("/api/ksc/settings").json()
    assert len(settings["checks"]) == 18 and settings["config"]["bases_old_days"] == 3 and settings["defaults"]["license_days"] == 30
    cfg = settings["config"]
    cfg["allowlist_hosts"] = ["ws02"]
    assert auth_client.put("/api/ksc/settings", json=cfg).status_code == 200
    r = auth_client.post(f"/api/ksc/snapshots/{snap['id']}/reanalyze")
    assert auth_client.get(f"/api/ksc/jobs/{r.json()['job_id']}").json()["status"] == "done"
    after = auth_client.get(f"/api/ksc/snapshots/{snap['id']}/findings?check=RTP_OFF").json()
    assert after["total"] == 1 and after["items"][0]["allowlisted"] and after["items"][0]["severity"] == "Info"
    path = snapshot_path(app_settings.data_dir, snap["id"])
    assert path.exists()
    assert auth_client.delete(f"/api/ksc/snapshots/{snap['id']}").status_code == 204
    assert not path.exists() and auth_client.get("/api/ksc/snapshots").json() == []
    assert auth_client.get(f"/api/ksc/servers/{snap['server_id']}/overview").json()["snapshot"] is None


def test_verdict_survives_next_snapshot(auth_client: TestClient) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    server_id = auth_client.get("/api/ksc/servers").json()[0]["id"]
    snap1 = auth_client.get("/api/ksc/snapshots").json()[0]["id"]
    item = auth_client.get(f"/api/ksc/snapshots/{snap1}/findings?check=RTP_OFF").json()["items"][0]
    assert auth_client.put(f"/api/ksc/verdicts/{item['key']}", json={"server_id": server_id, "reason": "стенд разработки"}).status_code == 204
    assert upload(auth_client, build_export(now=NOW + dt.timedelta(days=1)))["status"] == "done"
    snap2 = auth_client.get("/api/ksc/snapshots").json()[0]["id"]
    body = auth_client.get(f"/api/ksc/snapshots/{snap2}/findings?check=RTP_OFF").json()
    assert body["items"][0]["status"] == "accepted" and body["facets"]["status"]["accepted"] == 1
    detail = auth_client.get(f"/api/ksc/snapshots/{snap2}/findings/{item['key']}").json()
    assert detail["verdict"]["reason"] == "стенд разработки" and len(detail["history"]) == 2
    assert auth_client.delete(f"/api/ksc/verdicts/{item['key']}?server_id={server_id}").status_code == 204
    assert auth_client.get(f"/api/ksc/snapshots/{snap2}/findings?check=RTP_OFF").json()["items"][0]["status"] == "persisting"


def test_concurrent_job_rejected(auth_client: TestClient, db_session: Any) -> None:
    from api.modules.ksc.models import KscJob

    db_session.add(KscJob(kind="collect", stage="collecting", status="running", started_by="x"))
    db_session.commit()
    r = auth_client.post("/api/ksc/snapshots/file", files={"file": ("k.json", json.dumps(build_export()).encode(), "application/json")})
    assert r.status_code == 409
