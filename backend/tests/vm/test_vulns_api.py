"""Таблица пар, карточка, обзор, экспорт и пересчёт через API."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def loaded(auth_client: TestClient) -> TestClient:
    r = auth_client.post("/api/vm/import/file", files={"file": ("hosts.csv", (FIXTURES / "hosts.csv").read_bytes(), "text/csv")})
    assert r.status_code == 202
    for name, files in (("epss", ("epss.csv",)), ("nvd", ("nvd-2021.json", "nvd-2019.json")), ("exploitdb", ("exploits.csv",)), ("msf", ("msf.json",)), ("attack", ("ctid-kev.json",))):
        payload = [("files", (f, (FIXTURES / f).read_bytes(), "application/octet-stream")) for f in files]
        r = auth_client.post(f"/api/vm/refs/{name}/upload", files=payload)
        assert r.status_code == 202, r.text
    auth_client.put("/api/vm/zones", json=[{"name": "DMZ", "internet_access": True, "confidential_data": True}])
    assert auth_client.post("/api/vm/recalculate").status_code == 202
    return auth_client


def test_vulns_default_sort_and_facets(loaded: TestClient) -> None:
    body = loaded.get("/api/vm/vulns").json()
    assert body["total"] == 4
    risks = [i["risk"] for i in body["items"]]
    assert risks == sorted(risks, reverse=True)
    top = body["items"][0]
    assert top["cve_id"] == "CVE-2021-44228" and top["hostname"] == "srv01.corp.local"
    assert top["risk"] == 100 and top["level"] == "critical"
    assert top["cvss"] == 10.0 and top["cvss_source"] == "nvd_v3" and top["exploitdb_type"] == "remote"
    f = body["facets"]
    assert f["zone"] == {"DMZ": 3, "Internal": 1}
    assert sum(f["level"].values()) == 4 and f["exploits"]["yes"] == 2
    assert loaded.get("/api/vm/vulns?offset=1").json()["facets"] is None


def test_vulns_filters(loaded: TestClient) -> None:
    assert loaded.get("/api/vm/vulns?zone=DMZ").json()["total"] == 3
    assert loaded.get("/api/vm/vulns?cve=cve-2021-44228").json()["total"] == 1
    assert loaded.get("/api/vm/vulns?q=ws02").json()["total"] == 1
    assert loaded.get("/api/vm/vulns?level=critical").json()["total"] >= 1
    assert loaded.get("/api/vm/vulns?exploits=false").json()["total"] == 2
    assert loaded.get("/api/vm/vulns?cvss_source=none").json()["total"] == 2
    assert loaded.get("/api/vm/vulns?limit=1001").status_code == 422
    assert loaded.get("/api/vm/vulns?sort=bogus").status_code == 422
    by_cve = loaded.get("/api/vm/vulns?sort=cve_asc").json()["items"]
    assert [i["cve_id"] for i in by_cve] == sorted(i["cve_id"] for i in by_cve)


def test_risk_card(loaded: TestClient) -> None:
    item = loaded.get("/api/vm/vulns?cve=CVE-2021-44228").json()["items"][0]
    card = loaded.get(f"/api/vm/vulns/{item['host_id']}/cve-2021-44228").json()
    assert card["risk"]["score"] == 100 and card["risk"]["level_word"] == "критический"
    assert card["risk"]["epss"]["substituted"] is False and card["risk"]["epss"]["value"] == 0.97565
    assert card["risk"]["cvss"]["value"] == 1.0 and card["risk"]["cvss"]["source"] == "CVSS 10"
    assert card["risk"]["impact"]["substituted"] is False and card["host"]["internet_access"] is True
    assert len(card["cve"]["exploits"]) == 2 and card["cve"]["msf_modules"][0]["rank"] == 600
    assert card["cve"]["nvd_url"].endswith("CVE-2021-44228")
    assert card["refs_loaded_at"]["epss"]

    bare = loaded.get("/api/vm/vulns?cve=CVE-2023-1234").json()["items"][0]
    card = loaded.get(f"/api/vm/vulns/{bare['host_id']}/CVE-2023-1234").json()
    assert card["risk"]["cvss"]["substituted"] and card["risk"]["cve_param"]["substituted"]
    assert card["risk"]["impact"]["substituted"]  # зона Internal не размечена
    assert loaded.get("/api/vm/vulns/999999/CVE-0000-0000").status_code == 404


def test_host_detail_and_overview(loaded: TestClient) -> None:
    item = loaded.get("/api/vm/vulns?q=srv01").json()["items"][0]
    detail = loaded.get(f"/api/vm/hosts/{item['host_id']}").json()
    assert detail["host"]["hostname"] == "srv01.corp.local" and len(detail["items"]) == 2

    ov = loaded.get("/api/vm/overview").json()
    assert (ov["hosts"], ov["pairs"], ov["cves"]) == (3, 4, 4)
    assert ov["threshold"] == 70 and ov["above_threshold"] >= 1
    assert sum(ov["distribution"].values()) == 4
    assert ov["top_cves"][0]["cve_id"] == "CVE-2021-44228"
    assert ov["top_hosts"][0]["hostname"] == "srv01.corp.local"
    data = ov["data"]
    assert data["last_import"]["hosts"] == 3 and data["unmarked_zones"] == 1
    assert data["cves_without_epss"] == 1 and data["cves_without_nvd"] == 2
    assert all(not r["stale"] for r in data["refs"])


def test_export_csv(loaded: TestClient) -> None:
    r = loaded.get("/api/vm/export?zone=DMZ")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    text = r.content.decode("utf-8")
    assert text.startswith("﻿Риск;Уровень;Хост")
    lines = [line for line in text.splitlines() if line]
    assert len(lines) == 1 + 3
    assert lines[1].split(";")[4] == "CVE-2021-44228"


def test_empty_overview(auth_client: TestClient) -> None:
    ov = auth_client.get("/api/vm/overview").json()
    assert ov["pairs"] == 0 and ov["data"]["last_import"] is None and ov["top_cves"] == []
