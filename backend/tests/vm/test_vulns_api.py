"""Таблица пар, карточка, обзор, экспорт и пересчёт через API."""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.db.models import AppSetting
from api.modules.vm.models import VmCve, VmHost, VmHostCve, VmImport, VmZone
from api.modules.vm.services.stats import STATS_KEY
from kbaudit.attack.reference import rows_from_xlsx

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def loaded(auth_client: TestClient) -> TestClient:
    r = auth_client.post("/api/vm/import/file", files={"file": ("hosts.csv", (FIXTURES / "hosts.csv").read_bytes(), "text/csv")})
    assert r.status_code == 202
    for name, files in (("epss", ("epss.csv",)), ("nvd", ("nvd-2021.json", "nvd-2019.json")), ("exploitdb", ("exploits.csv",)), ("msf", ("msf.json",)), ("attack", ("ctid-kev.json",)), ("kev", ("kev.json",))):
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
    # KEV: L = 1; CVSS 10, сетевой вектор, хост из интернета; High + конф. + интернет = 1.0.
    assert top["risk"] == 99 and top["level"] == "critical"
    assert top["cvss"] == 10.0 and top["cvss_source"] == "nvd_v3" and top["exploitdb_type"] == "remote"
    assert (top["kev"], top["kev_ransomware"]) == (True, True)
    f = body["facets"]
    assert f["zone"] == {"DMZ": 3, "Internal": 1}
    # 100 и 97 (BlueKeep) — критические; KEV без NVD: 40 (Critical) и 24 (зона не размечена).
    assert f["level"] == {"low": 0, "medium": 0, "high": 2, "critical": 2} and f["exploits"]["yes"] == 2
    assert f["kev"] == {"yes": 3, "no": 1}
    assert "risk" not in f
    assert loaded.get("/api/vm/vulns?offset=1").json()["facets"] is None


def test_vulns_filters(loaded: TestClient) -> None:
    assert loaded.get("/api/vm/vulns?zone=DMZ").json()["total"] == 3
    assert loaded.get("/api/vm/vulns?cve=cve-2021-44228").json()["total"] == 1
    assert loaded.get("/api/vm/vulns?q=ws02").json()["total"] == 1
    assert loaded.get("/api/vm/vulns?level=critical").json()["total"] >= 1
    assert loaded.get("/api/vm/vulns?exploits=false").json()["total"] == 2
    assert loaded.get("/api/vm/vulns?cvss_source=none").json()["total"] == 2
    assert loaded.get("/api/vm/vulns?kev=true").json()["total"] == 3
    assert [i["cve_id"] for i in loaded.get("/api/vm/vulns?kev=false").json()["items"]] == ["CVE-2019-0708"]
    assert loaded.get("/api/vm/vulns?limit=1001").status_code == 422
    assert loaded.get("/api/vm/vulns?sort=bogus").status_code == 422
    by_cve = loaded.get("/api/vm/vulns?sort=cve_asc").json()["items"]
    assert [i["cve_id"] for i in by_cve] == sorted(i["cve_id"] for i in by_cve)


def test_risk_card(loaded: TestClient) -> None:
    item = loaded.get("/api/vm/vulns?cve=CVE-2021-44228").json()["items"][0]
    card = loaded.get(f"/api/vm/vulns/{item['host_id']}/cve-2021-44228").json()
    risk = card["risk"]
    assert risk["score"] == 99 and risk["level"] == "critical" and risk["level_word"] == "критический"
    assert risk["model"] == "additive" and risk["computed_score"] == 99
    assert [b["points"] for b in risk["blocks"].values()] == [40, 25, 20, 14]
    assert risk["floor"] == 90 and {r["minimum"] for r in risk["rules"]} == {80, 90}
    assert not risk["missing"] and card["host"]["internet_access"] is True
    assert (card["cve"]["kev"], card["cve"]["kev_added"], card["cve"]["kev_ransomware"], card["cve"]["kev_due"]) == (True, "2021-12-10", True, "2021-12-24")
    assert len(card["cve"]["exploits"]) == 2 and card["cve"]["msf_modules"][0]["rank"] == 600
    assert card["cve"]["nvd_url"].endswith("CVE-2021-44228")
    assert card["refs_loaded_at"]["epss"] and card["refs_loaded_at"]["kev"]

    bare = loaded.get("/api/vm/vulns?cve=CVE-2023-1234").json()["items"][0]
    card = loaded.get(f"/api/vm/vulns/{bare['host_id']}/CVE-2023-1234").json()
    assert card["risk"]["blocks"]["severity"]["assumed"]
    assert card["risk"]["blocks"]["exposure"]["assumed"]
    assert card["risk"]["blocks"]["asset"]["assumed"]
    assert card["risk"]["score"] == 80 and card["risk"]["level"] == "high"  # KEV floor
    assert loaded.get("/api/vm/vulns/999999/CVE-0000-0000").status_code == 404


def test_host_detail_and_overview(loaded: TestClient) -> None:
    item = loaded.get("/api/vm/vulns?q=srv01").json()["items"][0]
    detail = loaded.get(f"/api/vm/hosts/{item['host_id']}").json()
    assert detail["host"]["hostname"] == "srv01.corp.local" and len(detail["items"]) == 2

    ov = loaded.get("/api/vm/overview").json()
    assert (ov["hosts"], ov["pairs"], ov["cves"]) == (3, 4, 4)
    assert ov["threshold"] == 80 and ov["above_threshold"] >= 1
    assert ov["distribution"] == {"low": 0, "medium": 0, "high": 2, "critical": 2} and ov["kev_pairs"] == 3
    assert ov["top_cves"][0]["cve_id"] == "CVE-2021-44228"
    assert ov["top_hosts"][0]["hostname"] == "srv01.corp.local"
    data = ov["data"]
    assert data["last_import"]["hosts"] == 3 and data["unmarked_zones"] == 1
    assert data["cves_without_epss"] == 1 and data["cves_without_nvd"] == 2
    assert all(not r["stale"] for r in data["refs"] if r["loaded_at"] is not None)
    assert next(r for r in data["refs"] if r["name"] == "ghsa")["stale"]  # not loaded by this fixture


def test_export_csv(loaded: TestClient) -> None:
    r = loaded.get("/api/vm/export?zone=DMZ")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    text = r.content.decode("utf-8")
    assert text.startswith("﻿Риск;Уровень;Хост") and ";KEV;" in text.splitlines()[0]
    lines = [line for line in text.splitlines() if line]
    assert len(lines) == 1 + 3
    assert lines[1].split(";")[4] == "CVE-2021-44228"
    # KEV — «да» или пустая ячейка, не True/False.
    kev = {r[4]: r[15] for r in csv.reader(io.StringIO("\n".join(lines[1:])), delimiter=";")}
    assert kev["CVE-2021-44228"] == "да" and set(kev.values()) <= {"да", ""}
    full = loaded.get("/api/vm/export").content.decode("utf-8")
    kev_all = {r[4]: r[15] for r in csv.reader(io.StringIO(full.split("\r\n", 1)[1]), delimiter=";") if r}
    assert kev_all["CVE-2019-0708"] == ""


def test_export_csv_neutralises_formulas(loaded: TestClient, db_session: Any) -> None:
    """Аудит L2: имя хоста и ОС приходят из выгрузки MaxPatrol — Excel не должен исполнить их как
    формулу. Строки с =, +, -, @ получают апостроф; числа идут как есть."""
    host = db_session.execute(select(VmHost).where(VmHost.hostname == "srv01.corp.local")).scalar_one()
    host.hostname = '=HYPERLINK("http://evil.example","x")'
    host.os_name = "@SUM(1+1)"
    db_session.commit()
    text = loaded.get("/api/vm/export?cve=CVE-2021-44228").content.decode("utf-8")
    row = next(csv.reader(io.StringIO(text.splitlines()[1]), delimiter=";"))
    assert row[2] == "'=HYPERLINK(\"http://evil.example\",\"x\")" and row[13] == "'@SUM(1+1)"
    assert row[0] == "99" and row[4] == "CVE-2021-44228" and float(row[5]) == 10.0


def test_export_xlsx(loaded: TestClient) -> None:
    """Тот же фильтр и те же колонки, что в CSV, но книгой Excel."""
    r = loaded.get("/api/vm/export", params={"zone": "DMZ", "format": "xlsx"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/vnd.openxmlformats")
    assert "stools-vm-vulns-" in r.headers["content-disposition"]
    table = rows_from_xlsx(r.content)
    assert table[0][:3] == ["Риск", "Уровень", "Хост"] and len(table[0]) == 19
    assert len(table) == 1 + 3 and table[1][4] == "CVE-2021-44228"
    assert loaded.get("/api/vm/export", params={"format": "pdf"}).status_code == 422


def test_legacy_levels_cannot_override_additive_policy(loaded: TestClient) -> None:
    before = loaded.get("/api/vm/vulns").json()
    response = loaded.put("/api/vm/settings", json={"weights": {"levels": {"medium": 15, "high": 35, "critical": 90}}})
    assert response.status_code == 200
    assert response.json()["weights"]["levels"] == {"medium": 40, "high": 80, "critical": 85}
    after = loaded.get("/api/vm/vulns").json()
    assert before["facets"]["level"] == after["facets"]["level"]
    assert [(r["risk"], r["level"]) for r in before["items"]] == [(r["risk"], r["level"]) for r in after["items"]]
    assert all(r["level"] in ("high", "critical") for r in after["items"] if r["kev"])


def test_empty_overview(auth_client: TestClient) -> None:
    ov = auth_client.get("/api/vm/overview").json()
    assert ov["pairs"] == 0 and ov["data"]["last_import"] is None and ov["top_cves"] == []


def test_overview_hides_medium_low(auth_client: TestClient, db_session: Any) -> None:
    alpha, beta, gamma = [VmHost(hostname=name, zone=name) for name in ("alpha", "beta", "gamma")]
    kev, mixed, medium = [f"CVE-2026-100{i}" for i in (1, 2, 3)]
    db_session.add_all([alpha, beta, gamma, VmCve(cve_id=kev, kev=True), VmCve(cve_id=medium),
                        VmCve(cve_id=mixed, epss=0.5, cvss_source="nvd_v3"),
                        VmImport(source="file", filename="sample.csv", hosts=3, pairs=6, cves=3),
                        *(VmZone(name=h.zone, marked=h is beta) for h in (alpha, beta, gamma))])
    db_session.flush()
    for host, cve, risk in [(alpha, kev, 100), (beta, kev, 80), (beta, mixed, 85),
                            (alpha, mixed, 79), (gamma, mixed, 39), (gamma, medium, 45)]:
        db_session.add(VmHostCve(host_id=host.id, cve_id=cve, risk=risk, risk_raw=risk))
    db_session.commit()
    yesterday = (dt.date.today() - dt.timedelta(days=2)).isoformat()
    for host, cve, change in [(beta, kev, {"status": "in_work", "due_date": yesterday}),
                              (gamma, medium, {"status": "in_work", "due_date": yesterday}),
                              (beta, mixed, {"status": "risk_accepted", "comment": "проверено"})]:
        response = auth_client.put("/api/findings/state", json={"module": "vm", "scope_id": 0,
                                   "key": f"{host.hostname}||{cve}", **change})
        assert response.status_code == 200, response.text
    assert auth_client.put("/api/vm/settings", json={"threshold": 90}).status_code == 200

    all_risks = auth_client.get("/api/vm/overview").json()
    assert auth_client.get("/api/vm/overview?hide_medium_low=false").json() == all_risks
    assert (all_risks["hosts"], all_risks["cves"], all_risks["pairs"], all_risks["pairs_all"]) == (3, 3, 5, 6)
    assert all_risks["top_hosts"][0]["hostname"] == "alpha"
    url = "/api/vm/overview?hide_medium_low=true"
    ov = auth_client.get(url).json()
    assert (ov["hosts"], ov["cves"], ov["pairs"], ov["pairs_all"]) == (2, 2, 2, 3)
    assert ov["distribution"] == {"low": 0, "medium": 0, "high": 1, "critical": 1}
    assert (ov["above_threshold"], ov["kev_pairs"]) == (1, 2)
    assert [(h["hostname"], h["pairs"], h["risk_sum"]) for h in ov["top_hosts"]] == [("beta", 2, 165), ("alpha", 1, 100)]
    assert [(c["cve_id"], c["hosts"], c["risk_sum"]) for c in ov["top_cves"]] == [(kev, 2, 180), (mixed, 1, 85)]
    counts = ov["findings"]
    assert [counts["by_status"][s] for s in ("new", "in_work", "risk_accepted")] == [1, 1, 1]
    assert (counts["overdue"], counts["unassigned"]) == (1, 2)
    assert [ov["data"][k] for k in ("unmarked_zones", "cves_without_epss", "cves_without_nvd")] == [1, 1, 1]
    assert ov["data"]["refs"] == all_risks["data"]["refs"]
    assert ov["data"]["last_import"] == all_risks["data"]["last_import"]

    # An existing deployment can serve a cache written before the filtered overview existed.
    row = db_session.get(AppSetting, STATS_KEY)
    old_cache = json.loads(row.value_json)
    old_cache.pop("high_risk", None)
    row.value_json = json.dumps(old_cache)
    db_session.commit()
    assert auth_client.get(url).json() == ov
    assert auth_client.put("/api/settings/findings", json={"counted": {"risk_accepted": True}}).status_code == 200
    assert auth_client.get(url).json()["pairs"] == 3
    assert auth_client.put("/api/vm/settings", json={"threshold": 40}).status_code == 200
    assert auth_client.get(url).json()["above_threshold"] == 3
    assert auth_client.get("/api/vm/overview").json()["above_threshold"] == 5

    query = {"level": ["high", "critical"], "min_risk": 90, "status": "all"}
    assert auth_client.get("/api/vm/vulns", params=query).json()["total"] == 1
    exported = auth_client.get("/api/vm/export", params=query)
    assert exported.status_code == 200 and len(exported.content.decode("utf-8-sig").splitlines()) == 2
    bulk = auth_client.post("/api/findings/bulk", json={"module": "vm", "scope_id": 0, "filter": query,
                                                       "change": {"status": "in_work"}})
    assert bulk.status_code == 202, bulk.text
    assert auth_client.get(f"/api/vm/jobs/{bulk.json()['job_id']}").json()["processed"] == 1


def test_overview_without_high_risk(auth_client: TestClient, db_session: Any) -> None:
    host = VmHost(hostname="desk")
    cve = VmCve(cve_id="CVE-2026-1234")
    db_session.add_all([host, cve])
    db_session.flush()
    db_session.add(VmHostCve(host_id=host.id, cve_id=cve.cve_id, risk=79))
    db_session.commit()
    assert auth_client.get("/api/vm/overview").json()["pairs"] == 1
    ov = auth_client.get("/api/vm/overview?hide_medium_low=true").json()
    assert (ov["pairs_all"], ov["pairs"], ov["hosts"], ov["cves"], ov["kev_pairs"], ov["above_threshold"]) == (0,) * 6
    assert ov["top_hosts"] == ov["top_cves"] == [] and not any(ov["distribution"].values())
