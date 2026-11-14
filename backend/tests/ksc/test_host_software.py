"""AV host CVEs: coverage is not safety, and snapshot/host identities never leak."""
import datetime as dt

import pytest
from sqlalchemy import select

from api.modules.ksc.models import KscHost, KscServer
from api.modules.ksc.software_models import KscSoftware
from api.modules.vm.models import VmRefNvd
from tests.vm.test_ksc_software import entry, seed, snapshot, store


def host(db, server, data, days=0):
    snap = snapshot(db, server, dt.datetime.now(dt.UTC) + dt.timedelta(days=days))
    db.add(KscHost(snapshot_id=snap.id, host_id="same-guid", name="test-host"))
    store(db, snap, data)
    return f"/api/ksc/snapshots/{snap.id}/hosts/same-guid/software"


def test_host_coverage_cves_and_filtered_inventory(db_session, client_as):
    db = db_session
    server = seed(db)
    data = entry()
    data["items"] += [entry("2.0")["items"][0], entry("")["items"][0],
                      {"DisplayName": "Unlisted", "Publisher": "Example", "DisplayVersion": "1.0"}]
    url = host(db, server, data)
    av = client_as({"ksc": "read"})
    response = av.get(url)
    assert response.status_code == 200
    result = response.json()
    assert result["coverage"] == {"total": 4, "checked": 2, "unrecognized": 1, "missing_version": 1, "pending": 0, "uncertain": 0}
    checked = next(x for x in result["software"]["items"] if x["version"] == "1.9")
    assert checked["product_id"] == "widget" and checked["installed_on"] == "2026-10-01"
    assert result["vulnerabilities"]["total"] == 2  # one affected and one candidate with no version
    assert result["finding_counts"] == {"affected": 1, "unknown": 1}
    affected = next(x for x in result["vulnerabilities"]["items"] if x["state"] == "affected")
    assert affected["cve_id"] == "CVE-2026-12345" and affected["version"] == "1.9"
    assert affected["reason"] and affected["checked_at"] and affected["cvss"] == 8.8
    filtered = av.get(url, params={"coverage": "missing_version", "q": "Widget"}).json()
    assert filtered["software"]["total"] == 1 and filtered["software"]["items"][0]["version"] == ""
    assert filtered["coverage"] == result["coverage"]
    assert av.get(url, params={"coverage": "unrecognized"}).json()["software"]["items"][0]["name"] == "Unlisted"
    assert av.get(url, params={"q": "%"}).json()["software"]["total"] == 0
    assert av.get(url, params={"state": "affected"}).json()["vulnerabilities"]["total"] == 1
    pages = [av.get(url, params={"limit": 1, "software_offset": n}).json()["software"]["items"][0]["id"] for n in range(4)]
    assert len(set(pages)) == 4
    a = av.get(url, params={"limit": 1}).json()["vulnerabilities"]["items"][0]["id"]
    b = av.get(url, params={"limit": 1, "vuln_offset": 1}).json()["vulnerabilities"]["items"][0]["id"]
    assert a != b


def test_host_software_scope_permissions_and_validation(db_session, client_as):
    db = db_session; server = seed(db)
    old = host(db, server, entry())
    new = host(db, server, entry("2.0"), 1)
    other = KscServer(name="other"); db.add(other); db.flush()
    other_url = host(db, other, entry("2.0"))
    av = client_as({"ksc": "read"})
    assert av.get(old).json()["finding_counts"]["affected"] == 1
    for url in (new, other_url):
        assert av.get(url).json()["vulnerabilities"]["total"] == 0
    assert av.get(old.replace("same-guid", "absent")).status_code == 404
    assert av.get("/api/ksc/snapshots/999999/hosts/same-guid/software").status_code == 404
    for params in ({"limit": 101}, {"software_offset": -1}, {"coverage": "bad"}, {"state": "bad"}):
        assert av.get(old, params=params).status_code == 422
    assert client_as({"vm": "read"}).get(old).status_code == 403
    assert client_as({"assets": "read"}).get(old).status_code == 403


@pytest.mark.parametrize("data,status", [(None, "not_collected"), ({"status": "complete", "items": []}, "complete"),
                                          ({"status": "error", "error": "inventory unavailable"}, "error")])
def test_host_inventory_missing_empty_failed(db_session, client_as, data, status):
    url = host(db_session, seed(db_session), data)
    result = client_as({"ksc": "read"}).get(url).json()
    assert result["inventory_status"] == status
    assert result["coverage"]["total"] == 0
    if status == "error":
        assert result["inventory_error"] == "inventory unavailable"


def test_missing_nvd_and_uncertain_conditions_are_not_unrecognized(db_session, client_as):
    db = db_session; server = seed(db)
    url = host(db, server, entry())
    software = db.scalar(select(KscSoftware))
    software.assessment = "unknown"; db.commit()
    av = client_as({"ksc": "read"})
    assert av.get(url).json()["coverage"]["uncertain"] == 1
    nvd = db.scalar(select(VmRefNvd)); nvd.applicability_loaded = False; db.commit()
    result = av.get(url).json()
    assert not result["nvd_ready"]
    assert result["coverage"]["pending"] == 1 and result["coverage"]["unrecognized"] == 0


def test_blank_version_and_inventory_absent_are_not_success(db_session, client_as):
    from api.modules.ksc.software_models import KscSoftwareInventory
    db = db_session; server = seed(db)
    url = host(db, server, entry(" \t\r\n"))
    av = client_as({"ksc": "read"})
    assert av.get(url).json()["coverage"]["missing_version"] == 1
    software = db.scalar(select(KscSoftware))
    software.version = "1.0"; software.assessment = "pending"; db.commit()
    assert av.get(url).json()["coverage"]["pending"] == 1
    db.delete(db.scalar(select(KscSoftwareInventory))); db.commit()
    result = av.get(url).json()
    assert result["inventory_status"] == "not_collected"
    assert result["coverage"]["total"] == 0 and result["vulnerabilities"]["total"] == 0
