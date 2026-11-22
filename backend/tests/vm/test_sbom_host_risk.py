import datetime as dt

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from sqlalchemy.sql import text

from api.modules.assets.models import Asset, AssetObservation
from api.modules.vm.models import VmCve, VmHost, VmHostCve, VmRefKev, VmRefNvd
from api.modules.vm.sbom_models import VmSbomConfirmedCve
from api.modules.vm.services.sbom_risk import lock_inventory_links, publish_confirmed
from api.modules.vm.services.scoring import drop_orphan_cves


def _asset(db):
    asset = Asset(name="rpm-server", criticality="High", os="Альт")
    db.add(asset)
    db.flush()
    obs = AssetObservation(asset_id=asset.id, source="ksc", source_key="1:server",
                           seen_at=dt.datetime.now(dt.UTC))
    db.add(obs)
    db.commit()
    return asset, obs


def _finding(identifier, assessment="vendor_confirmed", bulletin="oval:vendor:def:123"):
    return {"vuln_id": identifier, "assessment": assessment, "bulletin": bulletin}


def test_only_vendor_confirmed_cves_enter_the_live_queue_and_host_risk(auth_client, db_session):
    db = db_session
    asset, obs = _asset(db)
    confirmed = "CVE-2024-10001"
    db.add_all([VmRefNvd(cve_id=confirmed, year=2024, cvss_v3=9.8, v3_av="NETWORK"),
                VmRefKev(cve_id=confirmed)])
    db.commit()
    assert auth_client.get("/api/vm/vulns").json()["total"] == 0
    findings = [_finding(confirmed), _finding(confirmed.lower()),
                _finding("CVE-2024-10002", "candidate"), _finding("CVE-2024-10003", bulletin=" "),
                _finding("CVE-2024-10004", "unassessed"), _finding("oval:vendor:def:123"),
                {"vuln_id": "CVE-2024-10005"}]
    publish_confirmed(db, asset.id, findings)
    db.commit()
    # The next MaxPatrol/Harbor maintenance cycle must keep a CVE held only by this asset.
    drop_orphan_cves(db)
    page = auth_client.get("/api/vm/vulns").json()
    assert page["total"] == 1
    item, = page["items"]
    assert (item["hostname"], item["host_id"], item["cve_id"]) == ("rpm-server", -asset.id, confirmed)
    assert item["sbom_asset_id"] == asset.id
    assert item["risk"] >= 85
    linked = auth_client.get("/api/vm/vulns", params={"q": f"asset:{asset.id}", "cve": confirmed}).json()
    assert [i["key"] for i in linked["items"]] == [item["key"]]
    assert auth_client.get(f"/api/vm/vulns/{item['host_id']}/{confirmed}").json()["cve"]["kev"]
    assert auth_client.get("/api/vm/overview").json()["top_hosts"][0]["risk_max"] == item["risk"]
    links = auth_client.get(f"/api/assets/assets/{asset.id}").json()["links"]
    assert (links["vm_host_id"], links["vm_cve_count"], links["vm_max_risk"]) == (-asset.id, 1, item["risk"])
    assert db.scalar(select(func.count()).select_from(VmHostCve)) == 0
    assert db.scalar(select(func.count()).select_from(VmHost)) == 0
    obs.gone_at = dt.datetime.now(dt.UTC)
    db.commit()
    assert auth_client.get("/api/vm/vulns").json()["total"] == 0
    assert not auth_client.get("/api/vm/overview").json()["top_hosts"]


def test_source_overlap_reimport_and_withdrawal_preserve_independent_findings(auth_client, db_session):
    db = db_session
    asset, _ = _asset(db)
    raw, common, vendor = ("CVE-2024-12301", "CVE-2024-12302", "CVE-2024-12303")
    host = VmHost(hostname="maxpatrol-name", ip="192.0.2.1")
    db.add_all([host, VmCve(cve_id=raw), VmCve(cve_id=common)])
    db.flush()
    db.add_all([VmHostCve(host_id=host.id, cve_id=vid, risk=32) for vid in (raw, common)])
    db.add(AssetObservation(asset_id=asset.id, source="vm", source_key="maxpatrol-name|192.0.2.1",
                            seen_at=dt.datetime.now(dt.UTC)))
    db.commit()
    publish_confirmed(db, asset.id, [_finding(common), _finding(vendor)])
    db.commit()
    page = auth_client.get(f"/api/vm/vulns?host_id={host.id}").json()
    assert page["total"] == 3 and {i["cve_id"] for i in page["items"]} == {raw, common, vendor}
    assert auth_client.get(f"/api/vm/vulns?asset_id={asset.id}&status=all").json()["total"] == 3
    # A replacement import changes host IDs and can stop reporting a CVE independently.
    db.execute(delete(VmHost).where(VmHost.id == host.id))
    replacement = VmHost(hostname="maxpatrol-name", ip="192.0.2.1")
    db.add(replacement)
    db.flush()
    db.add(VmHostCve(host_id=replacement.id, cve_id=raw, risk=32))
    db.commit()
    page = auth_client.get(f"/api/vm/vulns?host_id={replacement.id}").json()
    assert page["total"] == 3 and {i["cve_id"] for i in page["items"]} == {raw, common, vendor}
    publish_confirmed(db, asset.id, [])
    db.commit()
    page = auth_client.get("/api/vm/vulns").json()
    assert page["total"] == 1 and [i["cve_id"] for i in page["items"]] == [raw]


def test_final_publication_and_detach_cannot_cross(db_session):
    db = db_session
    asset, obs = _asset(db)
    moved_to = Asset(name="replacement")
    db.add(moved_to)
    db.commit()
    lock_inventory_links(db, asset.id)
    publish_confirmed(db, asset.id, [_finding("CVE-2024-14000")])
    with Session(db.get_bind()) as other:
        assert other.scalar(select(func.count()).select_from(VmSbomConfirmedCve)) == 0
        other.execute(text("SET LOCAL lock_timeout = '100ms'"))
        with pytest.raises(OperationalError) as exc:
            other.execute(text("UPDATE asset_observation SET asset_id = :new WHERE id = :id"),
                          {"new": moved_to.id, "id": obs.id})
        assert exc.value.orig.sqlstate == "55P03"
        other.rollback()
        db.commit()
        assert other.scalar(select(func.count()).select_from(VmSbomConfirmedCve)) == 1
        other.execute(text("UPDATE asset_observation SET asset_id = :new WHERE id = :id"),
                      {"new": moved_to.id, "id": obs.id})
        other.commit()
    assert db.scalar(select(func.count()).select_from(VmSbomConfirmedCve)) == 0


def test_asset_detail_and_queue_use_all_exact_links_before_dedup(auth_client, db_session):
    db = db_session
    asset, _ = _asset(db)
    primary, alias, unrelated = [VmHost(hostname=name, ip="192.0.2.9") for name in ("a", "b", "other")]
    cve = "CVE-2024-15000"
    db.add_all([primary, alias, unrelated, VmCve(cve_id=cve)])
    db.flush()
    for host in (primary, alias):
        db.add(AssetObservation(asset_id=asset.id, source="vm", source_key=f"{host.hostname}|{host.ip}",
                                seen_at=dt.datetime.now(dt.UTC)))
    db.add_all([VmHostCve(host_id=alias.id, cve_id=cve, risk=51),
                VmHostCve(host_id=unrelated.id, cve_id=cve, risk=99)])
    db.commit()
    publish_confirmed(db, asset.id, [_finding(cve)])
    db.commit()
    links = auth_client.get(f"/api/assets/assets/{asset.id}").json()["links"]
    assert (links["vm_cve_count"], links["vm_max_risk"]) == (1, 51)
    page = auth_client.get(f"/api/vm/vulns?asset_id={asset.id}&status=all").json()
    assert page["total"] == 1 and [(i["host_id"], i["risk"]) for i in page["items"]] == [(alias.id, 51)]
