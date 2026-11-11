"""KSC inventory persistence, NVD refresh, scoped read API."""
import datetime as dt
import json
from types import SimpleNamespace

from sqlalchemy import select

from api.modules.ksc.models import KscServer, KscSnapshot
from api.modules.vm.core.refs import nvd_record

CONFIG = [{"nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": True,
    "criteria": "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0"}]}]}]


def test_nvd_retains_applicability_and_rejected_cve_is_not_indexed():
    rec = nvd_record({"id": "CVE-2026-12345", "configurations": CONFIG})
    assert rec.configurations == CONFIG
    rejected = nvd_record({"id": "CVE-2026-12345", "vulnStatus": "Rejected", "configurations": CONFIG})
    assert rejected.configurations == []


def snapshot(db, server, when):
    s = KscSnapshot(server_id=server.id, collected_at=when, source="file")
    db.add(s); db.flush()
    return s


def store(db, snap, entry):
    from api.modules.ksc.services.software import store_inventory
    idx = SimpleNamespace(hosts=[SimpleNamespace(host_id="same-guid", name="test-host", os="Windows 11")],
                          export=SimpleNamespace(host_inventory={} if entry is None else {"same-guid": entry}))
    store_inventory(db, snap, idx)
    db.commit()


def entry(version="1.9"):
    return {"status": "complete", "items": [{"ProductID": "widget", "DisplayName": "Widget",
        "Publisher": "Example", "DisplayVersion": version, "InstallDate": "20261001"}]}


def seed(db):
    from api.modules.vm.models import VmRefNvd
    from api.modules.vm.software_models import VmNvdProduct
    db.add(VmRefNvd(cve_id="CVE-2026-12345", year=2026, cvss_v3=8.8, applicability_loaded=True, configurations_json=json.dumps(CONFIG)))
    db.flush()
    db.add(VmNvdProduct(cve_id="CVE-2026-12345", vendor="example", product="widget"))
    server = KscServer(name="inventory-test")
    db.add(server); db.flush()
    return server


def test_store_matches_version_and_latest_snapshot_hides_old_results(db_session, client_as):
    from api.modules.assets.models import Asset, AssetObservation
    from api.modules.ksc.software_models import KscSoftware
    db = db_session; server = seed(db); now = dt.datetime.now(dt.UTC)
    asset = Asset(name="test-host"); db.add(asset); db.flush()
    db.add(AssetObservation(asset_id=asset.id, source="ksc", source_key=f"{server.id}:same-guid", seen_at=now))
    first = snapshot(db, server, now); store(db, first, entry())
    vm = client_as({"vm": "read"})
    rows = vm.get("/api/vm/ksc-vulns").json()
    assert rows["total"] == 1 and rows["items"][0]["asset_id"] == asset.id
    assert rows["items"][0]["state"] == "affected"
    assets = client_as({"assets": "read"})
    data = assets.get(f"/api/assets/assets/{asset.id}/software").json()
    assert data["total"] == 1 and data["items"][0]["cve_count"] == 1
    assert data["items"][0]["installed_on"] == "2026-10-01"
    assert vm.get(f"/api/assets/assets/{asset.id}/software").status_code == 403
    assert assets.get("/api/vm/ksc-vulns").status_code == 403
    second = snapshot(db, server, now + dt.timedelta(days=1)); store(db, second, entry("2.0"))
    assert vm.get("/api/vm/ksc-vulns").json()["total"] == 0
    assert assets.get(f"/api/assets/assets/{asset.id}/software").json()["items"][0]["version"] == "2.0"
    assert len(db.scalars(select(KscSoftware)).all()) == 2  # historical inventory retained
    third = snapshot(db, server, now + dt.timedelta(days=2)); store(db, third, {"status": "error", "error": "unavailable"})
    data = assets.get(f"/api/assets/assets/{asset.id}/software").json()
    assert data["total"] == 0 and data["inventories"][0]["status"] == "error"
    assert vm.get("/api/vm/ksc-vulns").json()["total"] == 0


def test_old_and_empty_inventory_are_distinct_and_reimport_idempotent(db_session):
    from api.modules.ksc.software_models import KscSoftware, KscSoftwareInventory
    db = db_session; server = seed(db); now = dt.datetime.now(dt.UTC)
    old = snapshot(db, server, now); store(db, old, None)
    assert db.scalar(select(KscSoftwareInventory.status)) == "not_collected"
    store(db, old, {"status": "complete", "items": []})
    assert db.scalar(select(KscSoftwareInventory.status)) == "complete"
    assert db.scalar(select(KscSoftware.id)) is None
    store(db, old, entry()); store(db, old, entry())
    assert len(db.scalars(select(KscSoftware)).all()) == 1


def test_nvd_import_rebuilds_product_index_and_existing_findings(db_session, tmp_path):
    from api.jobs import JobHandle
    from api.modules.vm.models import VmJob
    from api.modules.vm.services.jobs import start_job
    from api.modules.vm.services.refs import load_ref
    from api.modules.vm.software_models import VmKscCve, VmNvdProduct
    db = db_session; server = seed(db)
    snap = snapshot(db, server, dt.datetime.now(dt.UTC)); store(db, snap, entry())
    assert db.scalar(select(VmKscCve.cve_id))
    path = tmp_path / "nvd.json"
    changed = json.loads(json.dumps(CONFIG)); changed[0]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"] = "1.0"
    path.write_text(json.dumps({"vulnerabilities": [{"cve": {"id": "CVE-2026-12345", "configurations": changed}}]}))
    job_id = start_job(db, "ref_nvd", "test")
    handle = JobHandle(db, db.get(VmJob, job_id))
    load_ref(db, handle, "nvd", path, "file")
    assert db.scalar(select(VmNvdProduct.product)) == "widget"
    assert db.scalar(select(VmKscCve.id)) is None


def test_readiness_tracks_legacy_rows_and_empty_applicability(db_session):
    from api.modules.vm.models import VmRefNvd
    from api.modules.vm.services.software import nvd_ready
    db = db_session
    db.add(VmRefNvd(cve_id="CVE-2026-11111", year=2026, applicability_loaded=True))
    db.flush()
    assert nvd_ready(db)  # Valid data can have no application CPEs.
    old = VmRefNvd(cve_id="CVE-2025-11111", year=2025)
    db.add(old); db.flush()
    assert not nvd_ready(db)
    old.applicability_loaded = True; db.flush()
    assert nvd_ready(db)


def test_same_guid_on_two_servers_and_filters(db_session, client_as):
    db = db_session; first = seed(db); now = dt.datetime.now(dt.UTC)
    second = KscServer(name="second-inventory-test"); db.add(second); db.flush()
    store(db, snapshot(db, first, now), entry())
    store(db, snapshot(db, second, now), entry("1.8"))
    client = client_as({"vm": "read"})
    data = client.get("/api/vm/ksc-vulns?limit=1").json()
    assert data["total"] == 2 and len(data["items"]) == 1
    following = client.get("/api/vm/ksc-vulns?limit=1&offset=1").json()
    assert following["items"][0]["server_id"] != data["items"][0]["server_id"]
    assert client.get("/api/vm/ksc-vulns?q=1.8").json()["total"] == 1
    assert client.get("/api/vm/ksc-vulns?q=%25").json()["total"] == 0
    assert client.get("/api/vm/ksc-vulns?state=unknown").json()["total"] == 0
    assert client.get("/api/vm/ksc-vulns?limit=9999").status_code == 422


def test_nvd_failure_rolls_back_previous_batches_and_findings(db_session, tmp_path, monkeypatch):
    import pytest

    from api.jobs import JobHandle
    from api.modules.vm.models import VmJob, VmRefNvd
    from api.modules.vm.services import refs
    from api.modules.vm.services.jobs import start_job
    from api.modules.vm.software_models import VmKscCve
    db = db_session; server = seed(db)
    store(db, snapshot(db, server, dt.datetime.now(dt.UTC)), entry())
    old = db.scalar(select(VmRefNvd.configurations_json))
    job_id = start_job(db, "ref_nvd", "test")
    handle = JobHandle(db, db.get(VmJob, job_id))
    path = tmp_path / "bad.json"; path.write_text("{}")
    def broken_parser(_):
        yield nvd_record({"id": "CVE-2026-12345", "configurations": []})
        raise ValueError("feed interrupted")
    monkeypatch.setattr(refs, "parse_nvd", broken_parser)
    original = refs._batched
    monkeypatch.setattr(refs, "_batched", lambda rows: original(rows, size=1))
    with pytest.raises(ValueError, match="feed interrupted"):
        refs.load_ref(db, handle, "nvd", path, "file")
    db.rollback()
    assert db.scalar(select(VmRefNvd.configurations_json)) == old
    assert db.scalar(select(VmKscCve.cve_id)) == "CVE-2026-12345"


def test_deleting_latest_snapshot_rechecks_promoted_inventory(db_session, tmp_path, monkeypatch):
    from api.modules.ksc.services import snapshots
    from api.modules.ksc.software_models import KscSoftware
    from api.modules.vm.models import VmRefNvd
    from api.modules.vm.services.software import rebuild_ksc
    from api.modules.vm.software_models import VmKscCve
    db = db_session; server = seed(db); now = dt.datetime.now(dt.UTC)
    first = snapshot(db, server, now); store(db, first, entry())
    newest = snapshot(db, server, now + dt.timedelta(days=1)); store(db, newest, entry("2.0"))
    changed = json.loads(json.dumps(CONFIG)); changed[0]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"] = "1.0"
    db.get(VmRefNvd, "CVE-2026-12345").configurations_json = json.dumps(changed)
    rebuild_ksc(db); db.commit()
    monkeypatch.setattr(snapshots, "_recompute_changes", lambda *a, **k: None)
    monkeypatch.setattr(snapshots.FINDINGS_ADAPTER, "reconcile", lambda *a, **k: None)
    snapshots.delete_snapshot(db, newest, tmp_path)
    assert db.scalar(select(KscSoftware.assessment)) == "no_match"
    assert db.scalar(select(VmKscCve.id)) is None
