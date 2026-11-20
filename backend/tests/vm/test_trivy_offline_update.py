"""An archive produced outside STools can replace the host scanner DB without network."""

import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from api.modules.vm.core.trivy_db_archive import LAYER, LAYER_TYPE, MANIFEST


def layer(version="2026-03-01T00:00:00Z", database=b"sample-database", extra=()):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        entries = [("metadata.json", json.dumps({"Version": 2, "UpdatedAt": version}).encode()),
                   ("trivy.db", database), *extra]
        for name, data in entries:
            item = tarfile.TarInfo(name)
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
    return output.getvalue()


def upstream(blob, digest=None):
    return json.dumps({"schemaVersion": 2, "layers": [{"mediaType": LAYER_TYPE, "size": len(blob),
                       "digest": "sha256:" + (digest or hashlib.sha256(blob).hexdigest())}]}).encode()


def envelope(path, blob, digest=None):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(MANIFEST, upstream(blob, digest))
        archive.writestr(LAYER, blob)
    return path


def test_kit_produces_importable_snapshot_and_reuses_verified_layer(tmp_path, monkeypatch):
    from api.modules.vm.services import trivy_update
    kit = Path(__file__).resolve().parents[3] / "frontend/public/offline"
    monkeypatch.syspath_prepend(str(kit))
    import offline_download
    import offline_sources

    blob = layer()
    requests = []
    class Transport:
        def __init__(self, **kwargs): pass

        def download(self, url, target, *, limit, **kwargs):
            requests.append(url)
            data = upstream(blob) if url.endswith("/manifests/2") else blob
            assert len(data) <= limit
            target.write_bytes(data)

    monkeypatch.setattr(offline_sources, "Transport", Transport)
    monkeypatch.setattr(trivy_update, "validate_database", lambda cache: None)
    monkeypatch.setattr(trivy_update.trivy_scan, "_BUNDLED_CACHE", tmp_path / "bundled")
    for mode in ("updates", "full"):
        args = ["--datasets", "trivy", "--mode", mode, "--output", str(tmp_path), "--quiet"]
        if mode == "updates":
            args += ["--period", "7d"]
        assert offline_download.main(args) == 0
        built, = tmp_path.glob("stools-*/trivy-" + mode + ".zip")
        result = trivy_update.install(built, tmp_path / "airgap")
        assert result["duplicate"] == (mode == "full")
    assert sum("/blobs/" in url for url in requests) == 1


def test_invalid_stale_and_duplicate_leave_installed_db_usable(tmp_path, monkeypatch):
    from api.modules.vm.services import trivy_update
    installed = tmp_path / "data"
    monkeypatch.setattr(trivy_update.trivy_scan, "_BUNDLED_CACHE", tmp_path / "bundled")
    checked = []
    def validate(cache):
        checked.append(cache)
        if (cache / "db/trivy.db").read_bytes() == b"broken":
            raise ValueError("scanner rejected DB")
    monkeypatch.setattr(trivy_update, "validate_database", validate)
    good = envelope(tmp_path / "good.zip", layer())
    assert trivy_update.install(good, installed)["duplicate"] is False
    assert trivy_update.install(good, installed)["duplicate"] is True
    active = trivy_update.trivy_scan.cache_path(installed)
    assert (active / "db/trivy.db").read_bytes() == b"sample-database"
    for invalid in [
        envelope(tmp_path / "stale.zip", layer("2025-01-01T00:00:00Z")),
        envelope(tmp_path / "digest.zip", layer(), "0"*64),
        envelope(tmp_path / "unsafe.zip", layer(extra=[("../outside", b"bad")])),
        envelope(tmp_path / "conflict.zip", layer(database=b"different")),
        envelope(tmp_path / "broken.zip", layer("2026-04-01T00:00:00Z", b"broken")),
    ]:
        with pytest.raises(ValueError):
            trivy_update.install(invalid, installed)
        assert trivy_update.trivy_scan.cache_path(installed) == active
    newer = envelope(tmp_path / "new.zip", layer("2026-04-01T00:00:00Z", b"new-data"))
    assert trivy_update.install(newer, installed)["duplicate"] is False
    assert (trivy_update.trivy_scan.cache_path(installed) / "db/trivy.db").read_bytes() == b"new-data"
    assert not (tmp_path / "outside").exists()


def test_batch_imports_trivy_without_rebuilding_vm_scores(auth_client, db_session, monkeypatch, app_settings, tmp_path):
    from api.modules.vm.services import trivy_update
    from tests.vm.test_archive_batches import URL, run, upload
    monkeypatch.setattr(trivy_update, "validate_database", lambda cache: None)
    monkeypatch.setattr(trivy_update.trivy_scan, "_BUNDLED_CACHE", app_settings.data_dir / "bundled")
    path = envelope(tmp_path / "test.zip", layer())
    assert upload(auth_client, ("arbitrary-name.zip", path.read_bytes())).status_code == 202
    run(db_session, monkeypatch)
    result = auth_client.get(URL).json()["items"][0]
    assert result["status"] == "done" and result["rebuild"] == "not_needed"
    assert result["files"][0]["kind"] == "trivy"
    assert result["files"][0]["db_updated_at"].startswith("2026-03-01")


def test_active_scan_keeps_its_snapshot_until_it_finishes(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from api.modules.vm.services import trivy_scan, trivy_update

    monkeypatch.setattr(trivy_scan, "_BUNDLED_CACHE", tmp_path / "bundled")
    data = tmp_path / "data"
    monkeypatch.setattr(trivy_update, "validate_database", lambda _: None)
    trivy_update.install(envelope(tmp_path / "first.zip", layer()), data)
    second = envelope(tmp_path / "second.zip", layer("2026-04-01T00:00:00Z", b"new"))
    staged = Event()
    monkeypatch.setattr(trivy_update, "validate_database", lambda _: staged.set())
    with ThreadPoolExecutor(max_workers=1) as pool:
        with trivy_scan.locked_cache(data) as old:
            task = pool.submit(trivy_update.install, second, data)
            assert staged.wait(5)
            assert (old / "db/trivy.db").read_bytes() == b"sample-database" and not task.done()
        assert task.result(timeout=5)["duplicate"] is False
    assert not old.exists() and (trivy_scan.cache_path(data) / "db/trivy.db").read_bytes() == b"new"


def test_only_a_new_active_db_requeues_existing_host(db_session, tmp_path, monkeypatch):
    import sys

    from api.modules.assets.models import Asset
    from api.modules.vm.sbom_models import HostSbomScan
    from api.modules.vm.services import host_sbom, trivy_scan, trivy_update

    data = tmp_path / "data"
    monkeypatch.setattr(trivy_scan, "_BUNDLED_CACHE", tmp_path / "bundled")
    monkeypatch.setattr(trivy_scan.shutil, "which", lambda _: sys.executable)
    monkeypatch.setattr(trivy_scan, "_scanner_version", lambda *_: "test")
    monkeypatch.setattr(trivy_update, "validate_database", lambda _: None)
    asset = Asset(name="offline-host")
    db_session.add(asset)
    db_session.commit()
    host_sbom.refresh_queue(db_session, data, asset.id)
    scan = db_session.get(HostSbomScan, asset.id)
    scan.status = "ready"
    db_session.commit()
    original_target = scan.target
    package = envelope(tmp_path / "version.zip", layer())
    trivy_update.install(package, data)
    host_sbom.refresh_queue(db_session, data)
    db_session.refresh(scan)
    assert scan.status == "pending" and scan.target != original_target
    scan.status = "ready"
    db_session.commit()
    stamp = scan.requested_at
    trivy_update.install(package, data)
    host_sbom.refresh_queue(db_session, data)
    db_session.refresh(scan)
    assert scan.status == "ready" and scan.requested_at == stamp


def test_downloader_falls_back_to_ghcr_and_rejects_wrong_bytes(tmp_path, monkeypatch):
    kit = Path(__file__).resolve().parents[3] / "frontend/public/offline"
    monkeypatch.syspath_prepend(str(kit))
    from offline_trivy import REGISTRIES, TOKEN_URL, download_database

    blob = layer()
    class Registry:
        corrupt = False

        def fetch(self, url, *args):
            assert url == TOKEN_URL
            return b'{"token":"test-token"}'

        def download(self, url, target, headers, **kwargs):
            if url.startswith(REGISTRIES[0]):
                assert "Authorization" not in headers
                raise OSError("unavailable")
            assert url.startswith(REGISTRIES[1]) and headers["Authorization"] == "Bearer test-token"
            if url.endswith("/manifests/2"):
                target.write_bytes(upstream(blob))
            else:
                target.write_bytes(b"bad" if self.corrupt else blob)

    source = Registry()
    output = tmp_path / "built.zip"
    assert download_database(output, tmp_path / "cache", source, lambda _: None, "en")["status"] == "ok"
    old_bytes = output.read_bytes()
    source.corrupt = True
    with pytest.raises(ValueError, match="SHA-256"):
        download_database(output, tmp_path / "other-cache", source, lambda _: None, "en")
    assert output.read_bytes() == old_bytes


def trivy_card(client):
    response = client.get("/api/vm/refs")
    assert response.status_code == 200
    return next(row for row in response.json() if row["name"] == "trivy")


def test_trivy_card_reads_active_database_and_imports_one_zip(
    auth_client, app_settings, tmp_path, monkeypatch,
):
    from api.modules.vm.services import trivy_scan, trivy_update

    bundled = tmp_path / "bundled"
    monkeypatch.setattr(trivy_scan, "_BUNDLED_CACHE", bundled)
    monkeypatch.setattr(trivy_update, "validate_database", lambda cache: None)
    assert trivy_card(auth_client)["loaded_at"] is None
    (bundled / "db").mkdir(parents=True)
    (bundled / "db/metadata.json").write_text('{"Version":2,"UpdatedAt":"2026-02-01T00:00:00Z"}')
    (bundled / "db/trivy.db").write_bytes(b"bundled")
    row = trivy_card(auth_client)
    assert row["source"] == "bundled" and row["loaded_at"].startswith("2026-02-01")
    assert row["records"] is None and row["update_available"]
    data = envelope(tmp_path / "trivy-updates.zip", layer()).read_bytes()
    url = "/api/vm/refs/trivy/upload"
    files = [("files", ("db.zip", data, "application/zip"))]
    assert auth_client.post(url, files=files * 2).status_code == 422
    submitted = auth_client.post(url, files=files)
    assert submitted.status_code == 202
    job = auth_client.get(f"/api/vm/jobs/{submitted.json()['job_id']}").json()
    assert job["status"] == "done", job
    row = trivy_card(auth_client)
    assert row["source"] == "bundle" and row["loaded_at"].startswith("2026-03-01")
    assert not row["pending_rebuild"]
    bad = auth_client.post(url, files={"files": ("wrong.zip", b"invalid", "application/zip")})
    assert bad.status_code == 202
    assert auth_client.get(f"/api/vm/jobs/{bad.json()['job_id']}").json()["status"] == "failed"
    row = trivy_card(auth_client)
    assert row["loaded_at"].startswith("2026-03-01") and row["last_error"]


def test_trivy_network_modes_check_digest_and_use_verified_snapshots(auth_client, db_session, app_settings, tmp_path, monkeypatch):
    import httpx

    from api.modules.vm.routers import refs as router
    from api.modules.vm.services import refs, trivy_update

    blob = layer()
    calls = []
    def registry(request):
        calls.append(request.url.path)
        return httpx.Response(200, content=upstream(blob) if request.url.path.endswith("/manifests/2") else blob)
    monkeypatch.setattr(trivy_update.trivy_scan, "_BUNDLED_CACHE", tmp_path / "absent")
    monkeypatch.setattr(trivy_update, "validate_database", lambda cache: None)
    def from_test_registry(db, handle, name, weights, years, mode):
        refs.run_ref_download(db, handle, name, weights, years, mode=mode,
                              http_factory=lambda: httpx.Client(transport=httpx.MockTransport(registry)))
    monkeypatch.setattr(router, "run_ref_download", from_test_registry)
    def update(mode):
        response = auth_client.post("/api/vm/refs/trivy/download", json={"mode": mode})
        assert response.status_code == 202
        job = auth_client.get(f"/api/vm/jobs/{response.json()['job_id']}").json()
        assert job["status"] == "done", job

    update("auto")
    assert (trivy_update.trivy_scan.cache_path(app_settings.data_dir) / "db/trivy.db").read_bytes() == b"sample-database"
    update("updates")
    assert sum("/blobs/" in path for path in calls) == 1
    update("full")
    assert sum("/blobs/" in path for path in calls) == 2
    from api.modules.vm.services.refs_view import ref_views
    row = next(row for row in ref_views(db_session) if row.name == "trivy")
    assert row.source == "network" and row.last_checked_at is not None


def test_trivy_card_respects_vm_permissions(client_as):
    client = client_as("auditor")
    assert trivy_card(client)["name"] == "trivy"
    base = "/api/vm/refs/trivy"
    assert client.post(base + "/download", json={"mode": "auto"}).status_code == 403
    assert client.post(base + "/upload", files={"files": ("db.zip", b"test")}).status_code == 403


def test_verified_bundled_database_skips_second_layer_download(db_session, app_settings, tmp_path, monkeypatch):
    import httpx

    from api.modules.vm.services import trivy_reference, trivy_scan, trivy_update

    blob = layer()
    root = tmp_path / "bundled"
    (root / "db").mkdir(parents=True)
    (root / "db/trivy.db").write_bytes(b"sample-database")
    (root / "db/metadata.json").write_text('{"Version":2,"UpdatedAt":"2026-03-01T00:00:00Z"}')
    monkeypatch.setattr(trivy_scan, "_BUNDLED_CACHE", root)
    monkeypatch.setattr(trivy_update, "validate_database", lambda cache: None)
    requests = []
    def registry(req):
        requests.append(req.url.path)
        return httpx.Response(200, content=upstream(blob) if req.url.path.endswith("/manifests/2") else blob)
    from unittest.mock import Mock
    handle = Mock()
    handle.cancelled.return_value = False
    for _ in range(2):
        trivy_reference.download(db_session, handle, "auto", lambda: httpx.Client(transport=httpx.MockTransport(registry)))
    assert sum("/blobs/" in path for path in requests) == 1
    assert trivy_reference.active_database(app_settings.data_dir).source == "bundled"


def test_trivy_card_only_conflicts_with_its_own_job(auth_client, db_session, app_settings, tmp_path, monkeypatch):
    from api.modules.vm.services import trivy_scan, trivy_update
    from api.modules.vm.services.jobs import start_job

    monkeypatch.setattr(trivy_scan, "_BUNDLED_CACHE", tmp_path / "empty")
    monkeypatch.setattr(trivy_update, "validate_database", lambda cache: None)
    start_job(db_session, "recalculate", "test")
    data = envelope(tmp_path / "update.zip", layer()).read_bytes()
    response = auth_client.post("/api/vm/refs/trivy/upload", files={"files": ("trivy.zip", data)})
    assert response.status_code == 202
    assert auth_client.get(f"/api/vm/jobs/{response.json()['job_id']}").json()["status"] == "done"
    job = start_job(db_session, "ref_trivy", "test")
    assert trivy_card(auth_client)["active_job_id"] == job
    assert auth_client.post("/api/vm/refs/trivy/download", json={"mode":"full"}).status_code == 409
