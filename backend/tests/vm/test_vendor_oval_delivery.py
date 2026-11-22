"""The downloadable offline kit and the VM settings install the same vendor inputs."""

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from api.modules.vm.core.vendor_oval_archive import ASTRA_META, ASTRA_TARGETS, FEEDS, MANIFEST
from api.modules.vm.services import vendor_bulletins


def xml(profile, stamp="2026-05-01T00:00:00Z"):
    vendor, version = profile.split("-")
    title = "The OVAL Astra Linux" if vendor == "astra" else "RED OS security oval"
    platform = "Astra Linux " + version if vendor == "astra" else "RED OS " + ("8.0" if version == "8" else version)
    return f"""<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
        xmlns:g="http://oval.mitre.org/XMLSchema/oval-common-5"><generator><g:product_name>{title}</g:product_name>
        <g:timestamp>{stamp}</g:timestamp></generator>
        <definitions><definition class="vulnerability" id="oval:{vendor}:def:1"><metadata>
        <affected family="unix"><platform>{platform}</platform></affected>
        </metadata></definition></definitions></oval_definitions>""".encode()


class Sources:
    def __init__(self, **_):
        self.files = {key: xml(key) for key in FEEDS}
        self.calls = []
        self.bad_hash = False

    def fetch(self, url, *args):
        assert url == ASTRA_META
        targets = [{"target": f"{v}_{arch}", "url": FEEDS["astra-" + v],
                    "sha256sum": "0" * 64 if self.bad_hash else hashlib.sha256(self.files["astra-" + v]).hexdigest()}
                   for v, arch in ASTRA_TARGETS.items()]
        return json.dumps({"platforms": [{"targets": targets}]}).encode()

    def download(self, url, target, *, limit, **_):
        key = next(k for k, v in FEEDS.items() if v == url)
        self.calls.append(key)
        assert len(self.files[key]) < limit
        target.write_bytes(self.files[key])


def pack(tmp_path, sources):
    from api.modules.vm.core.vendor_oval_archive import download_archive

    path = tmp_path / "oval-full.zip"
    download_archive(path, tmp_path / "cache", sources, lambda _: None)
    return path


def test_kit_catalog_is_atomic_and_independent_of_trivy(tmp_path, monkeypatch):
    kit = Path(__file__).resolve().parents[3] / "frontend/public/offline"
    monkeypatch.syspath_prepend(str(kit))
    import offline_download
    import offline_sources

    data = tmp_path / "airgap"
    trivy = data / "trivy" / "db" / "trivy.db"
    trivy.parent.mkdir(parents=True)
    trivy.write_bytes(b"current Trivy")
    monkeypatch.setattr(vendor_bulletins, "_BUNDLED", tmp_path / "absent")
    sources = Sources()
    monkeypatch.setattr(offline_sources, "Transport", lambda **_: sources)
    assert vendor_bulletins.vendor_revision(data) == ""
    assert offline_download.main(["--datasets", "oval", "--mode", "full", "--output", str(tmp_path), "--quiet"]) == 0
    archive, = tmp_path.glob("stools-*/oval-full.zip")
    assert vendor_bulletins.install(archive, data)["profiles_updated"] == len(FEEDS)
    original = vendor_bulletins.vendor_revision(data)
    assert original and vendor_bulletins.load_index(data, "astra-1.7").profile == "astra-1.7"
    assert vendor_bulletins.load_index(data, "unsupported") is None
    assert vendor_bulletins.install(archive, data)["duplicate"]
    assert vendor_bulletins.vendor_revision(data) == original

    sources.files["redos-8"] = xml("redos-8", "2026-05-02T00:00:00Z")
    newer = pack(tmp_path, sources)
    assert vendor_bulletins.install(newer, data)["profiles_updated"] == 1
    latest = vendor_bulletins.vendor_revision(data)
    assert latest != original
    assert vendor_bulletins.install(archive, data)["duplicate"]
    assert vendor_bulletins.vendor_revision(data) == latest
    repacked = tmp_path / "wrong.zip"
    with zipfile.ZipFile(newer) as src, zipfile.ZipFile(repacked, "w") as dest:
        for name in src.namelist():
            dest.writestr(name, src.read("astra-1.8.xml" if name == "astra-1.7.xml" else name))
    with pytest.raises(ValueError):
        vendor_bulletins.install(repacked, data)
    assert vendor_bulletins.vendor_revision(data) == latest and trivy.read_bytes() == b"current Trivy"


def test_official_hash_branch_and_doctype_fail_closed(tmp_path):
    sources = Sources()
    pack(tmp_path, sources)
    sources.calls.clear()
    original = pack(tmp_path, sources).read_bytes()
    assert set(sources.calls) == {"redos-7.3", "redos-8"}  # Unchanged, hashed Astra XML is cached.
    sources.bad_hash = True
    with pytest.raises(ValueError, match="SHA-256"):
        pack(tmp_path, sources)
    sources.bad_hash = False
    for wrong in (xml("redos-7.3"), b"<!DOCTYPE oval_definitions>" + xml("redos-8")):
        sources.files["redos-8"] = wrong
        with pytest.raises(ValueError, match="OVAL redos-8"):
            pack(tmp_path, sources)
    with zipfile.ZipFile(tmp_path / "oval-full.zip") as valid:
        assert MANIFEST in valid.namelist() and valid.read("redos-8.xml") == xml("redos-8")
    assert (tmp_path / "oval-full.zip").read_bytes() == original


def test_vm_card_accepts_and_reports_offline_catalog(auth_client, client_as, tmp_path, monkeypatch):
    monkeypatch.setattr(vendor_bulletins, "_BUNDLED", tmp_path / "absent")
    path = pack(tmp_path, Sources())
    url = "/api/vm/refs/oval/upload"
    assert client_as("auditor").post(url, files={"files": ("oval.zip", b"test")}).status_code == 403
    response = auth_client.post(url, files={"files": ("oval.zip", path.read_bytes(), "application/zip")})
    assert response.status_code == 202
    assert auth_client.get(f"/api/vm/jobs/{response.json()['job_id']}").json()["status"] == "done"
    card = next(item for item in auth_client.get("/api/vm/refs").json() if item["name"] == "oval")
    assert card["source"] == "bundle" and "astra-4.7" in card["detail"]
    assert card["loaded_at"].startswith("2026-05-01") and not card["pending_rebuild"]


def test_network_refresh_and_offline_batch_use_one_catalog(auth_client, db_session, app_settings, tmp_path, monkeypatch):
    import httpx

    from api.modules.vm.routers import refs as router
    from api.modules.vm.services import refs
    from tests.vm.test_archive_batches import URL, run, upload

    monkeypatch.setattr(vendor_bulletins, "_BUNDLED", tmp_path / "absent")
    sources = Sources()
    def registry(req):
        url = str(req.url)
        body = sources.fetch(url) if url == ASTRA_META else sources.files[next(key for key in FEEDS if FEEDS[key] == url)]
        return httpx.Response(200, content=body)
    def download(db, handle, name, weights, years, mode):
        refs.run_ref_download(db, handle, name, weights, years, mode=mode,
                              http_factory=lambda: httpx.Client(transport=httpx.MockTransport(registry)))
    monkeypatch.setattr(router, "run_ref_download", download)
    response = auth_client.post("/api/vm/refs/oval/download", json={"mode": "auto"})
    assert response.status_code == 202
    assert auth_client.get(f"/api/vm/jobs/{response.json()['job_id']}").json()["status"] == "done"
    card = next(item for item in auth_client.get("/api/vm/refs").json() if item["name"] == "oval")
    assert card["source"] == "network" and card["last_checked_at"]
    revision = vendor_bulletins.vendor_revision(app_settings.data_dir)
    assert upload(auth_client, ("offline.zip", pack(tmp_path, sources).read_bytes())).status_code == 202
    run(db_session, monkeypatch)
    job = auth_client.get(URL).json()["items"][0]
    assert job["status"] == "done" and job["rebuild"] == "not_needed"
    assert job["files"][0]["kind"] == "oval" and job["files"][0]["duplicate"]
    assert vendor_bulletins.vendor_revision(app_settings.data_dir) == revision


def test_bundled_release_indexes_are_readable_offline(tmp_path, monkeypatch):
    seed = Path(__file__).resolve().parents[2] / "docker/vendor-oval/catalog.oval"
    monkeypatch.setattr(vendor_bulletins, "_BUNDLED", seed)
    assert vendor_bulletins.vendor_revision(tmp_path)
    for profile in FEEDS:
        assert vendor_bulletins.load_index(tmp_path, profile).profile == profile
    assert vendor_bulletins.catalog_status(tmp_path)["source"] == "bundled"
