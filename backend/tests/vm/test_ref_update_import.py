"""Incremental reference imports publish records and source cursors together."""
from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from api.jobs import JobCancelled
from api.modules.vm.ghsa_models import VmRefGhsa, VmRefGhsaAlias, VmRefGhsaPackage
from api.modules.vm.models import VmRefNvd, VmRefState
from tests.vm.test_ghsa_import import ID, OTHER, advisory

BASE = {"cursor": "2025-01-01T00:00:00Z", "years": [2025]}
TARGET = {"cursor": "2025-02-01T00:00:00Z", "years": [2025]}


class Handle:
    def __init__(self, db: Any, *, cancel: bool = False) -> None:
        self.db, self.cancel = db, cancel

    def tick(self, *args: Any, **kwargs: Any) -> None:
        self.db.commit()  # Actual job progress commits must not publish catalog mutations.
        if self.cancel:
            raise JobCancelled()

    def stage(self, *args: Any, **kwargs: Any) -> None:
        self.db.commit()

    def report_progress(self, *args: Any, **kwargs: Any) -> None:
        pass

    def cancelled(self) -> bool:
        return self.cancel


def bundle(tmp_path: Path, entries: list[dict[str, Any]], payloads: dict[str, Any]) -> Path:
    path = tmp_path / "updates.zip"
    encoded = {name: json.dumps(value).encode() for name, value in payloads.items()}
    for entry in entries:
        entry["files"] = [{"path": name, "sha256": hashlib.sha256(encoded[name]).hexdigest()}
                          for name in entry.pop("paths", [])]
        entry.setdefault("deleted_ids", [])
    manifest = {"format": "stools-reference-update", "version": 1,
                "created_at": "2025-02-01T00:00:00Z", "sources": entries}
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as out:
        out.writestr("stools-reference-update.json", json.dumps(manifest))
        for name, data in encoded.items():
            out.writestr(name, data)
    return path


def seed(db: Any, name: str, checkpoint: dict[str, Any]) -> None:
    from api.modules.vm.sync_models import VmRefSyncState
    db.add(VmRefSyncState(name=name, checkpoint=checkpoint))
    db.add(VmRefState(name=name, records=1, detail="baseline"))
    db.commit()


def test_nvd_delta_preserves_same_year_and_replay(tmp_path: Path, db_session: Any) -> None:
    from api.modules.vm.services.ref_updates import apply_update_bundle
    from api.modules.vm.sync_models import VmRefSyncState
    db = db_session
    seed(db, "nvd", BASE)
    db.add_all([VmRefNvd(cve_id="CVE-2025-1000", year=2025, description="old"),
                VmRefNvd(cve_id="CVE-2025-2000", year=2025, description="untouched")])
    db.commit()
    path = bundle(tmp_path, [{"name": "nvd", "mode": "delta", "base": BASE, "target": TARGET,
                              "paths": ["nvd/part-0.json"]}], {
        "nvd/part-0.json": {"vulnerabilities": [{"cve": {"id": "CVE-2025-1000", "descriptions": [
            {"lang": "en", "value": "changed"}], "configurations": []}}]}})
    assert apply_update_bundle(db, Handle(db), path) == {"nvd"}
    assert db.get(VmRefNvd, "CVE-2025-1000").description == "changed"
    assert db.get(VmRefNvd, "CVE-2025-2000").description == "untouched"
    assert db.get(VmRefSyncState, "nvd").checkpoint == TARGET
    loaded = db.get(VmRefState, "nvd").loaded_at
    assert apply_update_bundle(db, Handle(db), path) == set()
    assert db.get(VmRefState, "nvd").loaded_at == loaded


def test_ghsa_delta_replaces_children_and_deletes_explicit_ids(tmp_path: Path, db_session: Any) -> None:
    from api.modules.vm.services.ref_updates import apply_update_bundle
    from api.modules.vm.sync_models import VmRefSyncState
    db = db_session
    base, target = {"revision": "a" * 40}, {"revision": "b" * 40}
    seed(db, "ghsa", base)
    db.add_all([VmRefGhsa(ghsa_id=ID), VmRefGhsa(ghsa_id=OTHER)])
    db.flush()
    db.add(VmRefGhsaAlias(ghsa_id=ID, alias="CVE-2025-9999"))
    db.add(VmRefGhsaPackage(ghsa_id=ID, position=0, ecosystem="PyPI", name="old"))
    db.commit()
    name = f"advisories/unreviewed/2025/01/{ID}/{ID}.json"
    path = bundle(tmp_path, [{"name": "ghsa", "mode": "delta", "base": base, "target": target,
                              "paths": [name], "deleted_ids": [OTHER]}], {name: advisory()})
    assert apply_update_bundle(db, Handle(db), path) == {"ghsa"}
    assert db.get(VmRefGhsa, OTHER) is None
    assert not db.get(VmRefGhsa, ID).reviewed
    assert list(db.scalars(select(VmRefGhsaAlias.alias))) == ["CVE-2025-1234"]
    assert db.scalar(select(VmRefGhsaPackage.name)) == "example"
    assert db.get(VmRefSyncState, "ghsa").checkpoint == target


@pytest.mark.parametrize("failure", ["stale", "cancel", "bad_second_source"])
def test_failed_bundle_preserves_rows_and_cursor(tmp_path: Path, db_session: Any, failure: str) -> None:
    from api.modules.vm.services.ref_updates import apply_update_bundle
    from api.modules.vm.sync_models import VmRefSyncState
    db = db_session
    seed(db, "nvd", BASE)
    db.add(VmRefNvd(cve_id="CVE-2025-1000", year=2025, description="old"))
    db.commit()
    entry = {"name": "nvd", "mode": "delta", "base": BASE, "target": TARGET,
             "paths": ["nvd/part.json"]}
    if failure == "stale":
        entry["base"] = {**BASE, "cursor": "2024-01-01T00:00:00Z"}
    entries = [entry]
    payloads = {"nvd/part.json": {"vulnerabilities": [{"cve": {"id": "CVE-2025-1000"}}]}}
    if failure == "bad_second_source":
        base, target = {"revision": "a" * 40}, {"revision": "b" * 40}
        seed(db, "ghsa", base)
        name = f"advisories/github-reviewed/2025/01/{ID}/{ID}.json"
        entries.append({"name": "ghsa", "mode": "delta", "base": base, "target": target, "paths": [name]})
        payloads[name] = {"id": "bad"}
    path = bundle(tmp_path, entries, payloads)
    with pytest.raises((ValueError, JobCancelled)):
        apply_update_bundle(db, Handle(db, cancel=failure == "cancel"), path)
    db.expire_all()
    assert db.get(VmRefNvd, "CVE-2025-1000").description == "old"
    assert db.get(VmRefSyncState, "nvd").checkpoint == BASE


def test_unchanged_retries_pending_rebuild(tmp_path: Path, db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from api.modules.vm.services import ref_updates
    from api.modules.vm.sync_models import VmRefSyncState
    db = db_session
    seed(db, "nvd", BASE)
    db.get(VmRefSyncState, "nvd").pending_rebuild = True
    db.commit()
    calls = []
    monkeypatch.setattr("api.modules.vm.services.bundle._rebuild", lambda *args: calls.append(args[2]))
    path = bundle(tmp_path, [{"name": "nvd", "mode": "unchanged", "base": BASE, "target": BASE}], {})
    ref_updates.run_update_bundle(db, Handle(db), path, None)
    assert calls == [{"nvd"}]
    assert not db.get(VmRefSyncState, "nvd").pending_rebuild
    assert db.get(VmRefSyncState, "nvd").last_mode == "unchanged"


def test_full_ghsa_uses_zip_revision_not_import_time(tmp_path: Path, db_session: Any) -> None:
    from api.modules.vm.services.ghsa_import import load_ghsa
    from api.modules.vm.services.ref_updates import export_state
    from tests.vm.test_ghsa_import import archive
    path = archive(tmp_path, [advisory()])
    with zipfile.ZipFile(path, "a") as out:
        out.comment = b"a" * 40
    load_ghsa(db_session, path, Handle(db_session), "file")
    assert export_state(db_session)["sources"]["ghsa"] == {"revision": "a" * 40}
    with zipfile.ZipFile(path, "a") as out:
        out.comment = b""
    load_ghsa(db_session, path, Handle(db_session), "file")
    assert "ghsa" not in export_state(db_session)["sources"]


def test_full_nvd_requires_timestamps_for_all_loaded_years(tmp_path: Path, db_session: Any) -> None:
    from api.modules.vm.services.ref_updates import export_state
    from api.modules.vm.services.refs import load_ref
    db = db_session
    db.add(VmRefNvd(cve_id="CVE-2024-1000", year=2024))
    db.commit()
    path = tmp_path / "nvdcve-2.0-2025.json"
    path.write_text(json.dumps({"timestamp": TARGET["cursor"], "vulnerabilities": [
        {"cve": {"id": "CVE-2025-1000"}}]}))
    load_ref(db, Handle(db), "nvd", path, "file")
    assert "nvd" not in export_state(db)["sources"]
    path.write_text(json.dumps({"timestamp": BASE["cursor"], "vulnerabilities": [
        {"cve": {"id": "CVE-2024-1000"}}]}))
    load_ref(db, Handle(db), "nvd", path, "file")
    assert export_state(db)["sources"]["nvd"] == {"cursor": BASE["cursor"], "years": [2024, 2025]}


def test_auto_legacy_catalog_requires_explicit_full(db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from api.modules.vm.services.refs import run_ref_download
    db = db_session
    db.add(VmRefState(name="ghsa", records=100))
    db.commit()
    with pytest.raises(ValueError, match="checkpoint|полный|baseline"):
        run_ref_download(db, Handle(db), "ghsa", None, mode="auto")


def test_state_export_and_no_baseline_ui(auth_client: Any, db_session: Any) -> None:
    seed(db_session, "nvd", BASE)
    exported = auth_client.get("/api/vm/refs/update-state")
    assert exported.status_code == 200
    assert exported.json() == {"format": "stools-reference-state", "version": 1, "sources": {"nvd": BASE}}
    refs = {row["name"]: row for row in auth_client.get("/api/vm/refs").json()}
    assert refs["nvd"]["update_available"] and refs["nvd"]["checkpoint"] == BASE
    assert not refs["ghsa"]["update_available"]
    assert refs["kev"]["update_capability"] == "snapshot"


def test_no_change_producer_bundle_advances_cursor_without_rebuild(tmp_path: Path, db_session: Any) -> None:
    import datetime as dt

    from api.modules.vm.core.ref_updates import HttpResponse, build_update_bundle
    from api.modules.vm.services.ref_updates import apply_update_bundle, export_state
    from api.modules.vm.sync_models import VmRefSyncState
    db = db_session
    seed(db, "nvd", BASE)
    loaded = db.get(VmRefState, "nvd").loaded_at
    path = tmp_path / "empty.zip"
    build_update_bundle(path, export_state(db), ["nvd"], tmp_path / "cache",
                        now=dt.datetime(2025, 2, 1, tzinfo=dt.UTC),
                        http=lambda *args: HttpResponse(200, {}, b'{"vulnerabilities":[],"totalResults":0,"startIndex":0}'))
    assert apply_update_bundle(db, Handle(db), path) == set()
    sync = db.get(VmRefSyncState, "nvd")
    assert sync.checkpoint["cursor"] == "2025-02-01T00:00:00Z"
    assert sync.last_mode == "unchanged" and not sync.pending_rebuild
    assert db.get(VmRefState, "nvd").loaded_at == loaded


def test_cancellation_after_rows_are_written_rolls_back(tmp_path: Path, db_session: Any) -> None:
    from api.modules.vm.services.ref_updates import apply_update_bundle
    from api.modules.vm.sync_models import VmRefSyncState
    db = db_session
    seed(db, "nvd", BASE)
    db.add(VmRefNvd(cve_id="CVE-2025-1000", year=2025, description="old"))
    db.commit()
    path = bundle(tmp_path, [{"name": "nvd", "mode": "delta", "base": BASE, "target": TARGET,
                              "paths": ["nvd/part.json"]}], {
        "nvd/part.json": {"vulnerabilities": [{"cve": {"id": "CVE-2025-1000"}}]}})
    class CancelAfterWrite(Handle):
        def tick(self, *args: Any, **kwargs: Any) -> None:
            self.db.commit()
            # Another connection must still see the previous committed row.
            self.db.expire_all()
            assert self.db.get(VmRefNvd, "CVE-2025-1000").description == "old"
            raise JobCancelled()
    with pytest.raises(JobCancelled):
        apply_update_bundle(db, CancelAfterWrite(db), path)
    db.expire_all()
    assert db.get(VmRefNvd, "CVE-2025-1000").description == "old"
    assert db.get(VmRefSyncState, "nvd").checkpoint == BASE


def test_rebuild_failure_persists_and_replay_recovers(tmp_path: Path, db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from api.modules.vm.services.ref_updates import run_update_bundle
    from api.modules.vm.sync_models import VmRefSyncState
    db = db_session
    base, target = {"revision": "a" * 40}, {"revision": "b" * 40}
    seed(db, "ghsa", base)
    name = f"advisories/github-reviewed/2025/01/{ID}/{ID}.json"
    path = bundle(tmp_path, [{"name": "ghsa", "mode": "delta", "base": base, "target": target,
                              "paths": [name]}], {name: advisory()})
    def fail(*args: Any) -> None:
        raise RuntimeError("derived rebuild failed")
    monkeypatch.setattr("api.modules.vm.services.bundle._rebuild", fail)
    with pytest.raises(RuntimeError, match="derived rebuild"):
        run_update_bundle(db, Handle(db), path, None)
    db.rollback()
    assert db.get(VmRefSyncState, "ghsa").checkpoint == target
    assert db.get(VmRefSyncState, "ghsa").pending_rebuild
    calls = []
    monkeypatch.setattr("api.modules.vm.services.bundle._rebuild", lambda *args: calls.append(args[2]))
    run_update_bundle(db, Handle(db), path, None)
    assert calls == [{"ghsa"}]
    assert not db.get(VmRefSyncState, "ghsa").pending_rebuild


@pytest.mark.parametrize("corruption", ["checksum", "unlisted", "duplicate", "unsafe", "missing", "version"])
def test_invalid_archive_keeps_checkpoint(tmp_path: Path, db_session: Any, corruption: str) -> None:
    from api.modules.vm.services.ref_updates import apply_update_bundle
    from api.modules.vm.sync_models import VmRefSyncState
    db = db_session
    seed(db, "nvd", BASE)
    path = bundle(tmp_path, [{"name": "nvd", "mode": "delta", "base": BASE, "target": TARGET,
                              "paths": ["nvd/part.json"]}], {"nvd/part.json": {"vulnerabilities": []}})
    with zipfile.ZipFile(path) as src:
        data = {info.filename: src.read(info) for info in src.infolist()}
    manifest = json.loads(data["stools-reference-update.json"])
    if corruption == "checksum":
        data["nvd/part.json"] += b" "
    elif corruption == "missing":
        del data["nvd/part.json"]
    elif corruption == "version":
        manifest["version"] = 2
    elif corruption == "unsafe":
        data["../evil.json"] = b"{}"
    elif corruption == "unlisted":
        data["extra.json"] = b"{}"
    data["stools-reference-update.json"] = json.dumps(manifest).encode()
    with zipfile.ZipFile(path, "w") as out:
        for name, payload in data.items():
            out.writestr(name, payload)
        if corruption == "duplicate":
            with pytest.warns(UserWarning):
                out.writestr("nvd/part.json", b"{}")
    with pytest.raises(ValueError):
        apply_update_bundle(db, Handle(db), path)
    assert db.get(VmRefSyncState, "nvd").checkpoint == BASE


def test_online_updates_304_does_not_import_or_rebuild(tmp_path: Path, db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from api.modules.vm.core import ref_updates as producer
    from api.modules.vm.services import refs
    from api.modules.vm.sync_models import VmRefSyncState
    db = db_session
    url = producer.SNAPSHOTS["epss"][0][1]
    checkpoint = {"validators": {url: {"etag": '"v1"', "sha256": "a" * 64}}}
    seed(db, "epss", checkpoint)
    old_loaded = db.get(VmRefState, "epss").loaded_at
    real_build = producer.build_update_bundle
    calls = []
    def transport(url: str, headers: dict) -> Any:
        calls.append((url, headers))
        return producer.HttpResponse(304, {}, b"")
    monkeypatch.setattr(producer, "build_update_bundle", lambda *args, **kwargs: real_build(*args, **kwargs, http=transport))
    monkeypatch.setattr(refs, "download", lambda *args, **kwargs: pytest.fail("full download during updates"))
    monkeypatch.setattr(refs, "_load_epss", lambda *args: pytest.fail("304 reimported"))
    monkeypatch.setattr("api.modules.vm.services.bundle._rebuild", lambda *args: pytest.fail("304 rebuilt"))
    refs.run_ref_download(db, Handle(db), "epss", None, mode="updates")
    assert len(calls) == 1 and calls[0][1]["If-None-Match"] == '"v1"'
    assert db.get(VmRefState, "epss").loaded_at == old_loaded
    assert db.get(VmRefSyncState, "epss").last_mode == "unchanged"


def test_modified_feed_refused_before_full_import(auth_client: Any, db_session: Any) -> None:
    response = auth_client.post("/api/vm/refs/nvd/upload", files=[
        ("files", ("nvdcve-2.0-modified.json", b'{"vulnerabilities":[]}', "application/json"))])
    assert response.status_code == 422
    assert "обновлений" in response.json()["detail"]


def test_bundle_preflight_precedes_zipfile_allocation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from api.modules.vm.core import ref_updates as producer
    from api.modules.vm.routers.refs import _has_known_refs
    path = bundle(tmp_path, [{"name": "nvd", "mode": "delta", "base": BASE, "target": TARGET,
                              "paths": ["nvd/one.json", "nvd/two.json"]}], {
        "nvd/one.json": {"vulnerabilities": []}, "nvd/two.json": {"vulnerabilities": []}})
    monkeypatch.setattr(producer, "MAX_FILES", 1)
    monkeypatch.setattr(zipfile, "ZipFile", lambda *args, **kwargs: pytest.fail("ZipFile allocated before bounded preflight"))
    assert not _has_known_refs(path)


def test_official_nvd_naive_timestamp_is_normalized_to_utc(tmp_path: Path, db_session: Any) -> None:
    from api.modules.vm.services.ref_updates import export_state
    from api.modules.vm.services.refs import load_ref
    path = tmp_path / "nvdcve-2.0-2002.json"
    path.write_text(json.dumps({"timestamp": "2026-11-12T03:02:58.8381505", "vulnerabilities": [
        {"cve": {"id": "CVE-2002-1000"}}]}))
    load_ref(db_session, Handle(db_session), "nvd", path, "file")
    assert export_state(db_session)["sources"]["nvd"] == {
        "cursor": "2026-11-12T03:02:58.838150Z", "years": [2002]}


def test_full_snapshot_records_valid_http_metadata(db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    from api.modules.vm.core.ref_updates import validate_state
    from api.modules.vm.services import refs
    from api.modules.vm.services.ref_updates import export_state
    content = (Path(__file__).parent / "fixtures" / "epss.csv").read_bytes()
    monkeypatch.setattr("api.modules.vm.services.bundle._rebuild", lambda *args: None)
    factory = lambda: httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=content, headers={"ETag": '"v1"'})))
    refs.run_ref_download(db_session, Handle(db_session), "epss", None, mode="full", http_factory=factory)
    state = export_state(db_session)
    validate_state(state)
    assert state["sources"]["epss"]["validators"][refs.URLS["epss"]] == {
        "etag": '"v1"', "sha256": hashlib.sha256(content).hexdigest()}


def test_snapshot_producer_payload_imports_with_its_digest(tmp_path: Path, db_session: Any) -> None:
    import gzip

    from api.modules.vm.core.ref_updates import HttpResponse, build_update_bundle
    from api.modules.vm.models import VmRefEpss
    from api.modules.vm.services.ref_updates import apply_update_bundle, export_state
    payload = gzip.compress((Path(__file__).parent / "fixtures" / "epss.csv").read_bytes())
    path = tmp_path / "epss-update.zip"
    build_update_bundle(path, export_state(db_session), ["epss"], tmp_path / "cache",
                        http=lambda *args: HttpResponse(200, {"etag": '"v1"'}, payload))
    assert apply_update_bundle(db_session, Handle(db_session), path) == {"epss"}
    assert db_session.scalar(select(VmRefEpss.cve_id).limit(1))


def test_offline_bundle_route_applies_two_updates_and_replays(tmp_path: Path, db_session: Any, auth_client: Any) -> None:
    from api.modules.vm.models import VmJob
    from api.modules.vm.sync_models import VmRefSyncState
    db = db_session
    seed(db, "nvd", BASE)
    targets = [TARGET, {**TARGET, "cursor": "2025-03-01T00:00:00Z"}]
    previous = BASE
    for index, target in enumerate(targets):
        path = bundle(tmp_path, [{"name": "nvd", "mode": "delta", "base": previous, "target": target,
                                  "paths": ["nvd/part.json"]}], {"nvd/part.json": {"vulnerabilities": [
            {"cve": {"id": "CVE-2025-1000", "descriptions": [{"lang": "en", "value": str(index)}]}}]}})
        payload = path.read_bytes()
        response = auth_client.post("/api/vm/refs/bundle/upload", files={"file": ("updates.zip", payload, "application/zip")})
        assert response.status_code == 202
        db.expire_all()
        job = db.get(VmJob, response.json()["job_id"])
        assert job.status == "done", job.error
        assert db.get(VmRefSyncState, "nvd").checkpoint == target
        previous = target
    loaded = db.get(VmRefState, "nvd").loaded_at
    response = auth_client.post("/api/vm/refs/bundle/upload", files={"file": ("updates.zip", payload, "application/zip")})
    db.expire_all()
    assert db.get(VmJob, response.json()["job_id"]).status == "done"
    assert db.get(VmRefState, "nvd").loaded_at == loaded
    assert db.get(VmRefNvd, "CVE-2025-1000").description == "1"


def test_unchanged_snapshot_cannot_initialize_missing_baseline(tmp_path: Path, db_session: Any) -> None:
    from api.modules.vm.core.ref_updates import SNAPSHOTS
    from api.modules.vm.services.ref_updates import apply_update_bundle
    from api.modules.vm.sync_models import VmRefSyncState
    target = {"validators": {SNAPSHOTS["epss"][0][1]: {"etag": '"v1"', "sha256": "a" * 64}}}
    path = bundle(tmp_path, [{"name": "epss", "mode": "unchanged", "base": None, "target": target}], {})
    with pytest.raises(ValueError, match="исходн|верси"):
        apply_update_bundle(db_session, Handle(db_session), path)
    assert db_session.get(VmRefSyncState, "epss") is None
    assert db_session.get(VmRefState, "epss") is None


@pytest.mark.parametrize("invalid", ["both", "csv", "json_alias", "empty"])
def test_attack_snapshot_validates_both_native_schemas_before_replacement(
    tmp_path: Path, db_session: Any, invalid: str,
) -> None:
    from api.modules.vm.core.ref_updates import SNAPSHOTS
    from api.modules.vm.models import VmRefAttack
    from api.modules.vm.services.ref_updates import apply_update_bundle
    from api.modules.vm.sync_models import VmRefSyncState
    db = db_session
    db.add(VmRefAttack(cve_id="CVE-2025-1000", technique_id="T1190", mapping_type="primary_impact"))
    db.commit()
    payloads = {
        SNAPSHOTS["attack"][0][0]: json.dumps({"mapping_objects": [
            {"capability_id": "CVE-2025-2000", "attack_object_id": "T1190", "mapping_type": "primary_impact"}]}).encode(),
        SNAPSHOTS["attack"][1][0]: b"CVE ID,Primary Impact,Secondary Impact,Exploitation Technique\nCVE-2025-2000,T1190,,\n",
    }
    if invalid in {"both", "csv"}:
        payloads[SNAPSHOTS["attack"][1][0]] = b"invalid\nformat\n"
    if invalid == "both":
        payloads[SNAPSHOTS["attack"][0][0]] = b"{}"
    elif invalid == "json_alias":
        payloads[SNAPSHOTS["attack"][0][0]] = b'{"mappings":[]}'
    if invalid == "empty":
        payloads[SNAPSHOTS["attack"][0][0]] = b'{"mapping_objects":[]}'
        payloads[SNAPSHOTS["attack"][1][0]] = b"CVE ID,Primary Impact,Secondary Impact,Exploitation Technique\n"
    target = {"validators": {url: {"sha256": hashlib.sha256(payloads[name]).hexdigest()}
                             for name, url in SNAPSHOTS["attack"]}}
    entry = {"name": "attack", "mode": "snapshot", "base": None, "target": target,
             "files": [{"path": name, "sha256": hashlib.sha256(body).hexdigest()} for name, body in payloads.items()],
             "deleted_ids": []}
    manifest = {"format": "stools-reference-update", "version": 1, "created_at": BASE["cursor"], "sources": [entry]}
    path = tmp_path / "attack-updates.zip"
    with zipfile.ZipFile(path, "w") as out:
        out.writestr("stools-reference-update.json", json.dumps(manifest))
        for name, body in payloads.items():
            out.writestr(name, body)
    with pytest.raises(ValueError, match="ATT&CK"):
        apply_update_bundle(db, Handle(db), path)
    assert db.get(VmRefAttack, ("CVE-2025-1000", "T1190")) is not None
    assert db.get(VmRefSyncState, "attack") is None


def test_native_attack_snapshot_updates_both_components(tmp_path: Path, db_session: Any) -> None:
    from sqlalchemy import func

    from api.modules.vm.core.ref_updates import SNAPSHOTS, HttpResponse, build_update_bundle
    from api.modules.vm.models import VmRefAttack
    from api.modules.vm.services.ref_updates import apply_update_bundle, export_state
    fixtures = Path(__file__).parent / "fixtures"
    payloads = {SNAPSHOTS["attack"][0][1]: (fixtures / "ctid-kev.json").read_bytes(),
                SNAPSHOTS["attack"][1][1]: (fixtures / "attack_to_cve.csv").read_bytes()}
    path = tmp_path / "native-attack.zip"
    build_update_bundle(path, export_state(db_session), ["attack"], tmp_path / "cache",
                        http=lambda url, headers: HttpResponse(200, {}, payloads[url]))
    assert apply_update_bundle(db_session, Handle(db_session), path) == {"attack"}
    assert db_session.scalar(select(func.count()).select_from(VmRefAttack)) == 9
