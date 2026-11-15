"""Period archives are partial merges, never evidence of a complete catalog."""
from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from api.jobs import JobCancelled
from api.modules.vm.ghsa_models import VmRefGhsa
from api.modules.vm.models import VmRefNvd, VmRefState
from api.modules.vm.services.ref_updates import apply_update_bundle, export_state, run_update_bundle
from api.modules.vm.services.refs_view import ref_views
from api.modules.vm.sync_models import VmRefSyncState
from tests.vm.test_ghsa_import import ID, OTHER, advisory
from tests.vm.test_ref_update_import import BASE, Handle, bundle, seed

WINDOW = {"since": "2025-01-25T00:00:00Z", "until": "2025-02-01T00:00:00Z"}
NVD_PATH = "nvd/part.json"
GHSA_PATH = f"advisories/github-reviewed/2025/01/{ID}/{ID}.json"


def nvd(description: str = "changed", year: int = 2025) -> dict:
    return {"vulnerabilities": [{"cve": {"id": f"CVE-{year}-1000", "descriptions": [
        {"lang": "en", "value": description}], "configurations": []}}]}


def period_bundle(tmp_path: Path, entries: list[dict] | None = None, payloads: dict | None = None,
                  **overrides: Any) -> Path:
    entries = entries if entries is not None else [{"name": "nvd", "mode": "delta", "paths": [NVD_PATH]}]
    payloads = payloads if payloads is not None else {NVD_PATH: nvd()}
    encoded = {name: value if isinstance(value, bytes) else json.dumps(value).encode()
               for name, value in payloads.items()}
    for entry in entries:
        entry["files"] = [{"path": name, "sha256": hashlib.sha256(encoded[name]).hexdigest()}
                          for name in entry.pop("paths", [])]
        entry.setdefault("deleted_ids", [])
        entry.setdefault("provenance", {})
    manifest = {"format": "stools-reference-update", "version": 2, "scope": "window",
                "created_at": WINDOW["until"], "window": WINDOW, "sources": entries, **overrides}
    path = tmp_path / "period.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as out:
        out.writestr("stools-reference-update.json", json.dumps(manifest))
        for name, data in encoded.items():
            out.writestr(name, data)
    return path


@pytest.mark.parametrize("baseline", [False, True])
def test_period_merges_without_advancing_complete_freshness(tmp_path: Path, db_session: Any, baseline: bool) -> None:
    db = db_session
    checked = dt.datetime(2024, 12, 1, tzinfo=dt.UTC)
    if baseline:
        seed(db, "nvd", BASE)
        sync = db.get(VmRefSyncState, "nvd")
        sync.last_checked_at, sync.baseline_years = checked, {"2025": BASE["cursor"]}
    db.add_all([VmRefNvd(cve_id="CVE-2025-1000", year=2025, description="old"),
                VmRefNvd(cve_id="CVE-2025-2000", year=2025, description="untouched")])
    db.commit()
    path = period_bundle(tmp_path)
    assert apply_update_bundle(db, Handle(db), path) == {"nvd"}
    assert db.get(VmRefNvd, "CVE-2025-1000").description == "changed"
    assert db.get(VmRefNvd, "CVE-2025-2000").description == "untouched"
    sync = db.get(VmRefSyncState, "nvd")
    assert sync.checkpoint == (BASE if baseline else None)
    assert sync.baseline_years == ({"2025": BASE["cursor"]} if baseline else None)
    assert sync.last_checked_at == (checked if baseline else None)
    view = next(view for view in ref_views(db) if view.name == "nvd")
    assert view.partial_window == WINDOW
    assert view.last_period_imported_at is not None
    assert view.stale  # A local import today does not make old/incomplete data fresh.
    assert ("nvd" in export_state(db)["sources"]) is baseline
    loaded, imported = db.get(VmRefState, "nvd").loaded_at, view.last_period_imported_at
    assert apply_update_bundle(db, Handle(db), path) == set()
    view = next(view for view in ref_views(db) if view.name == "nvd")
    assert db.get(VmRefState, "nvd").loaded_at == loaded
    assert view.last_period_imported_at == imported


def test_period_ghsa_preserves_existing_records_and_explicit_deletions(tmp_path: Path, db_session: Any) -> None:
    db = db_session
    untouched = "GHSA-aaaa-bbbb-cccc"
    db.add_all([VmRefGhsa(ghsa_id=ID), VmRefGhsa(ghsa_id=OTHER), VmRefGhsa(ghsa_id=untouched)])
    db.commit()
    path = period_bundle(tmp_path, [{"name": "ghsa", "mode": "delta", "paths": [GHSA_PATH],
                                    "deleted_ids": [OTHER]}], {GHSA_PATH: advisory()})
    assert apply_update_bundle(db, Handle(db), path) == {"ghsa"}
    assert db.get(VmRefGhsa, untouched) is not None
    assert db.get(VmRefGhsa, OTHER) is None
    assert db.get(VmRefGhsa, ID).summary
    assert db.get(VmRefSyncState, "ghsa").checkpoint is None
    assert db.get(VmRefSyncState, "ghsa").last_checked_at is None


@pytest.mark.parametrize("failure", ["bad_second_source", "cancel"])
def test_period_transaction_rolls_back_all_sources(tmp_path: Path, db_session: Any, failure: str) -> None:
    db = db_session
    db.add(VmRefNvd(cve_id="CVE-2025-1000", year=2025, description="old"))
    db.commit()
    path = period_bundle(tmp_path, [{"name": "nvd", "mode": "delta", "paths": [NVD_PATH]},
                                    {"name": "ghsa", "mode": "delta", "paths": [GHSA_PATH]}],
                         {NVD_PATH: nvd(), GHSA_PATH: {} if failure == "bad_second_source" else advisory()})
    class CancelAfterWrite(Handle):
        def tick(self, *args: Any, **kwargs: Any) -> None:
            self.db.commit()
            self.db.expire_all()
            assert self.db.get(VmRefNvd, "CVE-2025-1000").description == "old"
            raise JobCancelled()
    handle = CancelAfterWrite(db) if failure == "cancel" else Handle(db)
    with pytest.raises(JobCancelled if failure == "cancel" else ValueError):
        apply_update_bundle(db, handle, path)
    assert db.get(VmRefNvd, "CVE-2025-1000").description == "old"
    assert db.get(VmRefSyncState, "nvd") is None
    assert db.get(VmRefState, "nvd") is None


@pytest.mark.parametrize("window", [None, {}, {"since": "invalid", "until": WINDOW["until"]},
    {"since": "2025-01-25", "until": WINDOW["until"]},
    {"since": WINDOW["until"], "until": WINDOW["until"]},
    {"since": "2025-02-02T00:00:00Z", "until": WINDOW["until"]},
    {"since": "2024-10-31T23:59:59Z", "until": WINDOW["until"]}])
def test_period_invalid_window_rejected_before_mutation(tmp_path: Path, db_session: Any, window: Any) -> None:
    path = period_bundle(tmp_path, window=window)
    with pytest.raises(ValueError):
        apply_update_bundle(db_session, Handle(db_session), path)
    assert db_session.get(VmRefNvd, "CVE-2025-1000") is None
    assert db_session.get(VmRefSyncState, "nvd") is None


@pytest.mark.parametrize("corruption", ["digest", "unsafe", "missing_scope", "provenance", "checkpoint"])
def test_period_invalid_contract_rejected_before_mutation(tmp_path: Path, db_session: Any, corruption: str) -> None:
    path = period_bundle(tmp_path)
    with zipfile.ZipFile(path) as src:
        data = {info.filename: src.read(info) for info in src.infolist()}
    manifest = json.loads(data["stools-reference-update.json"])
    if corruption == "digest":
        data[NVD_PATH] += b" "
    elif corruption == "unsafe":
        data["../evil.json"] = b"{}"
    elif corruption == "missing_scope":
        del manifest["scope"]
    elif corruption == "provenance":
        manifest["sources"][0]["provenance"] = "unknown"
    else:
        manifest["sources"][0]["target"] = BASE
    data["stools-reference-update.json"] = json.dumps(manifest).encode()
    with zipfile.ZipFile(path, "w") as out:
        for name, payload in data.items():
            out.writestr(name, payload)
    with pytest.raises(ValueError):
        apply_update_bundle(db_session, Handle(db_session), path)
    assert db_session.get(VmRefSyncState, "nvd") is None


def test_period_stale_rejected_but_previously_applied_archive_replays(tmp_path: Path, db_session: Any) -> None:
    db = db_session
    path = period_bundle(tmp_path)
    original = path.read_bytes()
    apply_update_bundle(db, Handle(db), path)
    path = period_bundle(tmp_path, payloads={NVD_PATH: nvd("newer")},
                         window={"since": WINDOW["since"], "until": "2025-02-02T00:00:00Z"},
                         created_at="2025-02-02T00:00:00Z")
    apply_update_bundle(db, Handle(db), path)
    path = period_bundle(tmp_path, payloads={NVD_PATH: nvd("stale")})
    with pytest.raises(ValueError, match="стар|stale|период"):
        apply_update_bundle(db, Handle(db), path)
    assert db.get(VmRefNvd, "CVE-2025-1000").description == "newer"
    path.write_bytes(original)
    assert apply_update_bundle(db, Handle(db), path) == set()
    assert db.get(VmRefNvd, "CVE-2025-1000").description == "newer"


def test_period_replay_retries_failed_rebuild(tmp_path: Path, db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    db = db_session
    path = period_bundle(tmp_path, [{"name": "ghsa", "mode": "delta", "paths": [GHSA_PATH]}], {GHSA_PATH: advisory()})
    def fail(*args: Any) -> None:
        raise RuntimeError("rebuild failed")
    monkeypatch.setattr("api.modules.vm.services.bundle._rebuild", fail)
    with pytest.raises(RuntimeError, match="rebuild failed"):
        run_update_bundle(db, Handle(db), path, None)
    db.rollback()
    loaded = db.get(VmRefState, "ghsa").loaded_at
    assert db.get(VmRefSyncState, "ghsa").pending_rebuild
    calls = []
    monkeypatch.setattr("api.modules.vm.services.bundle._rebuild", lambda *args: calls.append(args[2]))
    run_update_bundle(db, Handle(db), path, None)
    assert calls == [{"ghsa"}]
    assert not db.get(VmRefSyncState, "ghsa").pending_rebuild
    assert db.get(VmRefState, "ghsa").loaded_at == loaded


def test_nvd_full_import_only_clears_partial_after_all_years_are_complete(tmp_path: Path, db_session: Any) -> None:
    from api.modules.vm.services.refs import load_ref
    db = db_session
    db.add(VmRefNvd(cve_id="CVE-2024-1000", year=2024))
    db.commit()
    apply_update_bundle(db, Handle(db), period_bundle(tmp_path))
    for year in (2025, 2024):
        path = tmp_path / f"nvdcve-2.0-{year}.json"
        path.write_text(json.dumps({"timestamp": "2025-02-02T00:00:00Z", **nvd(year=year)}))
        load_ref(db, Handle(db), "nvd", path, "file")
        sync = db.get(VmRefSyncState, "nvd")
        assert bool(sync.partial_window) is (year == 2025)
        if year == 2025:
            assert sync.last_checked_at is None
    assert sync.last_checked_at is not None
    assert sync.period_import is not None


def test_contiguous_v1_clears_partial_when_cursor_covers_the_window(tmp_path: Path, db_session: Any) -> None:
    db = db_session
    seed(db, "nvd", BASE)
    apply_update_bundle(db, Handle(db), period_bundle(tmp_path))
    target = {"cursor": "2025-02-02T00:00:00Z", "years": [2025]}
    path = bundle(tmp_path, [{"name": "nvd", "mode": "delta", "base": BASE, "target": target,
                              "paths": [NVD_PATH]}], {NVD_PATH: nvd("complete")})
    apply_update_bundle(db, Handle(db), path)
    assert db.get(VmRefSyncState, "nvd").partial_window is None
    assert db.get(VmRefSyncState, "nvd").period_import is not None


@pytest.mark.parametrize("validators", [False, True])
def test_period_snapshot_preserves_only_available_source_metadata(tmp_path: Path, db_session: Any, validators: bool) -> None:
    from api.modules.vm.core.ref_updates import SNAPSHOTS
    filename, url = SNAPSHOTS["epss"][0]
    payload = gzip.compress(b"cve,epss,percentile\nCVE-2025-1000,0.4,0.9\n")
    provenance = {"validators": {url: {"sha256": hashlib.sha256(payload).hexdigest()}}} if validators else {}
    path = period_bundle(tmp_path, [{"name": "epss", "mode": "snapshot", "paths": [filename],
                                    "provenance": provenance}], {filename: payload})
    assert apply_update_bundle(db_session, Handle(db_session), path) == {"epss"}
    sync = db_session.get(VmRefSyncState, "epss")
    assert sync.checkpoint == (provenance if validators else None)
    assert sync.last_mode == "snapshot"
    assert sync.last_checked_at == dt.datetime(2025, 2, 1, tzinfo=dt.UTC)
    assert sync.partial_window is None


def test_period_unchanged_source_cannot_invent_missing_baseline(tmp_path: Path, db_session: Any) -> None:
    path = period_bundle(tmp_path, [{"name": "epss", "mode": "unchanged"},
                                    {"name": "nvd", "mode": "unchanged"}], {})
    assert apply_update_bundle(db_session, Handle(db_session), path) == set()
    for name in ("epss", "nvd"):
        sync = db_session.get(VmRefSyncState, name)
        assert sync.checkpoint is None
        assert sync.last_checked_at is None
        assert db_session.get(VmRefState, name) is None


def test_full_ghsa_clears_partial_and_keeps_replay_history(tmp_path: Path, db_session: Any) -> None:
    from api.modules.vm.services.ghsa_import import load_ghsa
    from tests.vm.test_ghsa_import import archive
    db = db_session
    period = period_bundle(tmp_path, [{"name": "ghsa", "mode": "delta", "paths": [GHSA_PATH]}],
                           {GHSA_PATH: advisory()})
    apply_update_bundle(db, Handle(db), period)
    complete = archive(tmp_path, [advisory()])
    load_ghsa(db, complete, Handle(db), "file")
    sync = db.get(VmRefSyncState, "ghsa")
    assert sync.partial_window is None
    assert sync.period_import is not None
    assert sync.checkpoint is None  # A full archive without a revision cannot invent one.
    loaded, checked = db.get(VmRefState, "ghsa").loaded_at, sync.last_checked_at
    assert apply_update_bundle(db, Handle(db), period) == set()
    assert db.get(VmRefState, "ghsa").loaded_at == loaded
    assert db.get(VmRefSyncState, "ghsa").last_checked_at == checked
    assert db.get(VmRefSyncState, "ghsa").partial_window is None


def test_v1_does_not_clear_partial_if_it_omits_a_loaded_nvd_year(tmp_path: Path, db_session: Any) -> None:
    db = db_session
    seed(db, "nvd", BASE)
    checked = dt.datetime(2025, 1, 1, tzinfo=dt.UTC)
    db.get(VmRefSyncState, "nvd").last_checked_at = checked
    db.commit()
    apply_update_bundle(db, Handle(db), period_bundle(tmp_path, payloads={NVD_PATH: nvd(year=2024)}))
    target = {"cursor": "2025-02-02T00:00:00Z", "years": [2025]}
    path = bundle(tmp_path, [{"name": "nvd", "mode": "delta", "base": BASE, "target": target,
                              "paths": [NVD_PATH]}], {NVD_PATH: nvd()})
    apply_update_bundle(db, Handle(db), path)
    sync = db.get(VmRefSyncState, "nvd")
    assert sync.partial_window == WINDOW
    assert sync.last_checked_at == checked


def test_period_bundle_route_and_reference_status(tmp_path: Path, db_session: Any, auth_client: Any,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("api.modules.vm.services.bundle._rebuild", lambda *args: None)
    monkeypatch.setattr("api.modules.vm.services.software.rebuild_ksc", lambda *args: None)
    path = period_bundle(tmp_path)
    response = auth_client.post("/api/vm/refs/bundle/upload", files={"file": ("period.zip", path.read_bytes(), "application/zip")})
    assert response.status_code == 202, response.text
    view = next(item for item in auth_client.get("/api/vm/refs").json() if item["name"] == "nvd")
    assert view["partial_window"] == WINDOW
    assert view["last_period_imported_at"] is not None
    assert view["last_checked_at"] is None
    assert view["stale"]


@pytest.mark.parametrize("period", ["1d", "3m"])
def test_real_period_producer_archive_imports_without_state_export(tmp_path: Path, db_session: Any, period: str) -> None:
    from urllib.parse import parse_qs, urlsplit

    from api.modules.vm.core.ref_updates import HttpResponse
    from api.modules.vm.core.ref_window import build_window_bundle

    def http(url: str, headers: dict) -> HttpResponse:
        query = parse_qs(urlsplit(url).query)
        start = dt.datetime.fromisoformat(query["lastModStartDate"][0])
        modified = (start + dt.timedelta(hours=1)).isoformat()
        record = {"cve": {"id": "CVE-2025-1000", "lastModified": modified,
                           "descriptions": [{"lang": "en", "value": "producer change"}]}}
        # Only one page/window contains the fixture record.
        records = [record] if start.month == 1 and start.day == 31 else []
        return HttpResponse(200, {}, json.dumps({"vulnerabilities": records,
                            "totalResults": len(records), "startIndex": 0}).encode())

    path = tmp_path / "generated-period.zip"
    manifest = build_window_bundle(path, ["nvd"], tmp_path / "cache", period=period,
                                   now=dt.datetime(2025, 2, 1, tzinfo=dt.UTC), http=http)
    apply_update_bundle(db_session, Handle(db_session), path)
    sync = db_session.get(VmRefSyncState, "nvd")
    assert sync.partial_window == manifest["window"]
    assert sync.checkpoint is None and sync.baseline_years is None and sync.last_checked_at is None


@pytest.mark.parametrize("coverage", ["checkpoint", "baseline_year", "record"])
def test_first_period_cannot_overwrite_newer_trusted_nvd_data(tmp_path: Path, db_session: Any, coverage: str) -> None:
    db = db_session
    checkpoint = {"cursor": "2025-02-10T00:00:00Z", "years": [2025]}
    if coverage != "record":
        seed(db, "nvd", checkpoint if coverage == "checkpoint" else BASE)
        if coverage == "baseline_year":
            db.get(VmRefSyncState, "nvd").baseline_years = {"2025": checkpoint["cursor"]}
    db.add(VmRefNvd(cve_id="CVE-2025-1000", year=2025, description="newer complete data",
                    modified=dt.date(2025, 2, 10) if coverage == "record" else None))
    db.commit()
    with pytest.raises(ValueError, match="стар|период"):
        apply_update_bundle(db, Handle(db), period_bundle(tmp_path))
    assert db.get(VmRefNvd, "CVE-2025-1000").description == "newer complete data"
    sync = db.get(VmRefSyncState, "nvd")
    assert sync is None or sync.period_import is None


@pytest.mark.parametrize("deletion", [False, True])
def test_period_cannot_replace_or_delete_newer_ghsa_record(tmp_path: Path, db_session: Any, deletion: bool) -> None:
    db = db_session
    db.add(VmRefGhsa(ghsa_id=ID, summary="newer", modified=dt.datetime(2025, 2, 10, tzinfo=dt.UTC)))
    db.commit()
    entry = {"name": "ghsa", "mode": "delta", "paths": [] if deletion else [GHSA_PATH],
             "deleted_ids": [ID] if deletion else []}
    path = period_bundle(tmp_path, [entry], {} if deletion else {GHSA_PATH: advisory()})
    with pytest.raises(ValueError, match="стар|период"):
        apply_update_bundle(db, Handle(db), path)
    assert db.get(VmRefGhsa, ID).summary == "newer"
    assert db.get(VmRefSyncState, "ghsa") is None


def retime_bundle(path: Path, created_at: str) -> Path:
    with zipfile.ZipFile(path) as src:
        data = {info.filename: src.read(info) for info in src.infolist()}
    manifest = json.loads(data["stools-reference-update.json"])
    manifest["created_at"] = created_at
    data["stools-reference-update.json"] = json.dumps(manifest).encode()
    with zipfile.ZipFile(path, "w") as out:
        for name, payload in data.items():
            out.writestr(name, payload)
    return path


def test_period_respects_known_complete_ghsa_verification_time(tmp_path: Path, db_session: Any) -> None:
    db = db_session
    revision = {"revision": "a" * 40}
    seed(db, "ghsa", revision)
    db.add(VmRefGhsa(ghsa_id=ID, summary="complete"))
    db.commit()
    complete = bundle(tmp_path, [{"name": "ghsa", "mode": "unchanged", "base": revision,
                                 "target": revision}], {})
    apply_update_bundle(db, Handle(db), retime_bundle(complete, "2025-02-10T00:00:00Z"))
    path = period_bundle(tmp_path, [{"name": "ghsa", "mode": "delta", "paths": [GHSA_PATH]}],
                         {GHSA_PATH: advisory()})
    with pytest.raises(ValueError, match="стар|период"):
        apply_update_bundle(db, Handle(db), path)
    assert db.get(VmRefGhsa, ID).summary == "complete"


@pytest.mark.parametrize("verification", ["fresh", "old", "other_revision", "delta_replay"])
def test_ghsa_unchanged_complete_verification_clears_only_covered_partial(
    tmp_path: Path, db_session: Any, verification: str,
) -> None:
    db = db_session
    revision = {"revision": "a" * 40}
    seed(db, "ghsa", revision)
    checked = dt.datetime(2025, 1, 1, tzinfo=dt.UTC)
    db.get(VmRefSyncState, "ghsa").last_checked_at = checked
    db.commit()
    target = "b" * 40 if verification == "other_revision" else revision["revision"]
    path = period_bundle(tmp_path, [{"name": "ghsa", "mode": "unchanged",
                                    "provenance": {"target_revision": target}}], {})
    apply_update_bundle(db, Handle(db), path)
    old_base = {"revision": "c" * 40} if verification == "delta_replay" else revision
    complete = bundle(tmp_path, [{"name": "ghsa", "mode": "delta" if verification == "delta_replay" else "unchanged",
                                 "base": old_base, "target": revision}], {})
    if verification == "old":
        retime_bundle(complete, "2025-01-24T00:00:00Z")
    apply_update_bundle(db, Handle(db), complete)
    sync = db.get(VmRefSyncState, "ghsa")
    if verification == "fresh":
        assert sync.partial_window is None
        assert sync.last_checked_at > checked
        verified_at = sync.last_checked_at
        apply_update_bundle(db, Handle(db), complete)
        assert db.get(VmRefSyncState, "ghsa").last_checked_at == verified_at
    else:
        assert sync.partial_window == WINDOW
        assert sync.last_checked_at == checked



def test_period_does_not_compare_ghsa_upstream_date_to_local_import_time(tmp_path: Path, db_session: Any) -> None:
    db = db_session
    seed(db, "ghsa", {"revision": "a" * 40})
    checked = dt.datetime.now(dt.UTC)
    db.get(VmRefSyncState, "ghsa").last_checked_at = checked
    db.add(VmRefGhsa(ghsa_id=ID, summary="old", modified=dt.datetime(2025, 1, 28, tzinfo=dt.UTC)))
    db.commit()
    row = {**advisory(), "modified": "2025-01-30T00:00:00Z"}
    path = period_bundle(tmp_path, [{"name": "ghsa", "mode": "delta", "paths": [GHSA_PATH]}], {GHSA_PATH: row})
    assert apply_update_bundle(db, Handle(db), path) == {"ghsa"}
    assert db.get(VmRefGhsa, ID).summary == row["summary"]
    assert db.get(VmRefSyncState, "ghsa").last_checked_at == checked


def test_newer_nvd_baseline_does_not_block_uncovered_year(tmp_path: Path, db_session: Any) -> None:
    db = db_session
    checkpoint = {"cursor": "2025-02-10T00:00:00Z", "years": [2025]}
    seed(db, "nvd", checkpoint)
    db.add(VmRefNvd(cve_id="CVE-2025-1000", year=2025, description="current"))
    db.commit()
    path = period_bundle(tmp_path, payloads={NVD_PATH: nvd(year=2024)})
    assert apply_update_bundle(db, Handle(db), path) == {"nvd"}
    assert db.get(VmRefNvd, "CVE-2025-1000").description == "current"
    assert db.get(VmRefNvd, "CVE-2024-1000") is not None
    assert db.get(VmRefSyncState, "nvd").checkpoint == checkpoint


def test_period_cannot_downgrade_ghsa_record_inside_the_window(tmp_path: Path, db_session: Any) -> None:
    db = db_session
    db.add(VmRefGhsa(ghsa_id=ID, summary="newer", modified=dt.datetime(2025, 1, 31, tzinfo=dt.UTC)))
    db.commit()
    path = period_bundle(tmp_path, [{"name": "ghsa", "mode": "delta", "paths": [GHSA_PATH]}],
                         {GHSA_PATH: {**advisory(), "modified": "2025-01-30T00:00:00Z"}})
    with pytest.raises(ValueError, match="стар|период"):
        apply_update_bundle(db, Handle(db), path)
    assert db.get(VmRefGhsa, ID).summary == "newer"


def test_existing_complete_ghsa_proof_clears_later_partial_without_new_freshness(tmp_path: Path, db_session: Any) -> None:
    db = db_session
    revision = {"revision": "a" * 40}
    seed(db, "ghsa", revision)
    complete = bundle(tmp_path, [{"name": "ghsa", "mode": "unchanged", "base": revision,
                                 "target": revision}], {})
    retime_bundle(complete, "2025-02-10T00:00:00Z")
    apply_update_bundle(db, Handle(db), complete)
    checked = db.get(VmRefSyncState, "ghsa").last_checked_at
    path = period_bundle(tmp_path, [{"name": "ghsa", "mode": "unchanged",
                                    "provenance": {"target_revision": revision["revision"]}}], {})
    apply_update_bundle(db, Handle(db), path)
    assert db.get(VmRefSyncState, "ghsa").partial_window == WINDOW
    assert apply_update_bundle(db, Handle(db), complete) == set()
    sync = db.get(VmRefSyncState, "ghsa")
    assert sync.partial_window is None
    assert sync.last_checked_at == checked
