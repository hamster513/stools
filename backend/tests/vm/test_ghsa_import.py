"""Full GHSA snapshots preserve OSV identities and replace atomically."""
from __future__ import annotations

import json
import struct
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.jobs import JobCancelled
from api.modules.vm.core import ghsa
from api.modules.vm.ghsa_models import VmRefGhsa, VmRefGhsaAlias, VmRefGhsaPackage
from api.modules.vm.models import VmRefState
from api.modules.vm.services.bundle import classify
from api.modules.vm.services.ghsa_import import load_ghsa

ID = "GHSA-2345-6789-cfgh"
OTHER = "GHSA-cfgh-jmpq-rvwx"


def advisory(identifier: str = ID) -> dict[str, Any]:
    return {
        "id": identifier, "summary": "Package flaw", "details": "Full explanation",
        "published": "2025-01-01T12:00:00Z", "modified": "2025-02-02T12:00:00+00:00",
        "aliases": ["CVE-2025-1234", "CVE-2025-1234"], "related": ["CVE-2025-9999"],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-79"]},
        "references": [{"type": "ADVISORY", "url": "https://github.com/advisories/" + identifier}],
        "affected": [{"package": {"ecosystem": "npm", "name": "example", "purl": "pkg:npm/example"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
                      "versions": ["1.0.0"]}],
    }


def archive(tmp_path: Path, rows: list[dict[str, Any] | bytes], *, reviewed: bool = True) -> Path:
    path = tmp_path / "advisory-database.zip"
    folder = "github-reviewed" if reviewed else "unreviewed"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for i, row in enumerate(rows):
            identifier = row["id"] if isinstance(row, dict) else "GHSA-2222-3333-4444"
            zf.writestr(f"advisory-database-main/advisories/{folder}/2025/01/{identifier}/{identifier}.json",
                        json.dumps(row) if isinstance(row, dict) else row)
    return path


class Handle:
    def __init__(self, db: Any = None, cancel: bool = False) -> None:
        self.db, self.cancel = db, cancel

    def tick(self, *args: Any, **kwargs: Any) -> None:
        if self.db is not None:
            self.db.commit()  # Real JobHandle commits its session for progress.
        if self.cancel:
            raise JobCancelled()


@pytest.fixture
def analyze_snapshots(db_session: Any) -> Iterator[list[tuple[str, list[str]]]]:
    observed: list[tuple[str, list[str]]] = []
    engine = db_session.get_bind()

    def capture(_conn: Any, _cursor: Any, statement: str, _parameters: Any, _context: Any, _many: bool) -> None:
        if statement.strip().upper().startswith("ANALYZE "):
            # A separate connection must see the replacement before ANALYZE;
            # otherwise statistics were collected inside the publishing transaction.
            with Session(engine) as reader:
                observed.append((statement, list(reader.scalars(select(VmRefGhsa.ghsa_id)))))

    event.listen(engine, "before_cursor_execute", capture)
    try:
        yield observed
    finally:
        event.remove(engine, "before_cursor_execute", capture)


def test_parser_preserves_aliases_ranges_and_metrics(tmp_path: Path) -> None:
    record = next(ghsa.iter_advisories(archive(tmp_path, [advisory()])))
    assert record.ghsa_id == ID
    assert record.aliases == ["CVE-2025-1234"]
    assert record.cvss == 9.8 and record.cvss_version == "3.1"
    assert record.reviewed and record.severity == "critical"
    assert record.cwes == ["CWE-79"]
    assert record.published is not None and record.published.utcoffset().total_seconds() == 0
    assert record.packages[0]["fixed_versions"] == ["1.2.3"]
    assert record.packages[0]["ranges"] == advisory()["affected"][0]["ranges"]


def test_ghsa_only_unknown_severity_and_withdrawn(tmp_path: Path) -> None:
    row = advisory()
    row.update(aliases=[], severity=[], database_specific={}, withdrawn="2025-03-03T00:00:00Z")
    record = next(ghsa.iter_advisories(archive(tmp_path, [row], reviewed=False)))
    assert not record.reviewed and record.withdrawn is not None
    assert record.aliases == [] and record.cvss is None and record.severity == "unknown"


def test_archive_limits_and_unsafe_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = archive(tmp_path, [advisory()])
    monkeypatch.setattr(ghsa, "MAX_MEMBER_BYTES", 10)
    with pytest.raises(ValueError, match="limit|лимит"):
        list(ghsa.iter_advisories(path))
    monkeypatch.undo()
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("../escape.json", "{}")
    with pytest.raises(ValueError, match="path|путь"):
        list(ghsa.iter_advisories(path))


def test_bundle_classifies_official_archive() -> None:
    assert classify("refs/advisory-database.zip") == "ghsa"
    assert classify("advisory-database-main.zip") == "ghsa"


@pytest.mark.parametrize("failure", ["malformed", "empty", "cancelled", "duplicate"])
def test_failed_import_preserves_old_snapshot(
    tmp_path: Path, db_session: Any, monkeypatch: pytest.MonkeyPatch, failure: str,
    analyze_snapshots: list[tuple[str, list[str]]],
) -> None:
    from api.modules.vm.services import ghsa_import
    monkeypatch.setattr(ghsa_import, "BATCH_SIZE", 1)
    load_ghsa(db_session, archive(tmp_path, [advisory()]), Handle(db_session), "file", "old")
    analyze_snapshots.clear()
    row = advisory(OTHER)
    rows: list[dict[str, Any] | bytes] = [row]
    if failure == "malformed":
        rows.append(b"{broken")
    elif failure == "empty":
        rows = []
    elif failure == "duplicate":
        rows.append(row)
    with pytest.raises((ValueError, IntegrityError, JobCancelled)):
        load_ghsa(db_session, archive(tmp_path, rows), Handle(db_session, failure == "cancelled"), "file", "new")
    db_session.expire_all()
    assert list(db_session.scalars(select(VmRefGhsa.ghsa_id))) == [ID]
    assert list(db_session.scalars(select(VmRefGhsaAlias.alias))) == ["CVE-2025-1234"]
    assert db_session.get(VmRefGhsaPackage, (ID, 0)).name == "example"
    assert db_session.get(VmRefState, "ghsa").detail == "old"
    assert analyze_snapshots == []


def test_successful_snapshot_replaces_children_and_state(
    tmp_path: Path, db_session: Any, analyze_snapshots: list[tuple[str, list[str]]],
) -> None:
    load_ghsa(db_session, archive(tmp_path, [advisory()]), Handle(db_session), "file", "old")
    analyze_snapshots.clear()
    row = advisory(OTHER)
    row.update(aliases=[], affected=[])
    assert load_ghsa(db_session, archive(tmp_path, [row]), Handle(db_session), "network", "new") == 1
    db_session.expire_all()
    assert list(db_session.scalars(select(VmRefGhsa.ghsa_id))) == [OTHER]
    assert list(db_session.scalars(select(VmRefGhsaAlias.alias))) == []
    assert list(db_session.scalars(select(VmRefGhsaPackage.name))) == []
    assert db_session.get(VmRefState, "ghsa").detail == "new"
    assert len(analyze_snapshots) == 1
    statement, committed_ids = analyze_snapshots[0]
    assert statement == "ANALYZE vm_ref_ghsa, vm_ref_ghsa_alias, vm_ref_ghsa_package"
    assert committed_ids == [OTHER]


@pytest.mark.parametrize("limit", ["MAX_ENTRIES", "MAX_TOTAL_BYTES", "MAX_ARCHIVE_BYTES", "MAX_CENTRAL_BYTES"])
def test_archive_aggregate_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit: str) -> None:
    path = archive(tmp_path, [advisory()])
    monkeypatch.setattr(ghsa, limit, 0)
    with pytest.raises(ValueError, match="limit"):
        list(ghsa.iter_advisories(path))


def test_cvss_four_preferred_and_invalid_vector_stays_unknown(tmp_path: Path) -> None:
    row = advisory()
    row["severity"].append({"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"})
    record = next(ghsa.iter_advisories(archive(tmp_path, [row])))
    assert record.cvss_version == "4.0" and record.cvss == 10.0
    row["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}]
    record = next(ghsa.iter_advisories(archive(tmp_path, [row])))
    assert record.cvss is None and record.cvss_vector == "CVSS:3.1/AV:N"


def test_ghsa_nested_bundle_upload_and_reference_state(tmp_path: Path, auth_client: Any, db_session: Any) -> None:
    import io

    from api.modules.vm.models import VmJob
    nested = archive(tmp_path, [advisory()]).read_bytes()
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as bundle:
        bundle.writestr("advisory-database.zip", nested)
    response = auth_client.post("/api/vm/refs/bundle/upload", files={"file": ("refs.zip", data.getvalue(), "application/zip")})
    assert response.status_code == 202, response.text
    db_session.expire_all()
    job = db_session.get(VmJob, response.json()["job_id"])
    assert job.status == "done", job.error
    state = db_session.get(VmRefState, "ghsa")
    assert state.records == 1 and state.source == "bundle"
    refs = {row["name"]: row for row in auth_client.get("/api/vm/refs").json()}
    assert refs["ghsa"]["records"] == 1
    assert refs["ghsa"]["url"].endswith("/github/advisory-database/zip/refs/heads/main")


@pytest.mark.parametrize("second", ["advisory-database-main.zip", "other/advisory-database.zip"])
def test_bundle_chooses_one_ghsa_snapshot(second: str) -> None:
    from api.modules.vm.services.bundle import _plan
    selected, skipped = _plan([zipfile.ZipInfo("advisory-database.zip"), zipfile.ZipInfo(second)])
    assert len(selected) == 1 and selected[0][0] == "ghsa"
    assert len(skipped) == 1


@pytest.mark.parametrize("chunked", [False, True])
def test_ghsa_download_has_separate_bounded_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, chunked: bool) -> None:
    import httpx

    from api.modules.vm.services import refs
    monkeypatch.setattr(refs, "MAX_FEED_BYTES", 10)
    monkeypatch.setattr(refs, "MAX_GHSA_FEED_BYTES", 20)
    class DownloadHandle(Handle):
        def stage(self, *args: Any, **kwargs: Any) -> None:
            pass
    def factory() -> httpx.Client:
        response = httpx.Response(200, content=iter([b"x" * 11, b"x" * 11]) if chunked else b"x" * 22)
        return httpx.Client(transport=httpx.MockTransport(lambda request: response))
    with pytest.raises(ValueError, match="больше лимита"):
        refs.run_ref_download(None, DownloadHandle(), "ghsa", None, http_factory=factory, mode="full")
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"x" * 15))) as client:
        assert refs.download(refs.URLS["ghsa"], tmp_path / "feed", DownloadHandle(), client, max_bytes=20) == 15
        with pytest.raises(ValueError, match="больше лимита"):
            refs.download(refs.URLS["epss"], tmp_path / "feed", DownloadHandle(), client)


def test_archive_metadata_is_bounded_before_zipfile_allocation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = archive(tmp_path, [advisory()])
    monkeypatch.setattr(ghsa, "MAX_ENTRIES", 0)
    def unexpected(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("ZipFile constructed before metadata bounds")
    monkeypatch.setattr(zipfile, "ZipFile", unexpected)
    with pytest.raises(ValueError, match="limit"):
        list(ghsa.iter_advisories(path))


def test_archive_zip64_with_comment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(zipfile, "ZIP_FILECOUNT_LIMIT", 0)
    path = archive(tmp_path, [advisory()])
    with zipfile.ZipFile(path, "a") as zf:
        zf.comment = b"official snapshot comment"
    raw = bytearray(path.read_bytes())
    footer = raw.rfind(b"PK\x05\x06")
    struct.pack_into("<2H", raw, footer + 8, 65535, 65535)
    path.write_bytes(raw)
    assert next(ghsa.iter_advisories(path)).ghsa_id == ID



def test_import_flushes_large_records_before_row_batch_limit(tmp_path: Path, db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from api.modules.vm.services import ghsa_import
    monkeypatch.setattr(ghsa_import, "MAX_BATCH_BYTES", 1)
    monkeypatch.setattr(ghsa_import, "BATCH_SIZE", 1000)
    ticks: list[int] = []
    class Progress(Handle):
        def tick(self, processed: int, **kwargs: Any) -> None:
            ticks.append(processed)
            super().tick(processed, **kwargs)
    load_ghsa(db_session, archive(tmp_path, [advisory(), advisory(OTHER)]), Progress(db_session), "file")
    assert 1 in ticks and 2 in ticks



def test_archive_rejects_false_directory_counts_before_allocation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = archive(tmp_path, [advisory()])
    raw = bytearray(path.read_bytes())
    footer = raw.rfind(b"PK\x05\x06")
    struct.pack_into("<2H", raw, footer + 8, 0, 0)
    path.write_bytes(raw)
    def unexpected(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("ZipFile constructed before directory validation")
    monkeypatch.setattr(zipfile, "ZipFile", unexpected)
    with pytest.raises(ValueError, match="entry count"):
        list(ghsa.iter_advisories(path))
