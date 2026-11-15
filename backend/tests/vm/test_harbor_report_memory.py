"""Harbor report memory must depend on one image, not all images in a sync."""
from __future__ import annotations

import datetime as dt
import tracemalloc
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from api.modules.vm.core.harbor import HarborArtifact, HarborVuln
from api.modules.vm.core.weights import Weights
from api.modules.vm.models import VmImageCve
from api.modules.vm.services import harbor_sync
from tests.vm.test_harbor_sync import CONN, _sync, fake_harbor


class ReportsRead(Exception):
    pass


def test_reports_do_not_accumulate_in_memory(monkeypatch, tmp_path):
    sizes = []
    monkeypatch.setattr(harbor_sync, "get_settings", lambda: SimpleNamespace(data_dir=tmp_path))
    now = dt.datetime.now(dt.UTC)
    artifacts = [HarborArtifact(digest=f"sha256:{i:064x}", tags=("latest",), size=1,
        push_time=now, media_type="application/test", is_index=False, platforms=(),
        scan_status="success", scanned_at=now, scanner="Trivy", trivy_counts={}, reported_total=250)
        for i in range(80)]
    def listing(sync):
        sync.ok_repos = [harbor_sync._Repo("test", f"repository-{i}", [art]) for i, art in enumerate(artifacts)]
    def inspect_reports(sync, planned):
        sizes.append(tracemalloc.get_traced_memory()[0])
        raise ReportsRead()
    def vulnerabilities(*args):
        return [HarborVuln(vuln_id=f"CVE-2026-{10000 + i}", package=f"package-{i}",
            installed_version="1.0", fixed_version="2.0", severity="high", cvss=8.0,
            description=f"{i}:" + "x" * 1024, link=None) for i in range(250)]
    client = SimpleNamespace(vulnerabilities=vulnerabilities, http=SimpleNamespace(close=lambda: None))
    handle = SimpleNamespace(stage=lambda *a, **kw: None, tick=lambda *a, **kw: None)
    monkeypatch.setattr(harbor_sync._Sync, "_list", listing)
    monkeypatch.setattr(harbor_sync._Sync, "_read_policies", lambda _: None)
    monkeypatch.setattr(harbor_sync._Sync, "_known", lambda _: {})
    monkeypatch.setattr(harbor_sync._Sync, "_read_runtime", inspect_reports)
    tracemalloc.start()
    try:
        with pytest.raises(ReportsRead):
            harbor_sync.run_harbor_sync(None, handle, CONN, Weights(), "test", client_factory=lambda _: client)
    finally:
        tracemalloc.stop()
    assert sizes[0] < 3 * 1024 * 1024, f"Retained all reports: {sizes[0] / 1024**2:.1f} MiB"


def test_pair_insertion_is_streamed(db_session, monkeypatch):
    original = harbor_sync.insert_chunked
    seen = []
    def checked(db, model, rows, total, handle, what):
        assert not isinstance(rows, (list, tuple)), "All findings were materialized before insertion"
        seen.append(total)
        return original(db, model, rows, total, handle, what)
    monkeypatch.setattr(harbor_sync, "insert_chunked", checked)
    job, result = _sync(fake_harbor())
    assert job.status == "done", job.error
    assert seen and sum(seen) == result.cves


def test_failure_during_pair_insertion_keeps_old_findings(db_session, monkeypatch):
    from api import jobs
    first, _ = _sync(fake_harbor())
    assert first.status == "done"
    before = list(db_session.execute(select(VmImageCve.__table__).order_by(VmImageCve.image_id, VmImageCve.cve_id, VmImageCve.package, VmImageCve.installed_version).limit(100)))
    # Force reports to be re-read while preserving a real existing inventory.
    monkeypatch.setattr(harbor_sync._Sync, "_known", lambda _: {})
    monkeypatch.setattr(jobs, "INSERT_CHUNK", 1)
    original = jobs.JobHandle.report_progress
    def fail_after_insert(handle, processed, total, message, stage=None):
        if message.startswith("запись пар"):
            raise OSError("simulated storage failure")
        return original(handle, processed, total, message, stage)
    monkeypatch.setattr(jobs.JobHandle, "report_progress", fail_after_insert)
    job, _ = _sync(fake_harbor())
    assert job.status == "failed" and "simulated storage failure" in job.error
    db_session.expire_all()
    after = list(db_session.execute(select(VmImageCve.__table__).order_by(VmImageCve.image_id, VmImageCve.cve_id, VmImageCve.package, VmImageCve.installed_version).limit(100)))
    assert after == before


@pytest.mark.parametrize("outcome", ["done", "cancelled", "disk_full", "write_error"])
def test_report_file_closed_and_old_findings_safe(db_session, monkeypatch, outcome):
    import errno
    from contextlib import contextmanager

    from api import jobs
    first, _ = _sync(fake_harbor())
    assert first.status == "done"
    before = list(db_session.execute(select(VmImageCve.__table__).order_by(
        VmImageCve.image_id, VmImageCve.cve_id, VmImageCve.package, VmImageCve.installed_version).limit(100)))
    opened = []
    real_file = harbor_sync.TemporaryFile
    @contextmanager
    def tracked_file(*args, **kwargs):
        assert kwargs["dir"] == harbor_sync.get_settings().data_dir / "vm"
        with real_file(*args, **kwargs) as stream:
            opened.append(stream)
            if outcome == "disk_full":
                def fail_write(_):
                    raise OSError(errno.ENOSPC, "No space left on device")
                yield SimpleNamespace(tell=stream.tell, write=fail_write)
            else:
                yield stream
    monkeypatch.setattr(harbor_sync, "TemporaryFile", tracked_file)
    monkeypatch.setattr(harbor_sync._Sync, "_known", lambda _: {})
    if outcome == "cancelled":
        def cancel(*_):
            raise jobs.JobCancelled()
        monkeypatch.setattr(harbor_sync._Sync, "_read_runtime", cancel)
    elif outcome == "write_error":
        def fail_insert(db, model, rows, total, handle, what):
            db.execute(model.__table__.insert(), [next(iter(rows))])
            raise OSError("simulated insert failure")
        monkeypatch.setattr(harbor_sync, "insert_chunked", fail_insert)
    job, _ = _sync(fake_harbor())
    assert job.status == (outcome if outcome in {"done", "cancelled"} else "failed")
    assert opened and all(stream.closed for stream in opened)
    if outcome != "done":
        db_session.expire_all()
        after = list(db_session.execute(select(VmImageCve.__table__).order_by(
            VmImageCve.image_id, VmImageCve.cve_id, VmImageCve.package, VmImageCve.installed_version).limit(100)))
        assert after == before


def test_empty_report_removes_old_pairs_and_unicode_roundtrips(db_session, monkeypatch):
    from api.modules.vm.core.harbor import REPORT_MIME
    from tests.vm.test_harbor_sync import STOOLS, _images, _pairs, fixture
    assert _sync(fake_harbor())[0].status == "done"
    monkeypatch.setattr(harbor_sync._Sync, "_known", lambda _: {})
    report = fixture("vulns_stools_web.json")
    row = report[REPORT_MIME]["vulnerabilities"][0]
    row["description"] = 'Описание \n с "кавычками", слешем \\ и Unicode ☃'
    report[REPORT_MIME]["vulnerabilities"] = [row]
    fake = fake_harbor({f"{STOOLS}/stools-web/artifacts/*": report})
    assert _sync(fake)[0].status == "done"
    web = _images(db_session)["stools/stools-web"]
    assert _pairs(db_session, web.id)[0].description == row["description"]
    report[REPORT_MIME]["vulnerabilities"] = []
    assert _sync(fake)[0].status == "done"
    assert _pairs(db_session, web.id) == []
