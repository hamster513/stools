"""A second connection can observe the write, but cannot see an unfinished snapshot."""
import time
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import event, select, text

from api.db.base import get_engine
from api.modules.vm.models import VmHost, VmHostCve
from api.modules.vm.services.importer import run_import
from api.modules.vm.services.jobs import run_job, start_job
from api.modules.vm.services.settings import VmSettings
from tests.vm.test_import import _upload

CSV = b"@Host;Host.@Vulners.CVEs\nnew-host;CVE-2026-12345\nnew-host;CVE-2026-12345\n"


def test_running_import_exposes_its_step_and_real_lock(auth_client, db_session, tmp_path):
    assert _upload(auth_client, "hosts.csv")["status"] == "done"
    path = tmp_path / "next.csv"
    existing_cve = db_session.scalars(select(VmHostCve.cve_id).limit(1)).one()
    path.write_bytes(CSV.replace(b"CVE-2026-12345", existing_cve.encode()))
    job_id = start_job(db_session, "import_file", "test")
    other = start_job(db_session, "import_vm", "test")
    with ThreadPoolExecutor(max_workers=1) as pool, get_engine().connect() as blocker:
        # The foreign key check waits here only when the worker inserts the new pairs.
        blocker.execute(text("SELECT cve_id FROM vm_cve WHERE cve_id=:id LIMIT 1 FOR UPDATE"), {"id": existing_cve})
        worker = pool.submit(run_job, job_id, lambda db, handle: run_import(
            db, handle, "file", path, VmSettings(), tmp_path,
        ))
        try:
            deadline = time.monotonic() + 6
            while True:
                job = auth_client.get(f"/api/vm/jobs/{job_id}").json()
                if (job.get("sql_activity") or {}).get("state") == "lock":
                    break
                assert time.monotonic() < deadline, (job["stage"], job["message"], job.get("sql_activity"))
                time.sleep(0.04)
            assert (job["stage"], job["processed"], job["total"]) == ("writing", 4, 7)
            assert "уникальные пары" in job["message"].lower() and "2" in job["message"]
            assert job["sql_activity"]["pid"] > 0 and job["sql_activity"]["seconds"] >= 0
            assert set(job["sql_activity"]) == {"pid", "state", "seconds"}
            page = {j["id"]: j for j in auth_client.get("/api/vm/jobs").json()}
            assert page[job_id]["sql_activity"]["pid"] == job["sql_activity"]["pid"]
            assert page[other]["sql_activity"] is None
            assert "new-host" not in db_session.scalars(select(VmHost.hostname).limit(10)).all()
        finally:
            blocker.rollback()
        worker.result(timeout=10)
    done = auth_client.get(f"/api/vm/jobs/{job_id}").json()
    assert done["status"] == "done", done["error"]
    assert done["sql_activity"] is None
    assert auth_client.get("/api/vm/import").json()["last"]["pairs"] == 1
    with get_engine().connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM pg_stat_activity WHERE application_name = :name"),
                            {"name": f"stools.vm.import.{job_id}"}).scalar_one() == 0


def test_failed_pair_write_reports_operation_and_keeps_previous_snapshot(auth_client, db_session):
    assert _upload(auth_client, "hosts.csv")["status"] == "done"
    old = list(db_session.execute(select(VmHost.id, VmHost.hostname).order_by(VmHost.id).limit(10)))
    engine = get_engine()

    def fail_pair_insert(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO vm_host_cve "):
            raise RuntimeError("test failure during pair insert")

    event.listen(engine, "before_cursor_execute", fail_pair_insert)
    try:
        job = _upload(auth_client, "next.csv", CSV)
    finally:
        event.remove(engine, "before_cursor_execute", fail_pair_insert)
    assert job["status"] == "failed" and job["stage"] == "writing"
    assert "уникальн" in job["message"].lower() and "2" in job["message"]
    assert list(db_session.execute(select(VmHost.id, VmHost.hostname).order_by(VmHost.id).limit(10))) == old
