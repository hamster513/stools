from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from api.modules.vm.services.jobs import JobHandle, run_job, start_job


def test_job_progress_and_done(auth_client: TestClient, db_session: Any) -> None:
    job_id = start_job(db_session, "recalculate", "tester")

    def work(db: Any, h: JobHandle) -> None:
        h.stage("scoring", total=4)
        for i in range(1, 5):
            h.tick(i, message=f"шаг {i}")

    run_job(job_id, work)
    body = auth_client.get(f"/api/vm/jobs/{job_id}").json()
    assert body["status"] == "done" and body["progress"] == 100 and body["stage"] == "done"
    assert body["finished_at"] is not None


def test_job_failure_keeps_first_line_of_error(auth_client: TestClient, db_session: Any) -> None:
    job_id = start_job(db_session, "import_file", "tester")

    def work(db: Any, h: JobHandle) -> None:
        raise ValueError("файл не разобран\nselect * from secrets")

    run_job(job_id, work)
    body = auth_client.get(f"/api/vm/jobs/{job_id}").json()
    assert body["status"] == "failed"
    assert body["error"] == "файл не разобран"


def test_job_cancel(auth_client: TestClient, db_session: Any) -> None:
    job_id = start_job(db_session, "import_vm", "tester")

    def work(db: Any, h: JobHandle) -> None:
        h.stage("parsing", total=10)
        h.tick(1)
        r = auth_client.post(f"/api/vm/jobs/{job_id}/cancel")
        assert r.status_code == 204
        h.tick(2)  # здесь задача должна остановиться
        raise AssertionError("после отмены сюда доходить нельзя")

    run_job(job_id, work)
    body = auth_client.get(f"/api/vm/jobs/{job_id}").json()
    assert body["status"] == "cancelled"
    assert auth_client.post(f"/api/vm/jobs/{job_id}/cancel").status_code == 409


def test_jobs_list_running_first(auth_client: TestClient, db_session: Any) -> None:
    done_id = start_job(db_session, "ref_epss", "tester")
    run_job(done_id, lambda db, h: None)
    running_id = start_job(db_session, "import_vm", "tester")
    ids = [j["id"] for j in auth_client.get("/api/vm/jobs").json()]
    assert ids[0] == running_id and done_id in ids
