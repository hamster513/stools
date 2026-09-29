"""Прогресс записи находок KSC: пакетами, отдельной транзакцией, без половины снапшота."""
from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from api import jobs
from api.db import base as db_base
from api.modules.ksc.models import KscFinding, KscHost, KscJob, KscServer, KscSnapshot
from tests.ksc.synthetic import build_export


def _upload(client: TestClient) -> dict[str, Any]:
    r = client.post("/api/ksc/snapshots/file", files={"file": ("ksc.json", json.dumps(build_export()).encode(), "application/json")})
    assert r.status_code == 202, r.text
    return client.get(f"/api/ksc/jobs/{r.json()['job_id']}").json()


def _count(model: type[Any]) -> int:
    with db_base.get_sessionmaker()() as s:
        return int(s.scalar(select(func.count()).select_from(model)) or 0)


def _record(monkeypatch: pytest.MonkeyPatch, fail_after: int | None = None) -> list[tuple[int, int, str, int, int]]:
    """Подменяет `report_progress`: запоминает (processed, total, message) и то, что
    видно снаружи сразу после вызова, — processed строки задачи и число находок."""
    calls: list[tuple[int, int, str, int, int]] = []
    original = jobs.JobHandle.report_progress

    def spy(self: jobs.JobHandle, processed: int, total: int, message: str) -> None:
        original(self, processed, total, message)
        with db_base.get_sessionmaker()() as s:
            job = s.get(KscJob, self.id)
            assert job is not None
            outside = int(s.scalar(select(func.count()).select_from(KscFinding)) or 0)
            calls.append((processed, total, message, job.processed, outside))
        if fail_after is not None and len(calls) == fail_after:
            raise RuntimeError("сбой посреди записи")

    monkeypatch.setattr(jobs.JobHandle, "report_progress", spy)
    return calls


def test_findings_written_in_chunks_with_progress_to_total(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jobs, "INSERT_CHUNK", 7)
    calls = _record(monkeypatch)
    job = _upload(auth_client)
    assert job["status"] == "done", job
    total = _count(KscFinding)
    assert total > 10
    assert [c[0] for c in calls] == [*range(7, total, 7), total]
    assert all(c[1] == total for c in calls)
    # Прогресс виден снаружи сразу, а находки — нет: основная транзакция не зафиксирована.
    assert all(c[3] == c[0] and c[4] == 0 for c in calls)
    assert calls[-1][2] == f"запись находок {total} из {total}"
    # Последний `stage("done")` обнуляет счётчики в строке: копия задачи в основной
    # сессии знала о записанном в обход неё прогрессе и не пропустила UPDATE.
    assert job["progress"] == 100 and job["processed"] == 0 and job["total"] is None
    snaps = auth_client.get("/api/ksc/snapshots").json()
    assert snaps[0]["findings"] == total


def test_failure_mid_write_leaves_no_snapshot_but_keeps_progress(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jobs, "INSERT_CHUNK", 5)
    calls = _record(monkeypatch, fail_after=2)
    job = _upload(auth_client)
    assert job["status"] == "failed" and job["error"] == "сбой посреди записи", job
    assert job["stage"] == "persisting" and job["processed"] == 10 and job["total"] == calls[0][1] > 10
    assert job["progress"] == 10 * 100 // calls[0][1]
    assert _count(KscFinding) == 0 and _count(KscSnapshot) == 0 and _count(KscServer) == 0 and _count(KscHost) == 0


def test_cancel_between_chunks_rolls_back_everything(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Снятие посреди записи находок: задача останавливается после текущего пакета,
    основная транзакция откатывается — ни снапшота, ни находок."""
    monkeypatch.setattr(jobs, "INSERT_CHUNK", 5)
    calls = _record(monkeypatch)
    original = jobs.JobHandle.report_progress

    def cancel_after_first(self: jobs.JobHandle, processed: int, total: int, message: str) -> None:
        original(self, processed, total, message)
        if len(calls) == 1:
            assert auth_client.post(f"/api/ksc/jobs/{self.id}/cancel").status_code == 204

    monkeypatch.setattr(jobs.JobHandle, "report_progress", cancel_after_first)
    job = _upload(auth_client)
    assert job["status"] == "cancelled" and job["error"] is None, job
    assert len(calls) == 1 and job["processed"] == 5
    assert _count(KscFinding) == 0 and _count(KscSnapshot) == 0 and _count(KscServer) == 0 and _count(KscHost) == 0


def test_reanalyze_reports_persisting_progress(auth_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    assert _upload(auth_client)["status"] == "done"
    snap = auth_client.get("/api/ksc/snapshots").json()[0]
    monkeypatch.setattr(jobs, "INSERT_CHUNK", 7)
    calls = _record(monkeypatch)
    r = auth_client.post(f"/api/ksc/snapshots/{snap['id']}/reanalyze")
    job = auth_client.get(f"/api/ksc/jobs/{r.json()['job_id']}").json()
    assert job["status"] == "done", job
    assert calls and calls[-1][0] == calls[-1][1] == snap["findings"] == _count(KscFinding)
    # Старые находки снапшота остаются видимыми, пока новая запись не зафиксирована.
    assert all(c[4] == snap["findings"] for c in calls)
