"""Снятие фоновых задач: живую — флагом, осиротевшую — сразу; уборка при старте API."""
from __future__ import annotations

import logging
import threading
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError, ProgrammingError

from api import jobs
from api.db import base as db_base
from api.db.models import Job
from api.jobs import JobHandle, run_job, start_job
from api.modules.ad.models import AdJob
from api.modules.attack.models import AttackJob
from api.modules.ksc.models import KscJob
from api.modules.vm.models import VmJob

ORPHAN_ERROR = "снята: процесс, который её вёл, перезапускался"
RESTART_ERROR = "прервана: API перезапускался"

#: (модель, адрес списка задач, адрес снятия) — снятие ATT&CK живёт в общих настройках.
CANCEL_PATHS = [
    (AdJob, "/api/ad/jobs", "/api/ad/jobs"),
    (KscJob, "/api/ksc/jobs", "/api/ksc/jobs"),
    (VmJob, "/api/vm/jobs", "/api/vm/jobs"),
    (AttackJob, "/api/attack/jobs", "/api/settings/attack/jobs"),
]


def _row(model: type[Any], job_id: int) -> Any:
    with db_base.get_sessionmaker()() as s:
        job = s.get(model, job_id)
        assert job is not None
        s.expunge(job)
        return job


def test_cancel_live_job_only_raises_the_flag(auth_client: TestClient, db_session: Any) -> None:
    """Задачу ведёт этот процесс: снятие — просьба, остановится она сама между пакетами."""
    job_id = start_job(db_session, AdJob, "collect", "tester", message="dc.example")
    seen: dict[str, Any] = {}

    def work(db: Any, h: JobHandle) -> None:
        h.stage("collecting", total=10)
        assert auth_client.post(f"/api/ad/jobs/{job_id}/cancel").status_code == 204
        seen.update(auth_client.get(f"/api/ad/jobs/{job_id}").json())
        h.tick(1)
        raise AssertionError("после снятия сюда доходить нельзя")

    run_job(AdJob, job_id, work)
    assert seen["status"] == "running" and seen["cancel_requested"] is True and seen["finished_at"] is None
    body = auth_client.get(f"/api/ad/jobs/{job_id}").json()
    assert body["status"] == "cancelled" and body["finished_at"] is not None
    assert body["error"] is None and body["message"] == ""


@pytest.mark.parametrize(("model", "read", "cancel"), CANCEL_PATHS, ids=["ad", "ksc", "vm", "attack"])
def test_cancel_orphaned_job_closes_it_at_once(
    auth_client: TestClient, db_session: Any, model: type[Any], read: str, cancel: str,
) -> None:
    """Задача «идёт», но в процессе её никто не ведёт: флаг проверять некому,
    поэтому она снимается сразу."""
    job_id = start_job(db_session, model, "collect", "tester", message="dc.example")
    assert auth_client.post(f"{cancel}/{job_id}/cancel").status_code == 204
    body = auth_client.get(f"{read}/{job_id}").json()
    assert body["status"] == "cancelled", body
    assert body["finished_at"] is not None
    # Причина снятия — в error; message (что делала задача) не затирается.
    assert (body["error"], body["message"]) == (ORPHAN_ERROR, "dc.example")
    assert auth_client.post(f"{cancel}/{job_id}/cancel").status_code == 409
    assert auth_client.post(f"{cancel}/999999/cancel").status_code == 404


def test_job_cancelled_before_start_does_not_run(auth_client: TestClient, db_session: Any) -> None:
    """Снятие успело раньше, чем фоновый поток взял задачу: работа не начинается."""
    job_id = start_job(db_session, AdJob, "collect", "tester")
    assert auth_client.post(f"/api/ad/jobs/{job_id}/cancel").status_code == 204

    def work(db: Any, h: JobHandle) -> None:
        raise AssertionError("снятая задача не должна исполняться")

    run_job(AdJob, job_id, work)
    job = _row(AdJob, job_id)
    assert job.status == "cancelled" and job.error == ORPHAN_ERROR


def test_cancel_racing_with_start_is_consistent(app_settings: Any, db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Гонка: снятие уже решило, что задачу никто не ведёт, а поток как раз её берёт.
    Строку держит блокировка снятия, поэтому поток видит уже снятую задачу и работу не
    начинает — а не исполняет её до «готово» под сообщением о сироте."""
    job_id = start_job(db_session, AdJob, "collect", "tester")
    started = threading.Event()
    original = jobs.is_live

    def work(db: Any, h: JobHandle) -> None:
        started.set()

    thread = threading.Thread(target=run_job, args=(AdJob, job_id, work))

    def is_live_then_start(model: type[Any], jid: int) -> bool:
        live = original(model, jid)
        thread.start()  # поток регистрируется и читает строку, пока снятие не зафиксировано
        started.wait(timeout=1.0)
        return live

    monkeypatch.setattr(jobs, "is_live", is_live_then_start)
    with db_base.get_sessionmaker()() as s:
        jobs.cancel_job(s, AdJob, job_id)
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert not started.is_set(), "снятая задача не должна исполняться"
    job = _row(AdJob, job_id)
    assert (job.status, job.error) == ("cancelled", ORPHAN_ERROR)


def test_live_registry_forgets_finished_jobs(db_session: Any) -> None:
    job_id = start_job(db_session, AdJob, "collect", "tester")
    inside: list[bool] = []
    run_job(AdJob, job_id, lambda db, h: inside.append(jobs.is_live(AdJob, job_id)))
    assert inside == [True]
    assert not jobs.is_live(AdJob, job_id)
    # Ключ — таблица и id: тот же номер в другой таблице — другая задача.
    failing = start_job(db_session, KscJob, "collect", "tester")

    def boom(db: Any, h: JobHandle) -> None:
        assert jobs.is_live(KscJob, failing) and not jobs.is_live(AdJob, failing)
        raise RuntimeError("сбой")

    run_job(KscJob, failing, boom)
    assert not jobs.is_live(KscJob, failing)


def test_startup_fails_jobs_left_running(app_settings: Any, db_session: Any) -> None:
    """Потоки задач живут в процессе API: после его перезапуска «идущие» задачи
    никто не ведёт, и при старте они закрываются как прерванные — во всех таблицах."""
    running = {model: start_job(db_session, model, "collect", "tester") for model in (AdJob, KscJob, VmJob, AttackJob)}
    done_id = start_job(db_session, AdJob, "collect", "tester")
    run_job(AdJob, done_id, lambda db, h: None)
    siem = Job(stage="parsing", status="running", progress=40)
    db_session.add(siem)
    db_session.commit()
    siem_id = siem.id

    from api.main import app

    with TestClient(app):
        pass

    for model, job_id in running.items():
        job = _row(model, job_id)
        assert (job.status, job.error) == ("failed", RESTART_ERROR), model.__name__
        assert job.finished_at is not None, model.__name__
    siem_job = _row(Job, siem_id)
    assert (siem_job.status, siem_job.error) == ("failed", RESTART_ERROR)
    done = _row(AdJob, done_id)
    assert done.status == "done" and done.error is None


class _Unreachable:
    """Сессия, у которой каждый запрос падает ошибкой `exc`."""

    def __init__(self, exc: Exception) -> None:
        self.exc = exc
        self.executed = 0

    def execute(self, *args: Any, **kwargs: Any) -> Any:
        self.executed += 1
        raise self.exc

    def commit(self) -> None:
        raise AssertionError("после ошибки запроса commit не вызывается")

    def rollback(self) -> None:
        pass


def test_startup_cleanup_stops_when_database_is_unreachable(caplog: pytest.LogCaptureFixture) -> None:
    """База недоступна: остальные таблицы не трогаются (каждая ждала бы таймаут подключения), одно предупреждение."""
    db = _Unreachable(OperationalError("UPDATE", {}, ConnectionRefusedError("connection refused")))
    with caplog.at_level(logging.WARNING, logger="api.jobs"):
        jobs.fail_interrupted_jobs(db)  # type: ignore[arg-type]
    assert db.executed == 1
    assert len(caplog.records) == 1
    # Ошибка одной таблицы (миграция не применена) по-прежнему не мешает остальным.
    missing = _Unreachable(ProgrammingError("UPDATE", {}, Exception("relation does not exist")))
    jobs.fail_interrupted_jobs(missing)  # type: ignore[arg-type]
    assert missing.executed == len(jobs.job_models())
