"""Задачи модуля VM поверх платформенного механизма (api/jobs.py)."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Iterable

from sqlalchemy.orm import Session

from api.jobs import JobCancelled, JobHandle
from api.jobs import active_job as _active_job
from api.jobs import run_job as _run_job
from api.jobs import start_job as _start_job
from api.modules.vm.models import VmJob

__all__ = ["JobCancelled", "JobHandle", "active_job", "fail_job", "run_job", "start_job"]


def active_job(db: Session, kinds: Iterable[str]) -> VmJob | None:
    return _active_job(db, VmJob, kinds)


def start_job(db: Session, kind: str, started_by: str, message: str = "") -> int:
    return _start_job(db, VmJob, kind, started_by, message)


def run_job(job_id: int, fn: Callable[[Session, JobHandle], None]) -> None:
    _run_job(VmJob, job_id, fn)


def fail_job(db: Session, job_id: int, error: str) -> None:
    """Закрыть задачу, до исполнения которой дело не дошло (загрузка отвергнута):
    иначе она висит «в работе» и блокирует следующую."""
    job = db.get(VmJob, job_id)
    if job is not None:
        job.status = "failed"
        job.error = error
        job.finished_at = dt.datetime.now(dt.UTC)
        db.commit()
