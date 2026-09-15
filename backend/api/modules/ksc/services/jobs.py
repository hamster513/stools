"""Задачи модуля KSC поверх платформенного механизма (api/jobs.py)."""
from __future__ import annotations

from collections.abc import Callable, Iterable

from sqlalchemy.orm import Session

from api.jobs import JobCancelled, JobHandle
from api.jobs import active_job as _active_job
from api.jobs import run_job as _run_job
from api.jobs import start_job as _start_job
from api.modules.ksc.models import KscJob

__all__ = ["JobCancelled", "JobHandle", "active_job", "run_job", "start_job"]


def active_job(db: Session, kinds: Iterable[str]) -> KscJob | None:
    return _active_job(db, KscJob, kinds)


def start_job(db: Session, kind: str, started_by: str, message: str = "") -> int:
    return _start_job(db, KscJob, kind, started_by, message)


def run_job(job_id: int, fn: Callable[[Session, JobHandle], None]) -> None:
    _run_job(KscJob, job_id, fn)
