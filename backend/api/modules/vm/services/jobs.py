"""Задачи модуля VM поверх платформенного механизма (api/jobs.py)."""
from __future__ import annotations

from collections.abc import Callable, Iterable

from sqlalchemy import text
from sqlalchemy.orm import Session

from api.jobs import JobCancelled, JobHandle
from api.jobs import active_job as _active_job
from api.jobs import fail_job as _fail_job
from api.jobs import run_job as _run_job
from api.jobs import start_job as _start_job
from api.modules.vm.core.refs import REF_NAMES
from api.modules.vm.models import VmJob

__all__ = ["DATA_KINDS", "JobCancelled", "JobHandle", "active_job", "fail_job", "lock_job_start", "run_job", "start_job"]

#: Задачи, которые заменяют или пересчитывают пары: массовая смена статусов с ними одновременно не идёт.
#: Архив справочников — тоже: в конце он пересчитывает риск всех пар. Синхронизация образов
#: из Harbor пополняет витрину CVE и пересчитывает риск пар образов.
REF_KINDS = tuple(f"ref_{name}" for name in REF_NAMES)
DATA_KINDS = ("import_vm", "import_file", "recalculate", "ref_bundle", "harbor_sync", *REF_KINDS)


def lock_job_start(db: Session) -> None:
    """Проверка «не идёт ли мешающая задача» и заведение своей — под одной транзакционной
    блокировкой: два запуска не проскочат проверку оба. Отпускается commit-ом `start_job`."""
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('vm_job_start'))"))


def active_job(db: Session, kinds: Iterable[str]) -> VmJob | None:
    return _active_job(db, VmJob, kinds)


def start_job(db: Session, kind: str, started_by: str, message: str = "") -> int:
    return _start_job(db, VmJob, kind, started_by, message)


def run_job(job_id: int, fn: Callable[[Session, JobHandle], None]) -> None:
    _run_job(VmJob, job_id, fn)


def fail_job(db: Session, job_id: int, error: str) -> None:
    _fail_job(db, VmJob, job_id, error)
