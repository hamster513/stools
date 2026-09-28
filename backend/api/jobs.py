"""Фоновые задачи модулей — платформенный механизм.

Задача исполняется функцией `fn(db, handle)` в потоке `BackgroundTasks`
со своей сессией: сессия запроса к этому моменту уже закрыта. Прогресс
пишется в строку задачи на каждом `tick`, отмена — флаг в той же строке,
который задача проверяет между пакетами через `handle.cancelled()`.

Таблица у каждого модуля своя (`vm_job`, `ad_job`): их история и права
не смешиваются, а колонки одинаковы — `JobColumns`.
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Iterable
from typing import Any

from sqlalchemy import Boolean, DateTime, Integer, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from api.db.base import get_sessionmaker
from api.db.models import _utcnow


class JobColumns:
    """Общие колонки таблицы задач; наследуется вместе с Base."""

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    stage: Mapped[str] = mapped_column(String(32), default="pending")
    #: running | done | failed | cancelled
    status: Mapped[str] = mapped_column(String(16), default="running", index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    processed: Mapped[int] = mapped_column(Integer, default=0)
    total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    message: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_by: Mapped[str] = mapped_column(String(255), default="")



class JobCancelled(Exception):
    """Задача остановлена по просьбе человека; не ошибка."""


class JobHandle:
    def __init__(self, db: Session, job: JobColumns) -> None:
        self._db = db
        self._job = job

    @property
    def id(self) -> int:
        return self._job.id

    def stage(self, name: str, total: int | None = None, message: str = "") -> None:
        self._job.stage = name
        self._job.total = total
        self._job.processed = 0
        self._job.progress = 0
        self._job.message = message
        self._db.commit()

    def tick(self, processed: int, message: str | None = None, total: int | None = None) -> None:
        """Обновить прогресс. Проверка отмены здесь же: между пакетами
        строк — единственное место, где задачу можно прервать безопасно."""
        self._job.processed = processed
        if total is not None:
            self._job.total = total
        if message is not None:
            self._job.message = message
        if self._job.total:
            self._job.progress = min(100, int(processed * 100 / self._job.total))
        self._db.commit()
        if self.cancelled():
            raise JobCancelled()

    def cancelled(self) -> bool:
        self._db.refresh(self._job, attribute_names=["cancel_requested"])
        return bool(self._job.cancel_requested)


def active_job[J: JobColumns](db: Session, model: type[J], kinds: Iterable[str]) -> J | None:
    return db.execute(
        select(model).where(model.kind.in_(list(kinds)), model.status == "running").order_by(model.id.desc())
    ).scalars().first()


def start_job[J: JobColumns](db: Session, model: type[J], kind: str, started_by: str, message: str = "") -> int:
    job = model(kind=kind, stage="pending", status="running", message=message, started_by=started_by)  # type: ignore[call-arg]
    db.add(job)
    db.commit()
    return job.id


def safe_error(exc: Exception) -> str:
    """Текст ошибки без хвоста драйвера: в нём могут быть данные запроса."""
    text = str(exc).strip().splitlines()[0] if str(exc).strip() else exc.__class__.__name__
    return text[:500]


def run_job(model: type[Any], job_id: int, fn: Callable[[Session, JobHandle], None]) -> None:
    session_factory = get_sessionmaker()
    with session_factory() as db:
        job = db.get(model, job_id)
        if job is None:
            return
        handle = JobHandle(db, job)
        try:
            fn(db, handle)
            db.rollback()
            job = db.get(model, job_id)
            assert job is not None
            job.status = "done"
            job.stage = "done"
            job.progress = 100
        except JobCancelled:
            db.rollback()
            job = db.get(model, job_id)
            assert job is not None
            job.status = "cancelled"
        except Exception as exc:  # noqa: BLE001 — любая ошибка задачи должна осесть в её строке
            db.rollback()
            job = db.get(model, job_id)
            assert job is not None
            job.status = "failed"
            job.error = safe_error(exc)
        job.finished_at = dt.datetime.now(dt.UTC)
        db.commit()


# ---- Роутер задач: одинаков для всех модулей ------------------------------


def cancel_job(db: Session, model: type[Any], job_id: int) -> None:
    """Попросить идущую задачу остановиться: 404 — задачи нет, 409 — уже завершена."""
    from fastapi import HTTPException, status

    job = db.get(model, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="задача не найдена")
    if job.status != "running":
        raise HTTPException(status.HTTP_409_CONFLICT, detail="задача уже завершена")
    job.cancel_requested = True
    db.commit()


def make_jobs_router(model: type[Any], tag: str, *, cancel: bool = True) -> Any:
    """`GET /jobs`, `GET /jobs/{id}` и (`cancel=True`) `POST /jobs/{id}/cancel` для таблицы модуля.
    `cancel=False` — отмена живёт в другом месте (задания ATT&CK: их запускает и отменяет
    администратор в общих настройках)."""
    import datetime as _dt

    from fastapi import APIRouter, Depends, HTTPException, Query, status
    from pydantic import BaseModel, ConfigDict

    from api.db.base import get_db
    from api.db.models import AppUser
    from api.deps import get_current_user

    class JobView(BaseModel):
        model_config = ConfigDict(from_attributes=True)

        id: int
        kind: str
        stage: str
        status: str
        progress: int
        processed: int
        total: int | None = None
        message: str
        error: str | None = None
        cancel_requested: bool
        started_at: _dt.datetime
        finished_at: _dt.datetime | None = None
        started_by: str

    router = APIRouter(prefix="/jobs", tags=[tag])

    @router.get("", response_model=list[JobView])
    def list_jobs(
        limit: int = Query(default=50, ge=1, le=200),
        db: Session = Depends(get_db),
        _user: AppUser = Depends(get_current_user),
    ) -> list[Any]:
        running = db.execute(select(model).where(model.status == "running").order_by(model.id.desc())).scalars().all()
        finished = db.execute(select(model).where(model.status != "running").order_by(model.id.desc()).limit(limit)).scalars().all()
        return list(running) + list(finished)

    @router.get("/{job_id}", response_model=JobView)
    def get_job(job_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> Any:
        job = db.get(model, job_id)
        if job is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="задача не найдена")
        return job

    if cancel:
        @router.post("/{job_id}/cancel", status_code=status.HTTP_204_NO_CONTENT)
        def cancel_running(job_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> None:
            cancel_job(db, model, job_id)

    return router
