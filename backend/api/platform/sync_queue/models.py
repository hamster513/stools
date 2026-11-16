"""Persisted requests and immutable execution plans for synchronization."""
import datetime as dt
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base
from api.jobs import JobColumns


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class SyncTaskConfig(Base):
    __tablename__ = "platform_sync_task_config"
    key: Mapped[str] = mapped_column(String(160), primary_key=True)
    dependencies: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SyncRun(Base):
    __tablename__ = "platform_sync_run"
    __table_args__ = (Index("ix_sync_run_queue", "status", "id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actor: Mapped[str] = mapped_column(String(255))
    origin: Mapped[str] = mapped_column(String(16), default="manual")
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(16), default="queued")
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class SyncStep(Base):
    __tablename__ = "platform_sync_step"
    __table_args__ = (Index("ix_sync_step_task_status", "key", "status"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("platform_sync_run.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(160))
    title: Mapped[str] = mapped_column(String(512))
    module: Mapped[str] = mapped_column(String(32))
    kind: Mapped[str] = mapped_column(String(32))
    target_id: Mapped[int] = mapped_column(Integer)
    is_root: Mapped[bool] = mapped_column(Boolean, default=False)
    dependencies: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="queued")
    message: Mapped[str] = mapped_column(Text, default="")
    job_model: Mapped[str | None] = mapped_column(String(80))
    job_id: Mapped[int | None] = mapped_column(Integer)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    checked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON)


class SyncJob(JobColumns, Base):
    __tablename__ = "platform_sync_job"
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON)
