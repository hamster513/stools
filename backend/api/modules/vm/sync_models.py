"""Trusted upstream checkpoints, independently of local import timestamps."""
from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base


class VmRefSyncState(Base):
    __tablename__ = "vm_ref_sync_state"

    name: Mapped[str] = mapped_column(String(16), primary_key=True)
    checkpoint: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    baseline_years: Mapped[dict[str, str] | None] = mapped_column(JSONB, nullable=True)
    last_checked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_mode: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_counts: Mapped[dict[str, int] | None] = mapped_column(JSONB, nullable=True)
    partial_window: Mapped[dict[str, str] | None] = mapped_column(JSONB, nullable=True)
    period_import: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    pending_rebuild: Mapped[bool] = mapped_column(Boolean, default=False)
