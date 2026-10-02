"""Таблицы статусов находок (спека §2).

Строка состояния заводится только тогда, когда о находке что-то решили
люди; находка без строки — `new`. Поэтому сверка с данными (`reconcile`)
строк не создаёт, а держит в порядке только существующие.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.db.models import Base, _utcnow

JSONType = JSON().with_variant(JSONB(), "postgresql")


class FindingState(Base):
    __tablename__ = "platform_finding_state"
    __table_args__ = (
        UniqueConstraint("module", "scope_id", "key", name="uq_platform_finding_state_key"),
        Index("ix_platform_finding_state_status", "module", "scope_id", "status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    module: Mapped[str] = mapped_column(String(16))
    #: Домен AD, сервер KSC; у модулей с одной областью — 0.
    scope_id: Mapped[int] = mapped_column(Integer)
    key: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), default="new")
    assignee: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    due_date: Mapped[dt.date | None] = mapped_column(Date, nullable=True, index=True)
    risk_until: Mapped[dt.date | None] = mapped_column(Date, nullable=True, index=True)
    #: Обоснование последнего закрывающего решения; при возврате в работу остаётся как след.
    reason: Mapped[str] = mapped_column(Text, default="")
    present: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    title: Mapped[str] = mapped_column(String(512), default="")
    severity: Mapped[str] = mapped_column(String(16), default="")
    updated_by: Mapped[str] = mapped_column(String(255), default="")
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class FindingEvent(Base):
    __tablename__ = "platform_finding_event"

    id: Mapped[int] = mapped_column(primary_key=True)
    state_id: Mapped[int] = mapped_column(ForeignKey("platform_finding_state.id", ondelete="CASCADE"), index=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    #: Логин или `system`.
    actor: Mapped[str] = mapped_column(String(255))
    #: status | assign | due | comment | auto_resolved | auto_reopened | risk_expired | migrated
    kind: Mapped[str] = mapped_column(String(16))
    from_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    to_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    comment: Mapped[str] = mapped_column(Text, default="")
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)

    #: Только в эту сторону: событие новой строки вставляется вместе с ней, а
    #: коллекция событий у строки не грузится при каждой смене статуса.
    state: Mapped[FindingState] = relationship()


class FindingSettingsRow(Base):
    """Одна строка: {"counted": {...}, "risk_max_days": null, "risk_accept_role": "analyst"}."""

    __tablename__ = "platform_finding_settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    updated_by: Mapped[str] = mapped_column(String(255), default="")
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
