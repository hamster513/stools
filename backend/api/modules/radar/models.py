"""Nginx inventory and immutable import snapshots."""
from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base, _utcnow

JSONType = JSON().with_variant(JSONB(), 'postgresql')


class RadarServer(Base):
    __tablename__ = 'radar_server'
    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True)
    latest_snapshot_id: Mapped[int | None] = mapped_column(nullable=True)
    search_text: Mapped[str] = mapped_column(Text, default='')


class RadarSnapshot(Base):
    __tablename__ = 'radar_snapshot'
    id: Mapped[int] = mapped_column(primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey('radar_server.id', ondelete='CASCADE'), index=True)
    imported_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    filename: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64))
    original_encrypted: Mapped[str] = mapped_column(Text)
    document: Mapped[dict[str, Any]] = mapped_column(JSONType)
