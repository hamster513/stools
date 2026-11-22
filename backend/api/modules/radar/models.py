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


class NettraceConfig(Base):
    __tablename__ = 'radar_nettrace_config'
    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(String(1024), default='')
    token_encrypted: Mapped[str] = mapped_column(Text, default='')
    ca_pem: Mapped[str] = mapped_column(Text, default='')
    enabled: Mapped[bool] = mapped_column(default=False)
    generation: Mapped[int] = mapped_column(default=1)
    latest_snapshot_id: Mapped[int | None] = mapped_column(nullable=True)
    synced_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_request_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_evaluation_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class NettraceSnapshot(Base):
    __tablename__ = 'radar_nettrace_snapshot'
    id: Mapped[int] = mapped_column(primary_key=True)
    generation: Mapped[int] = mapped_column(index=True)
    snapshot_set_id: Mapped[str] = mapped_column(String(64), index=True)
    collected_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    snapshot_set: Mapped[dict[str, Any]] = mapped_column(JSONType)
    device_count: Mapped[int] = mapped_column(default=0)
    warnings: Mapped[list[str]] = mapped_column(JSONType, default=list)


class NettraceDevice(Base):
    __tablename__ = 'radar_nettrace_device'
    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey('radar_nettrace_snapshot.id', ondelete='CASCADE'), index=True)
    device_id: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255))
    document: Mapped[dict[str, Any]] = mapped_column(JSONType)


class NettraceEvaluation(Base):
    __tablename__ = 'radar_nettrace_evaluation'
    id: Mapped[int] = mapped_column(primary_key=True)
    generation: Mapped[int] = mapped_column(index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    run_id: Mapped[int | None] = mapped_column(ForeignKey('platform_sync_run.id', ondelete='SET NULL'), nullable=True)
    request: Mapped[dict[str, Any]] = mapped_column(JSONType)
    request_hash: Mapped[str] = mapped_column(String(64), index=True)
    snapshot_set_id: Mapped[str] = mapped_column(String(64), default='', index=True)
    snapshot_set: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    response: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    verdict: Mapped[str] = mapped_column(String(16), default='unknown')
    consistent: Mapped[bool] = mapped_column(default=False)
    warnings: Mapped[list[str]] = mapped_column(JSONType, default=list)
    cache_source_id: Mapped[int | None] = mapped_column(nullable=True)


class RadarAddressBinding(Base):
    __tablename__ = 'radar_address_binding'
    server_id: Mapped[int] = mapped_column(ForeignKey('radar_server.id', ondelete='CASCADE'), primary_key=True)
    addresses: Mapped[list[str]] = mapped_column(JSONType, default=list)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
