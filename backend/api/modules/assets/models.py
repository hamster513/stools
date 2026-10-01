"""Таблицы модуля Assets (спека §1): сети, справочник зон, активы, наблюдения источников,
DNS-серверы, задачи, настройки.

Актив — каноническая карточка, наблюдение — последнее, что о хосте сказал один источник.
Карточка пересчитывается из наблюдений, а ручные поля (`criticality`, `tags`, `note`,
`network_manual`, `pinned`) синхронизация не трогает никогда.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base, _utcnow
from api.jobs import JobColumns

#: Порты TCP по умолчанию: SSH, HTTP(S), RPC/NetBIOS/SMB, RDP — хватает, чтобы узнать хост Windows и Linux.
DEFAULT_PORTS = [22, 80, 135, 139, 443, 445, 3389]

#: Предустановленные зоны; справочник правится, это лишь стартовый набор миграции.
DEFAULT_ZONES = ("DMZ", "Internal", "Guest", "Management", "Industrial")

JSONType = JSON().with_variant(JSONB(), "postgresql")


class AssetZone(Base):
    __tablename__ = "asset_zone"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(255), default="")
    description: Mapped[str] = mapped_column(Text, default="")


class Network(Base):
    __tablename__ = "network"

    id: Mapped[int] = mapped_column(primary_key=True)
    cidr: Mapped[str] = mapped_column(String(64), unique=True)
    title: Mapped[str] = mapped_column(String(255), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    #: Имя из справочника; удалить зону, на которую ссылается сеть, нельзя (RESTRICT).
    zone: Mapped[str | None] = mapped_column(
        ForeignKey("asset_zone.name", ondelete="RESTRICT", onupdate="CASCADE"), nullable=True, index=True,
    )
    site: Mapped[str] = mapped_column(String(255), default="")
    owner: Mapped[str] = mapped_column(String(255), default="")
    vlan: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tags: Mapped[list[str]] = mapped_column(JSONType, default=list)
    scan_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    ports: Mapped[list[int]] = mapped_column(JSONType, default=lambda: list(DEFAULT_PORTS))
    exclude: Mapped[list[str]] = mapped_column(JSONType, default=list)
    concurrency: Mapped[int] = mapped_column(Integer, default=64)
    icmp_timeout_ms: Mapped[int] = mapped_column(Integer, default=1000)
    tcp_timeout_ms: Mapped[int] = mapped_column(Integer, default=2000)
    schedule_id: Mapped[int | None] = mapped_column(
        ForeignKey("platform_schedule.id", ondelete="SET NULL"), nullable=True,
    )
    last_scan_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_alive: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class Asset(Base):
    __tablename__ = "asset"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    #: Короткое имя в нижнем регистре — ключ поиска и сопоставления.
    name_key: Mapped[str] = mapped_column(String(255), default="", index=True)
    fqdn: Mapped[str] = mapped_column(String(255), default="", index=True)
    domain: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    os: Mapped[str] = mapped_column(String(255), default="")
    network_id: Mapped[int | None] = mapped_column(
        ForeignKey("network.id", ondelete="SET NULL"), nullable=True, index=True,
    )
    network_manual: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    #: Critical | High | Medium | Low | пусто
    criticality: Mapped[str] = mapped_column(String(16), default="")
    tags: Mapped[list[str]] = mapped_column(JSONType, default=list)
    note: Mapped[str] = mapped_column(Text, default="")
    #: {"name": true, "ip": true} — закреплённые поля пересчёт не трогает.
    pinned: Mapped[dict[str, bool]] = mapped_column(JSONType, default=dict)
    merged_into: Mapped[int | None] = mapped_column(ForeignKey("asset.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class AssetObservation(Base):
    __tablename__ = "asset_observation"
    __table_args__ = (UniqueConstraint("source", "source_key", name="uq_asset_observation_source_key"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id", ondelete="CASCADE"), index=True)
    #: vm | ksc | ad | scan | dns
    source: Mapped[str] = mapped_column(String(16))
    #: KSC «server_id:host_id», SID компьютера AD, VM «hostname|ip», IP для scan, FQDN или IP для dns.
    source_key: Mapped[str] = mapped_column(String(512))
    name: Mapped[str] = mapped_column(String(255), default="")
    fqdn: Mapped[str] = mapped_column(String(255), default="", index=True)
    domain: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    ips: Mapped[list[str]] = mapped_column(JSONType, default=list)
    os: Mapped[str] = mapped_column(String(255), default="")
    #: Когда источник видел хост: дата снапшота, скана, запроса.
    seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    gone_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    extra: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class AssetDns(Base):
    __tablename__ = "asset_dns"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255), default="")
    #: direct | ad
    mode: Mapped[str] = mapped_column(String(16), default="direct")
    #: Для direct; пусто — системный резолвер.
    server: Mapped[str] = mapped_column(String(255), default="")
    ad_connection_id: Mapped[int | None] = mapped_column(
        ForeignKey("ad_connection.id", ondelete="SET NULL"), nullable=True,
    )
    zones: Mapped[list[str]] = mapped_column(JSONType, default=list)
    forward: Mapped[bool] = mapped_column(Boolean, default=True)
    reverse: Mapped[bool] = mapped_column(Boolean, default=True)
    zone_read: Mapped[bool] = mapped_column(Boolean, default=False)
    rate_per_s: Mapped[int] = mapped_column(Integer, default=50)
    timeout_ms: Mapped[int] = mapped_column(Integer, default=3000)
    schedule_id: Mapped[int | None] = mapped_column(
        ForeignKey("platform_schedule.id", ondelete="SET NULL"), nullable=True,
    )
    last_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class AssetJob(JobColumns, Base):
    """Сканы, DNS-обновления и синхронизация с модулями: kind ∈ scan, dns, sync."""

    __tablename__ = "asset_job"


class AssetSettings(Base):
    """Одна строка: {"inactive_days": 30, "stale_days": 30, "sync_after_import": true}."""

    __tablename__ = "asset_settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
