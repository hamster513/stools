"""Таблицы модуля Assets (спека §1): сети, справочник зон, активы, наблюдения источников,
DNS-серверы, задачи, настройки; пользователи как активы — свои таблицы `asset_user*`.

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
#: External — сети с публичными адресами; её получают такие сети из RackTables.
DEFAULT_ZONES = ("DMZ", "Internal", "Guest", "Management", "Industrial", "External")
EXTERNAL_ZONE = "External"

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
    #: Новых сокетов (ICMP echo или SYN) в секунду на весь скан сети.
    rate_per_s: Mapped[int] = mapped_column(Integer, default=500, server_default="500")
    schedule_id: Mapped[int | None] = mapped_column(
        ForeignKey("platform_schedule.id", ondelete="SET NULL"), nullable=True,
    )
    last_scan_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_alive: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: Шёл ли последний скан с ICMP; False — «только порты» (ICMP-сокет не открылся), None — не сканировали.
    last_scan_icmp: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    #: Откуда сеть: пусто — описана вручную, racktables — создана задачей RackTables (origin_key — id сети там).
    origin: Mapped[str] = mapped_column(String(32), default="", server_default="")
    origin_key: Mapped[str] = mapped_column(String(64), default="", server_default="")
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


class AssetUser(Base):
    """Пользователь как актив (спека «Пользователи как активы» §3–§4): карточка из наблюдений AD и KSC.

    Ключи личности — `sid` и `name_key` (`core.users.user_key`): `<dns-домен>\\<sam>` или
    `local:<asset_id хоста>\\<sam>` у локальной учётки. `enabled` и `privileged` знает только AD;
    `note` и `tags` — ручные, синхронизация их не трогает."""

    __tablename__ = "asset_user"

    id: Mapped[int] = mapped_column(primary_key=True)
    sid: Mapped[str] = mapped_column(String(255), default="", index=True)
    name_key: Mapped[str] = mapped_column(String(512), default="", index=True)
    sam: Mapped[str] = mapped_column(String(255), default="")
    upn: Mapped[str] = mapped_column(String(255), default="")
    display_name: Mapped[str] = mapped_column(String(255), default="")
    #: DNS-домен (`corp.local`); у локальной учётки пусто.
    domain: Mapped[str] = mapped_column(String(255), default="")
    local: Mapped[bool] = mapped_column(Boolean, default=False)
    #: None — AD учётку не видел (KSC-only, локальная, домен без выгрузки).
    enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    merged_into: Mapped[int | None] = mapped_column(ForeignKey("asset_user.id", ondelete="SET NULL"), nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[list[str]] = mapped_column(JSONType, default=list)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class AssetUserObservation(Base):
    """Последнее, что об учётке сказал один источник (ad | ksc); `data` — поля как пришли."""

    __tablename__ = "asset_user_observation"
    __table_args__ = (UniqueConstraint("source", "source_key", name="uq_asset_user_observation_source_key"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("asset_user.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(16))
    source_key: Mapped[str] = mapped_column(String(512))
    seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    gone_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)


class AssetUserHost(Base):
    """Связь «пользователь → актив-хост»: сеанс, владелец устройства или член локальной группы."""

    __tablename__ = "asset_user_host"
    __table_args__ = (
        UniqueConstraint("user_id", "asset_id", "source", "kind", name="uq_asset_user_host_link"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("asset_user.id", ondelete="CASCADE"))
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(16))
    #: session | owner | local_group
    kind: Mapped[str] = mapped_column(String(16))
    #: Для сеанса KSC: True — в системе на момент сбора, False — заходил раньше.
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    gone_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AssetUserGroup(Base):
    """Группа AD пользователя: прямая (`direct`) или через вложенность."""

    __tablename__ = "asset_user_group"
    __table_args__ = (UniqueConstraint("user_id", "group_sid", name="uq_asset_user_group_sid"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("asset_user.id", ondelete="CASCADE"))
    group_sid: Mapped[str] = mapped_column(String(255))
    group_name: Mapped[str] = mapped_column(String(512), default="")
    direct: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(16), default="ad")


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


class AssetRacktables(Base):
    """Подключение к JSON API RackTables: сети и имена адресов → сети Assets и наблюдения `rt`."""

    __tablename__ = "asset_racktables"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255), default="")
    url: Mapped[str] = mapped_column(String(512))
    username: Mapped[str] = mapped_column(String(255), default="")
    #: Зашифрован, как пароль подключения AD.
    password: Mapped[str] = mapped_column(Text, default="")
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    rate_per_s: Mapped[int] = mapped_column(Integer, default=10)
    timeout_ms: Mapped[int] = mapped_column(Integer, default=30000)
    schedule_id: Mapped[int | None] = mapped_column(
        ForeignKey("platform_schedule.id", ondelete="SET NULL"), nullable=True,
    )
    last_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class AssetJob(JobColumns, Base):
    """Сканы, DNS-обновления, проходы RackTables и синхронизация с модулями: kind ∈ scan, dns, rt, sync."""

    __tablename__ = "asset_job"


class AssetSettings(Base):
    """Одна строка: {"inactive_days": 30, "stale_days": 30, "sync_after_import": true}."""

    __tablename__ = "asset_settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
