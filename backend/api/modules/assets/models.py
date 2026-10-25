"""Таблицы модуля Assets (спека §1): сети, справочник зон, активы, наблюдения источников,
DNS-серверы, задачи, настройки; пользователи и группы как активы — свои таблицы `asset_user*`,
`asset_group*`.

Актив — каноническая карточка, наблюдение — последнее, что о хосте сказал один источник.
Карточка пересчитывается из наблюдений, а ручные поля (`criticality`, `tags`, `note`,
`network_manual`, `pinned`) синхронизация не трогает никогда.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base, _utcnow
from api.jobs import JobColumns

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
    #: Признаки группы сетей (спека §3): расположение internal | dmz | external | "" (не задано),
    #: доступна ли из интернета, есть ли конфиденциальные данные. В расчёт риска не идут.
    placement: Mapped[str] = mapped_column(String(16), default="", server_default="")
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    confidential: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))


class NetworkZoneRule(Base):
    """Правило отнесения сети к группе (спека §4): по `position`, срабатывает первое включённое подошедшее."""

    __tablename__ = "network_zone_rule"

    id: Mapped[int] = mapped_column(primary_key=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    #: Группу, на которую ссылается правило, удалить нельзя (RESTRICT).
    zone: Mapped[str] = mapped_column(ForeignKey("asset_zone.name", ondelete="RESTRICT", onupdate="CASCADE"), index=True)
    #: name_prefix | name_contains | name_glob | tag | cidr
    match: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(500))
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


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
    #: Откуда группа: manual — выбрал человек (правила не трогают), rule — `zone_rule_id`,
    #: racktables — публичный адрес без подошедшего правила (External), "" — не назначена.
    zone_source: Mapped[str] = mapped_column(String(16), default="", server_default="")
    zone_rule_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_zone_rule.id", ondelete="SET NULL"), nullable=True, index=True,
    )
    site: Mapped[str] = mapped_column(String(255), default="")
    owner: Mapped[str] = mapped_column(String(255), default="")
    vlan: Mapped[int | None] = mapped_column(Integer, nullable=True)
    #: Явные теги: у сети RackTables — `etags` (перезаписываются импортом), у описанной вручную — правит человек.
    tags: Mapped[list[str]] = mapped_column(JSONType, default=list)
    #: Унаследованные теги RackTables (`itags`); у сетей, описанных вручную, пусто.
    implicit_tags: Mapped[list[str]] = mapped_column(JSONType, default=list, server_default="[]")
    #: Откуда сеть: пусто — описана вручную, racktables — создана задачей RackTables (origin_key — id сети там).
    origin: Mapped[str] = mapped_column(String(32), default="", server_default="")
    origin_key: Mapped[str] = mapped_column(String(64), default="", server_default="")
    #: Начало последнего импорта, давшего сеть; NULL — описана вручную или ещё не импортировалась.
    origin_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
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
    #: vm | ksc | ad | dns | rt
    source: Mapped[str] = mapped_column(String(16))
    #: KSC «server_id:host_id», SID компьютера AD, VM «hostname|ip», FQDN или IP для dns, IP для rt.
    source_key: Mapped[str] = mapped_column(String(512))
    name: Mapped[str] = mapped_column(String(255), default="")
    fqdn: Mapped[str] = mapped_column(String(255), default="", index=True)
    domain: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    ips: Mapped[list[str]] = mapped_column(JSONType, default=list)
    os: Mapped[str] = mapped_column(String(255), default="")
    #: Когда источник видел хост: дата снапшота, запроса, импорта.
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
    #: Один живой пользователь на SID; пустой SID и слитые строки не мешают.
    __table_args__ = (
        Index("uq_asset_user_sid_live", "sid", unique=True,
              postgresql_where=text("sid <> '' AND merged_into IS NULL")),
    )

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
    #: С индексом: удаление пользователя (`SET NULL` самоссылки) ищет ссылки на него по этому столбцу.
    merged_into: Mapped[int | None] = mapped_column(ForeignKey("asset_user.id", ondelete="SET NULL"), nullable=True, index=True)
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
    group_sid: Mapped[str] = mapped_column(String(255), index=True)
    group_name: Mapped[str] = mapped_column(String(512), default="")
    direct: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(16), default="ad")


class AssetGroup(Base):
    """Группа как актив (спека «Группы как активы» §3): доменная из AD или локальная хоста из VM.

    Личность — `group_key` (`core.groups.group_key`): (домен, SID) у доменной, (хост, SID) у локальной,
    без SID — имя. `in_ad=False` — доменная группа, которую VM видит участником, а выгрузки AD — нет."""

    __tablename__ = "asset_group"
    #: Страница списка идёт по `lower(name)`: индекс отдаёт её без сортировки всей таблицы.
    __table_args__ = (
        UniqueConstraint("group_key", name="uq_asset_group_group_key"),
        Index("ix_asset_group_name_lower", text("lower(name)")),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    group_key: Mapped[str] = mapped_column(String(800))
    sid: Mapped[str] = mapped_column(String(255), default="", index=True)
    name: Mapped[str] = mapped_column(String(512), default="")
    #: DNS-домен (`corp.local`); у локальной пусто.
    domain: Mapped[str] = mapped_column(String(255), default="")
    local: Mapped[bool] = mapped_column(Boolean, default=False)
    #: Семейство ОС локальной группы (windows | linux, по снимку VM); у доменной пусто.
    os_family: Mapped[str] = mapped_column(String(8), default="")
    host_asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("asset.id", ondelete="CASCADE"), nullable=True, index=True
    )
    description: Mapped[str] = mapped_column(Text, default="")
    #: ad | vm
    sources: Mapped[list[str]] = mapped_column(JSONType, default=list)
    in_ad: Mapped[bool] = mapped_column(Boolean, default=False)
    #: Строк прямого состава (все источники); ведёт синхронизация после каждой записи состава — список,
    #: фасет и фильтр «участники» читают столбец, а не считают строки.
    members_direct: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    gone_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class AssetGroupMember(Base):
    """Прямой участник группы и то, с чем его удалось связать: пользователь, группа или актив-хост.

    Отдельного индекса по `group_id` нет: уникальный индекс начинается с него. `user_id` и `asset_id` —
    с индексами: удаление пользователя или актива (`SET NULL`) ищет ссылки по ним."""

    __tablename__ = "asset_group_member"
    __table_args__ = (
        UniqueConstraint("group_id", "source", "member_sid", "member_name", name="uq_asset_group_member"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("asset_group.id", ondelete="CASCADE"))
    #: user | group | computer | well_known | unknown
    member_kind: Mapped[str] = mapped_column(String(16))
    user_id: Mapped[int | None] = mapped_column(ForeignKey("asset_user.id", ondelete="SET NULL"), nullable=True, index=True)
    member_group_id: Mapped[int | None] = mapped_column(
        ForeignKey("asset_group.id", ondelete="SET NULL"), nullable=True, index=True
    )
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("asset.id", ondelete="SET NULL"), nullable=True, index=True)
    member_sid: Mapped[str] = mapped_column(String(255), default="")
    member_name: Mapped[str] = mapped_column(String(512), default="")
    member_domain: Mapped[str] = mapped_column(String(255), default="")
    #: Членство через primaryGroupID (Domain Users и т. п.).
    primary: Mapped[bool] = mapped_column(Boolean, default=False)
    #: ad | vm
    source: Mapped[str] = mapped_column(String(8))


class AssetGroupGpo(Base):
    """Права по политике: запись `ad.core.gpo_rights` — группа становится членом локальной группы на хостах GPO."""

    __tablename__ = "asset_group_gpo"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    group_sid: Mapped[str] = mapped_column(String(255), default="", index=True)
    group_name: Mapped[str] = mapped_column(String(512), default="")
    local_group: Mapped[str] = mapped_column(String(255), default="")
    local_group_sid: Mapped[str] = mapped_column(String(255), default="")
    #: restricted_groups | gpp; `action` — member | memberof | add | replace | delete (как в `gpo_rights`).
    via: Mapped[str] = mapped_column(String(32), default="")
    action: Mapped[str] = mapped_column(String(16), default="")
    gpo_name: Mapped[str] = mapped_column(String(512), default="")
    gpo_dn: Mapped[str] = mapped_column(String(1024), default="")
    filtered: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    #: Имена хостов, как в `gpo_rights`; полное число — `hosts_total`.
    hosts: Mapped[list[str]] = mapped_column(JSONType, default=list)
    hosts_total: Mapped[int] = mapped_column(Integer, default=0)
    seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))


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
    """DNS-обновления, проходы RackTables и синхронизация с модулями: kind ∈ dns, rt, sync."""

    __tablename__ = "asset_job"


class AssetSettings(Base):
    """Одна строка: {"inactive_days": 30, "stale_days": 30, "sync_after_import": true}."""

    __tablename__ = "asset_settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
