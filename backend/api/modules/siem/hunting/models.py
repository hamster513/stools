"""Таблицы Threat Hunting: ханты (гипотезы с PDQL-запросами), ночные прогоны, большие ханты, находки и события.

Хант и его запросы — справочник, который ведёт человек, поэтому хант
удаляется «мягко» (`deleted_at`): находки и история прогонов ссылаются на
его код, и пропасть вместе с ним им незачем. Находка копирует `hunt_code`
и `query_id` по той же причине — она должна читаться, даже если хант
переименовали или убрали. События находки — отдельная таблица: их много,
а по истечении срока хранения они удаляются, оставляя саму находку
(`events_purged`).
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    BigInteger,
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
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base, _utcnow
from api.jobs import JobColumns


class ThHunt(Base):
    __tablename__ = "th_hunt"

    id: Mapped[int] = mapped_column(primary_key=True)
    #: Устойчивый код хунта (например, из каталога или заданный человеком); по нему ссылаются находки.
    code: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    #: Техника ATT&CK (T1059 и т. п.), если хант к ней привязан.
    technique_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    #: Место ханта в очереди ночного прогона; порядок задаёт человек, новый хант встаёт в конец.
    position: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    updated_by: Mapped[str] = mapped_column(String(255), default="")
    deleted_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ThQuery(Base):
    __tablename__ = "th_query"
    __table_args__ = (UniqueConstraint("hunt_id", "query_id", name="uq_th_query_hunt_query"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    hunt_id: Mapped[int] = mapped_column(ForeignKey("th_hunt.id", ondelete="CASCADE"))
    #: Номер запроса внутри хунта (Q1, Q2, …).
    query_id: Mapped[str] = mapped_column(String(32))
    position: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(255), default="", server_default="")
    description: Mapped[str] = mapped_column(Text, default="", server_default="")
    is_full_pdql: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    query: Mapped[str] = mapped_column(Text)
    #: JSON-список полей события, которые просит запрос: ["time", "src.ip", ...].
    fields_json: Mapped[str] = mapped_column(Text, default="[]")
    #: JSON-список подписей колонок, по одной на поле из `fields_json` (в том же порядке).
    labels_json: Mapped[str] = mapped_column(Text, default="[]")
    #: Предел событий запроса; пусто — умолчание из настроек.
    limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class ThJob(JobColumns, Base):
    """kind: nightly | deep."""

    __tablename__ = "th_job"


class ThRun(Base):
    """Ночной прогон за сутки: один на дату, повторный запуск той же даты вытесняет прежний.

    Вытесненный (`superseded`) остаётся строкой — на него ссылаются находки со статусами
    и его история, — поэтому единственность даты только среди невытесненных."""

    __tablename__ = "th_run"
    __table_args__ = (
        Index(
            "uq_th_run_target_date_live", "target_date", unique=True,
            postgresql_where=text("status <> 'superseded'"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    target_date: Mapped[dt.date] = mapped_column()
    period_from: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    period_to: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    #: queued | running | done | failed | aborted | cancelled | superseded
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    queries_total: Mapped[int] = mapped_column(Integer, default=0)
    queries_done: Mapped[int] = mapped_column(Integer, default=0)
    findings: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class ThRunQuery(Base):
    """Итог одного запроса в прогоне. `query_pk` — без внешнего ключа: запрос могут удалить, а история остаётся."""

    __tablename__ = "th_run_query"
    __table_args__ = (UniqueConstraint("run_id", "query_pk", name="uq_th_run_query"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("th_run.id", ondelete="CASCADE"))
    query_pk: Mapped[int] = mapped_column(Integer)
    hunt_code: Mapped[str] = mapped_column(String(64))
    query_id: Mapped[str] = mapped_column(String(32))
    #: ok | failed | skipped | aborted
    status: Mapped[str] = mapped_column(String(16))
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    events: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    finding_id: Mapped[int | None] = mapped_column(Integer, nullable=True)


class ThDeepHunt(Base):
    """Большой хант: запрос за длинный период, нарезанный на окна; можно ставить на паузу и продолжать."""

    __tablename__ = "th_deep_hunt"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    #: Хант-источник; при его удалении большой хант остаётся со своей копией запроса.
    hunt_id: Mapped[int | None] = mapped_column(ForeignKey("th_hunt.id", ondelete="SET NULL"), nullable=True)
    query_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    is_full_pdql: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    query: Mapped[str] = mapped_column(Text)
    fields_json: Mapped[str] = mapped_column(Text, default="[]")
    labels_json: Mapped[str] = mapped_column(Text, default="[]")
    limit: Mapped[int] = mapped_column(Integer, default=5000)
    period_from: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    period_to: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    #: queued | running | paused | done | failed | cancelled
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    slices_total: Mapped[int] = mapped_column(Integer, default=0)
    slices_done: Mapped[int] = mapped_column(Integer, default=0)
    #: С какого момента продолжать после паузы или перезапуска.
    next_slice_from: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    events: Mapped[int] = mapped_column(Integer, default=0)
    #: Окна, где запрос упёрся в предел: в них события могли быть отрезаны.
    limit_hit_slices: Mapped[int] = mapped_column(Integer, default=0)
    partial: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ThFinding(Base):
    """Результат запроса за период: ночной (run_id) или большого хунта (deep_id)."""

    __tablename__ = "th_finding"

    id: Mapped[int] = mapped_column(primary_key=True)
    #: nightly | deep
    kind: Mapped[str] = mapped_column(String(8))
    hunt_id: Mapped[int | None] = mapped_column(ForeignKey("th_hunt.id", ondelete="SET NULL"), nullable=True, index=True)
    hunt_code: Mapped[str] = mapped_column(String(64), index=True)
    query_id: Mapped[str] = mapped_column(String(32))
    run_id: Mapped[int | None] = mapped_column(ForeignKey("th_run.id", ondelete="SET NULL"), nullable=True, index=True)
    deep_id: Mapped[int | None] = mapped_column(ForeignKey("th_deep_hunt.id", ondelete="CASCADE"), nullable=True, index=True)
    period_from: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    period_to: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    limit_hit: Mapped[bool] = mapped_column(Boolean, default=False)
    partial: Mapped[bool] = mapped_column(Boolean, default=False)
    #: JSON-список колонок таблицы событий: [{"field": ..., "label": ...}].
    columns_json: Mapped[str] = mapped_column(Text, default="[]")
    #: События удалены по сроку хранения, находка осталась.
    events_purged: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)


class ThEvent(Base):
    __tablename__ = "th_event"
    __table_args__ = (Index("ix_th_event_finding_position", "finding_id", "position"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("th_finding.id", ondelete="CASCADE"))
    position: Mapped[int] = mapped_column(Integer)
    data_json: Mapped[str] = mapped_column(Text)


class ThIntelItem(Base):
    """External reference material; never an executable hunt/query."""
    __tablename__ = 'th_intel_item'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_id: Mapped[str] = mapped_column(String(100), index=True)
    external_id: Mapped[str] = mapped_column(String(1024))
    kind: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(2000))
    url: Mapped[str] = mapped_column(String(2048))
    text: Mapped[str] = mapped_column(Text)
    format: Mapped[str] = mapped_column(String(32))
    published_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    collected_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    technique_ids_json: Mapped[str] = mapped_column(Text, default='[]')
    full_text: Mapped[bool] = mapped_column(Boolean, default=False)
    import_id: Mapped[str] = mapped_column(ForeignKey('th_intel_import.id'))
    content_hash: Mapped[str] = mapped_column(String(64))


class ThIntelImport(Base):
    __tablename__ = 'th_intel_import'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    created_by: Mapped[str] = mapped_column(String(255))
    result_json: Mapped[str] = mapped_column(Text)
    manifest_json: Mapped[str] = mapped_column(Text)
