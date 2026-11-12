import datetime as dt
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base, _utcnow


class VmTrendIngestState(Base):
    __tablename__ = "vm_trend_ingest_state"
    id: Mapped[int] = mapped_column(primary_key=True)
    collector_id: Mapped[str] = mapped_column(String(100))
    epoch: Mapped[str] = mapped_column(String(100))
    generation: Mapped[str] = mapped_column(String(36))
    active_generation: Mapped[str | None] = mapped_column(String(36), nullable=True)
    snapshot_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    snapshot_baseline: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    batch_until: Mapped[int] = mapped_column(BigInteger, default=0)
    cursor: Mapped[int] = mapped_column(BigInteger, default=0)
    received_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class VmTrendSource(Base):
    __tablename__ = "vm_trend_source"
    generation: Mapped[str] = mapped_column(String(36), primary_key=True)
    external_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)


class VmTrendEventReceipt(Base):
    __tablename__ = "vm_trend_event_receipt"
    generation: Mapped[str] = mapped_column(String(36), primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    data: Mapped[dict[str, Any] | None] = mapped_column(JSONB(none_as_null=True), nullable=True)
    payload_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    received_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class VmTrendPublication(Base):
    __tablename__ = "vm_trend_publication"
    __table_args__ = (UniqueConstraint("generation", "external_id", name="uq_vm_trend_publication"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    generation: Mapped[str] = mapped_column(String(36), index=True)
    external_id: Mapped[str] = mapped_column(String(100))
    source_id: Mapped[str] = mapped_column(String(100))
    revision: Mapped[int] = mapped_column(Integer)
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)
    retracted: Mapped[bool] = mapped_column(Boolean, default=False)
    processing: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    analysis: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    received_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class VmTrendCard(Base):
    __tablename__ = "vm_trend_card"
    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    title: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="new")
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    active_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_event_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reason: Mapped[str] = mapped_column(String(40), default="needs_review")
    independent_sources: Mapped[int] = mapped_column(Integer, default=0)


class VmTrendEvidence(Base):
    __tablename__ = "vm_trend_evidence"
    card_id: Mapped[str] = mapped_column(ForeignKey("vm_trend_card.id", ondelete="CASCADE"), primary_key=True)
    publication_id: Mapped[int] = mapped_column(ForeignKey("vm_trend_publication.id", ondelete="CASCADE"), primary_key=True)


class VmTrendReview(Base):
    __tablename__ = "vm_trend_review"
    id: Mapped[int] = mapped_column(primary_key=True)
    card_id: Mapped[str] = mapped_column(ForeignKey("vm_trend_card.id", ondelete="CASCADE"), index=True)
    actor: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    decision: Mapped[dict[str, Any]] = mapped_column(JSONB)


class VmTrendEnrichment(Base):
    __tablename__ = 'vm_trend_enrichment'
    generation: Mapped[str] = mapped_column(String(36), primary_key=True)
    external_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer)
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)
    retracted: Mapped[bool] = mapped_column(Boolean, default=False)


class VmTrendPoc(Base):
    __tablename__ = 'vm_trend_poc'
    generation: Mapped[str] = mapped_column(String(36), primary_key=True)
    external_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer)
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)
    retracted: Mapped[bool] = mapped_column(Boolean, default=False)


class VmTrendPocReview(Base):
    __tablename__ = 'vm_trend_poc_review'
    __table_args__ = (UniqueConstraint('candidate_id', 'commit_sha', 'version', name='uq_trend_poc_review_version'),)
    id: Mapped[int] = mapped_column(primary_key=True)
    candidate_id: Mapped[str] = mapped_column(String(100), index=True)
    commit_sha: Mapped[str] = mapped_column(String(64))
    version: Mapped[int] = mapped_column(Integer, default=1)
    actor: Mapped[str] = mapped_column(String(255))
    state: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list[str]] = mapped_column(JSONB, default=list)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class VmTrendPolicy(Base):
    __tablename__ = 'vm_trend_policy'
    id: Mapped[int] = mapped_column(primary_key=True)
    scope: Mapped[str] = mapped_column(String(32))
    target_key: Mapped[str] = mapped_column(String(2000))
    reason: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    actor: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    history: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)


class VmTrendAiAnswer(Base):
    """Paid answers survive navigation, model changes and collector replays."""
    __tablename__ = 'vm_trend_ai_answer'
    __table_args__ = (Index('ix_vm_trend_ai_answer_target_mode_created', 'target', 'mode', 'created_at'),)
    cache_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    target: Mapped[str] = mapped_column(String(140))
    mode: Mapped[str] = mapped_column(String(16))
    answer: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
