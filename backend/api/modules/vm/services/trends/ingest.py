import datetime as dt
import hashlib
import json
import uuid
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from api.modules.vm.trend_models import (
    VmTrendEnrichment,
    VmTrendEventReceipt,
    VmTrendIngestState,
    VmTrendPoc,
    VmTrendPublication,
    VmTrendSource,
)

from .monitoring_contracts import CveEnrichment, PocCandidate, SourceConfigV2


class ChangeEvent(BaseModel):
    seq: int = Field(ge=1)
    entity_type: Literal["source", "publication", "cve_enrichment", "poc_candidate"]
    operation: Literal["upsert", "retract"]
    entity_id: str = Field(min_length=1, max_length=100)
    revision: int = Field(ge=1)
    observed_at: dt.datetime
    payload: dict[str, Any]


class ChangePage(BaseModel):
    protocol_version: Literal[1, 2]
    collector_id: str = Field(min_length=1, max_length=100)
    epoch: str = Field(min_length=1, max_length=100)
    until_seq: int = Field(ge=0)
    next_cursor: int = Field(ge=0)
    has_more: bool
    events: list[ChangeEvent] = Field(max_length=500)

    @model_validator(mode="after")
    def validate_events(self):
        for event in self.events:
            if len(json.dumps(event.payload, ensure_ascii=False).encode()) > 2 * 1024 * 1024:
                raise ValueError("event payload exceeds size limit")
            if self.protocol_version == 1 and event.entity_type not in ("source", "publication"):
                raise ValueError("v2 event in v1 page")
            if event.entity_type in ("cve_enrichment", "poc_candidate"):
                model = CveEnrichment if event.entity_type == "cve_enrichment" else PocCandidate
                data = model.model_validate(event.payload)
                expected = 'cve:' + data.cve_id if event.entity_type == 'cve_enrichment' else f'poc:{data.cve_id}:{data.repository_id}'
                if event.entity_id != expected:
                    raise ValueError("entity identity mismatch")
            elif self.protocol_version == 2 and event.entity_type == "source":
                SourceConfigV2.model_validate(event.payload)
        return self


def apply_page(db: Session, data: Any, reset: Any=False) -> Any:
    # A page is atomic even when a caller catches an error and keeps its session.
    with db.begin_nested():
        cursor = _apply_page(db, data, reset)
    db.commit()
    return cursor


def _apply_page(db: Session, data: Any, reset: Any=False) -> Any:
    page = ChangePage.model_validate(data)
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('vm_trend_ingest'))"))
    state = db.get(VmTrendIngestState, 1, with_for_update=True)
    if state is None:
        state = VmTrendIngestState(id=1, collector_id=page.collector_id, epoch=page.epoch,
                                   generation=str(uuid.uuid4()), cursor=0)
        db.add(state)
        db.flush()
    elif reset or state.collector_id == "offline-news-archives":
        state.collector_id, state.epoch = page.collector_id, page.epoch
        state.generation, state.cursor, state.batch_until = str(uuid.uuid4()), 0, 0
        state.snapshot_id = state.snapshot_baseline = None
    if (state.collector_id, state.epoch) != (page.collector_id, page.epoch):
        raise ValueError("изменилась история сборщика, требуется полная синхронизация")
    if page.next_cursor > page.until_seq or page.has_more != (page.next_cursor < page.until_seq):
        raise ValueError("неверные границы страницы")
    if page.events and page.events[-1].seq != page.next_cursor:
        raise ValueError("курсор не соответствует последнему событию")
    previous = None
    for event in page.events:
        if previous is not None and event.seq != previous + 1:
            raise ValueError("разрыв последовательности событий")
        previous = event.seq
        serialized = event.model_dump(mode="json")
        receipt = db.get(VmTrendEventReceipt, (state.generation, event.seq))
        if event.seq <= state.cursor:
            if receipt is None or (receipt.payload_hash != event_hash(serialized) if receipt.payload_hash else receipt.data != serialized):
                raise ValueError("повторное событие отличается от сохранённого")
            continue
        if event.seq != state.cursor + 1:
            raise ValueError("разрыв последовательности событий")
        value = event.payload
        if event.entity_type == "source":
            source_row = db.get(VmTrendSource, (state.generation, event.entity_id))
            if source_row is None:
                source_row = VmTrendSource(generation=state.generation, external_id=event.entity_id, data=value)
                db.add(source_row)
            source_row.data = value
        elif event.entity_type in ("cve_enrichment", "poc_candidate"):
            model = VmTrendEnrichment if event.entity_type == "cve_enrichment" else VmTrendPoc
            row = db.get(model, (state.generation, event.entity_id))
            if row and event.revision <= row.revision:
                raise ValueError("неверная версия контекста")
            if row is None:
                row = model(generation=state.generation, external_id=event.entity_id)
                db.add(row)
            row.revision, row.data = event.revision, value
            row.retracted = event.operation == "retract"
        else:
            source_id = value.get("source_id")
            if not source_id or len(str(source_id)) > 100:
                raise ValueError("неполная публикация")
            source = db.get(VmTrendSource, (state.generation, source_id))
            if source is None:
                raise ValueError("публикация ссылается на неизвестный источник")
            value = {**value, "title": value.get("title") or value.get("url") or event.entity_id, "origin_adapter": value.get("origin_adapter", source.data.get("adapter"))}
            if len(value.get("text", "").encode()) > 2 * 1024 * 1024:
                raise ValueError("текст публикации превышает лимит")
            row = db.scalar(select(VmTrendPublication).where(VmTrendPublication.generation == state.generation,
                                                            VmTrendPublication.external_id == event.entity_id))
            if row and event.revision <= row.revision:
                raise ValueError("неверная версия публикации")
            if row is None:
                row = VmTrendPublication(generation=state.generation, external_id=event.entity_id,
                                         source_id=source_id, revision=event.revision, data=value)
                db.add(row)
            row.data, row.revision = value, event.revision
            row.retracted, row.processing = event.operation == "retract", "pending"
            row.error, row.analysis = None, {}
        db.add(VmTrendEventReceipt(generation=state.generation, seq=event.seq, data=serialized, payload_hash=event_hash(serialized)))
        state.cursor = event.seq
        db.flush()
    if page.next_cursor > state.cursor or (not page.events and page.next_cursor != state.cursor):
        raise ValueError("страница пропускает события")
    state.batch_until = max(state.batch_until, state.cursor, page.until_seq)
    state.received_at = dt.datetime.now(dt.UTC)
    db.flush()
    return state.cursor


def event_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def compact_receipts(db: Session, days: int, *, execute: bool = False, as_of: dt.datetime | None = None) -> dict:
    cutoff = (as_of or dt.datetime.now(dt.UTC)) - dt.timedelta(days=days)
    eligible, size = db.execute(text("SELECT count(*), coalesce(sum(pg_column_size(data)),0) FROM vm_trend_event_receipt WHERE data IS NOT NULL AND received_at < :cutoff"), {'cutoff': cutoff}).one()
    total = db.scalar(text("SELECT count(*) FROM vm_trend_event_receipt"))
    if execute:
        # Serialise with ingestion; never remove the fingerprint used to reject corrupt replays.
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext('vm_trend_ingest'))"))
        while True:
            rows = list(db.scalars(select(VmTrendEventReceipt).where(VmTrendEventReceipt.data.is_not(None), VmTrendEventReceipt.received_at < cutoff).limit(500).with_for_update()))
            if not rows:
                break
            for row in rows:
                row.payload_hash = row.payload_hash or event_hash(row.data)
                row.data = None
            db.flush()
    return {"eligible_rows": eligible, "protected_rows": total-eligible, "estimated_bytes": size}


def apply_snapshot_page(db: Session, data: Any, *, reset: bool = False) -> int:
    """Stage a frozen snapshot; its synthetic sequence never enters the delivery journal."""
    snapshot_id, baseline = data.get('snapshot_id'), data.get('baseline_seq')
    if not isinstance(snapshot_id, str) or not snapshot_id or not isinstance(baseline, int) or baseline < 0:
        raise ValueError('неверный снимок сборщика')
    try:
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext('vm_trend_ingest'))"))
        state = db.get(VmTrendIngestState, 1)
        if not reset and (state is None or state.snapshot_id != snapshot_id or state.snapshot_baseline != baseline):
            raise ValueError('изменился снимок сборщика, требуется полная синхронизация')
        cursor = _apply_page(db, data, reset=reset)
        state = db.get(VmTrendIngestState, 1)
        state.snapshot_id, state.snapshot_baseline = snapshot_id, baseline
        if not data['has_more']:
            db.execute(text('DELETE FROM vm_trend_event_receipt WHERE generation=:generation'), {'generation':state.generation})
            state.cursor = state.batch_until = baseline
            state.snapshot_id = None
        db.commit()
        return cursor
    except Exception:
        db.rollback()
        raise
