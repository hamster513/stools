"""Rebuildable discrepancy index; publication and local repairs are transactional."""
from __future__ import annotations

import datetime as dt
import uuid
from collections import defaultdict
from collections.abc import Callable
from dataclasses import asdict
from typing import Any, cast

from sqlalchemy import delete, func, insert, select, text
from sqlalchemy.orm import Session, defer

from api.modules.assets.models import (
    Asset,
    AssetObservation,
    AssetReadDirty,
    AssetReadEntry,
    AssetReadFinding,
    AssetReadState,
    AssetZone,
    Network,
)
from api.platform.data_revision import DataRevision, ensure_revision, read_revision
from api.timeutil import utcnow

VERSION = 1  # Bump when discrepancy rules or indexed field semantics change.
BATCH = 500


class SourceChanged(RuntimeError):
    pass


def ready_generation(db: Session, now: dt.datetime) -> str | None:
    row = db.execute(select(AssetReadState.generation, AssetReadState.revision,
        AssetReadState.version, AssetReadState.calculated_at, AssetReadState.valid_until).where(AssetReadState.id == 1)).first()
    if (row and row.version == VERSION and row.calculated_at <= now < row.valid_until
            and row.revision == read_revision(db, "assets")
            and db.scalar(select(AssetReadDirty.asset_id).limit(1)) is None):
        return cast(str, row.generation)
    return None


def _batch(db: Session, ids: list[int], generation: str, now: dt.datetime, settings: dict[str, Any],
           networks: dict[int, Network], zones: dict[str, AssetZone]) -> None:
    from api.modules.assets.core.discrepancies import _iso, finding_key
    from api.modules.assets.core.matching import normalize_fqdn
    from api.modules.assets.services import assets as svc

    rows = list(db.scalars(select(AssetObservation).where(AssetObservation.asset_id.in_(ids))
                          .options(defer(AssetObservation.extra)).order_by(AssetObservation.id)))
    extras = dict(db.execute(select(AssetObservation.id, AssetObservation.extra).where(
        AssetObservation.asset_id.in_(ids), AssetObservation.source.in_(svc.LIST_EXTRA_SOURCES))).tuples().all())
    by_asset: dict[int, list[AssetObservation]] = defaultdict(list)
    for row in rows:
        by_asset[row.asset_id].append(row)
    entries, findings = [], []
    for asset in db.scalars(select(Asset).where(Asset.id.in_(ids), Asset.merged_into.is_(None))):
        observations = by_asset[asset.id]
        observed = [svc.observed(r, extra=extras.get(r.id) or {}) for r in observations]
        net = networks.get(asset.network_id) if asset.network_id is not None else None
        terms = [asset.name, asset.fqdn, asset.ip, asset.os]
        cluster, laps = None, None
        # Daily safety cutoff; earlier last-logon/seen-at transitions are exact (>= in _found).
        expiry = dt.datetime.combine(now.date() + dt.timedelta(days=1), dt.time(), tzinfo=dt.UTC)
        for row in observations:
            terms.extend([row.name, row.fqdn, row.ip, *row.ips])
            if row.gone_at is not None:
                continue
            extra = extras.get(row.id) or {}
            if row.source == "ad":
                if extra.get("cluster") is not None:
                    cluster = extra["cluster"]
                if extra.get("laps") is not None:
                    laps = bool(extra["laps"]) or bool(laps)
                stamp = _iso(extra.get("last_logon"))
            else:
                stamp = row.seen_at
            if stamp:
                edge = stamp + dt.timedelta(days=int(settings["inactive_days"]), microseconds=1)
                if now < edge < expiry:
                    expiry = edge
        entries.append({"generation": generation, "asset_id": asset.id,
            "sort_name": asset.name_key or normalize_fqdn(asset.fqdn) or "~", "sort_ip": asset.ip,
            "network_id": asset.network_id, "zone": (net.zone or "") if net else "",
            "placement": svc._placement(net, zones), "criticality": asset.criticality or "none",
            "cluster": cluster, "laps": laps, "sources": sorted({r.source for r in observations if r.gone_at is None}),
            "ad_keys": [r.source_key for r in observations if r.source == "ad"], "tags": asset.tags,
            "search_terms": sorted({(t or "").lower() for t in terms}), "valid_until": expiry})
        for ordinal, d in enumerate(svc._found(asset, observed, settings, now)):
            findings.append({"generation": generation, "asset_id": asset.id, "ordinal": ordinal,
                                 "key": finding_key(asset.id, d), "code": d.code, "payload": asdict(d)})
    if entries:
        db.execute(insert(AssetReadEntry), entries)
    if findings:
        db.execute(insert(AssetReadFinding), findings)


def _lock(db: Session) -> bool:
    # A manual edit holding the source revision must never wait for a full builder.
    return bool(db.scalar(text("SELECT pg_try_advisory_xact_lock(hashtext('assets_read_refresh'))")))


def _publish(db: Session, generation: str, revision: int, now: dt.datetime) -> None:
    # Source triggers acquire this lock BEFORE changing business rows.
    latest = db.scalar(select(DataRevision.revision).where(DataRevision.module == "assets").with_for_update()) or 0
    if latest != revision:
        raise SourceChanged("Данные активов изменились во время расчёта; индекс будет пересчитан")
    expiry = db.scalar(select(func.min(AssetReadEntry.valid_until)).where(AssetReadEntry.generation == generation))
    state = db.get(AssetReadState, 1)
    if state is None:
        state = AssetReadState(id=1)
        db.add(state)
    state.generation, state.revision, state.version = generation, revision, VERSION
    state.calculated_at, state.valid_until = now, expiry or now + dt.timedelta(days=1)
    db.execute(delete(AssetReadDirty))
    db.flush()


def _populate(db: Session, generation: str, now: dt.datetime, check: Callable[[], None] | None = None) -> int:
    from api.modules.assets.services import assets as svc
    settings = svc.load_settings(db)
    networks = {n.id: n for n in db.scalars(select(Network))}
    zones = svc._zones(db)
    processed, cursor = 0, 0
    while True:
        if check:
            check()
        ids = list(db.scalars(select(Asset.id).where(Asset.id > cursor, Asset.merged_into.is_(None))
                             .order_by(Asset.id).limit(BATCH)))
        if not ids:
            break
        _batch(db, ids, generation, now, settings, networks, zones)
        processed += len(ids)
        cursor = ids[-1]
    if check:
        check()
    return processed


def refresh(db: Session, *, now: dt.datetime | None = None, check: Callable[[], None] | None = None) -> dict[str, int | bool]:
    now = now or utcnow()
    db.flush()
    ensure_revision(db, "assets")  # An absent row cannot serialize the first publication.
    if not _lock(db):
        return {"busy": True}
    revision = read_revision(db, "assets")
    generation = uuid.uuid4().hex
    processed = _populate(db, generation, now, check)
    _publish(db, generation, revision, now)
    db.execute(delete(AssetReadFinding).where(AssetReadFinding.generation != generation))
    db.execute(delete(AssetReadEntry).where(AssetReadEntry.generation != generation))
    return {"assets": processed, "revision": revision}


def private_export_generation(db: Session, now: dt.datetime) -> str:
    """Expired-index fallback: bounded calculation in private, transaction-scoped tables.

    These shadow only the two derived tables on this connection. No shared generation
    or business data is changed by a reader; rollback/commit removes both temp tables.
    """
    for table in ("asset_read_entry", "asset_read_finding"):
        db.execute(text(f"CREATE TEMP TABLE {table} (LIKE public.{table} INCLUDING ALL) ON COMMIT DROP"))
    db.execute(text("SET LOCAL search_path TO pg_temp, public"))
    generation = uuid.uuid4().hex
    _populate(db, generation, now)
    return generation


def refresh_small(db: Session, *, now: dt.datetime | None = None) -> bool:
    """Repair a bounded manual mutation in its transaction; bulk writers use the queue."""
    from api.modules.assets.services import assets as svc

    now = now or utcnow()
    db.flush()
    state = db.get(AssetReadState, 1, populate_existing=True)
    if state is None or state.version != VERSION or not state.calculated_at <= now < state.valid_until:
        return False
    ids = list(db.scalars(select(AssetReadDirty.asset_id).order_by(AssetReadDirty.asset_id).limit(201)))
    if not ids or ids[0] == 0 or len(ids) > 200 or not _lock(db):
        return False
    revision = read_revision(db, "assets")
    for model in (AssetReadEntry, AssetReadFinding):
        db.execute(delete(model).where(model.generation == state.generation, model.asset_id.in_(ids)))
    _batch(db, ids, state.generation, now, svc.load_settings(db),
           {n.id: n for n in db.scalars(select(Network))}, svc._zones(db))
    _publish(db, state.generation, revision, now)
    return True
