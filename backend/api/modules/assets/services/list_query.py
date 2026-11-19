"""SQL filtering/facets; business observations are loaded only for the selected page."""
from __future__ import annotations

import datetime as dt
from collections import defaultdict
from collections.abc import Iterator
from typing import Any

from sqlalchemy import and_, case, false, func, literal, select, true, union_all
from sqlalchemy.orm import Session, defer

from api.modules.assets.core.discrepancies import CODES, Discrepancy
from api.modules.assets.models import Asset, AssetObservation, Network
from api.modules.assets.models import AssetReadEntry as Entry
from api.modules.assets.models import AssetReadFinding as Finding
from api.modules.assets.services import assets as svc
from api.modules.assets.services.networks import PLACEMENTS
from api.platform.findings import service as findings
from api.platform.findings.core import OPEN, STATUSES
from api.platform.findings.models import FindingState


def _data(generation: str, *, q: str | None = None, source_has: frozenset[str] | None = None,
          source_missing: frozenset[str] | None = None, network_id: frozenset[int] | None = None,
          zone: frozenset[str] | None = None, placement: frozenset[str] | None = None, tag: str | None = None,
          criticality: frozenset[str] | None = None, laps: frozenset[str] | None = None,
          cluster: frozenset[str] | None = None, ad_keys: frozenset[str] | None = None) -> Any:
    stmt = select(Entry).where(Entry.generation == generation)
    if source_has:
        stmt = stmt.where(Entry.sources.overlap(sorted(source_has)))
    if source_missing:
        stmt = stmt.where(~Entry.sources.contains(sorted(source_missing)))
    for col, values in ((Entry.network_id, network_id), (Entry.zone, zone), (Entry.placement, placement)):
        if values is not None:
            stmt = stmt.where(col.in_(values))
    if cluster:
        stmt = stmt.where(Entry.cluster.in_(cluster))
    if criticality is not None:
        stmt = stmt.where(Entry.criticality.in_({v or "none" for v in criticality}))
    if tag:
        stmt = stmt.where(Entry.tags.contains([tag]))
    if laps:
        stmt = stmt.where(Entry.laps.in_([v == "yes" for v in laps]))
    if ad_keys is not None:
        stmt = stmt.where(Entry.ad_keys.overlap(sorted(ad_keys)))
    needle = (q or "").strip().lower()
    if needle:
        if "\x00" in needle:
            stmt = stmt.where(false())
        else:
            term = func.unnest(Entry.search_terms).table_valued("value").render_derived()
            stmt = stmt.where(select(1).select_from(term).where(func.strpos(term.c.value, needle) > 0).exists())
    return stmt.cte("asset_data")


class Query:
    def __init__(self, db: Session, generation: str, *, code: frozenset[str] | None = None,
                 disc_status: Any = None, assignee: Any = None, overdue: bool | None = None,
                 login: str = "", **filters: Any) -> None:
        self.db, self.generation = db, generation
        self.counted = findings.counted_statuses(db)
        self.f = svc.disc_filter(self.counted, code=code, disc_status=disc_status, assignee=assignee, overdue=overdue, login=login)
        self.today = findings.today()
        self.data = data = _data(generation, **filters)
        self.findings = found = select(Finding.asset_id, Finding.code,
            func.coalesce(FindingState.status, "new").label("status"),
            func.coalesce(func.nullif(FindingState.assignee, ""), "none").label("assignee"),
            FindingState.due_date).select_from(Finding).join(data, data.c.asset_id == Finding.asset_id).outerjoin(
                FindingState, and_(FindingState.module == svc.FINDINGS_MODULE, FindingState.scope_id == svc.FINDINGS_SCOPE,
                                   FindingState.key == Finding.key)).where(Finding.generation == generation).cte("asset_findings")
        stmt = select(data)
        if self.f.active:
            stmt = stmt.where(select(1).select_from(found).where(found.c.asset_id == data.c.asset_id, *self.hits()).exists())
        self.passed = stmt.cte("asset_passed")

    def expired(self) -> Any:
        return and_(self.findings.c.status.in_(OPEN), self.findings.c.due_date < self.today)

    def hits(self, *, code: bool = True, status: bool = True, overdue: bool = True) -> list[Any]:
        f, c = self.f, self.findings.c
        predicates = []
        if code and f.code and svc.ANY_CODE not in f.code:
            predicates.append(c.code.in_(f.code))
        if status and f.statuses is not None:
            predicates.append(c.status.in_(f.statuses))
        if f.assignee is not None:
            predicates.append(c.assignee.in_(f.assignee))
        if overdue and f.overdue:
            predicates.append(self.expired())
        return predicates

    def ids(self, *, limit: int | None = None, offset: int = 0) -> list[int]:
        p = self.passed.c
        stmt = select(p.asset_id).order_by(p.sort_name, p.sort_ip, p.asset_id).offset(offset)
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self.db.scalars(stmt))

    def facets(self) -> tuple[int, dict[str, Any]]:
        p, f = self.passed, self.findings
        counts = [select(literal("total").label("facet"), literal("").label("value"), func.count().label("n")).select_from(p)]
        for name, col, predicate in (("zone", p.c.zone, p.c.zone != ""), ("placement", p.c.placement, true()),
            ("criticality", p.c.criticality, true()), ("cluster", p.c.cluster, p.c.cluster.is_not(None)),
            ("laps", case((p.c.laps.is_(True), "yes"), else_="no"), p.c.laps.is_not(None))):
            counts.append(select(literal(name), col, func.count()).select_from(p).where(predicate).group_by(col))
        source = func.unnest(p.c.sources).table_valued("value").render_derived()
        counts.append(select(literal("source"), source.c.value, func.count()).select_from(p.join(source, true())).group_by(source.c.value))
        codes = f.join(p, p.c.asset_id == f.c.asset_id)
        counts.append(select(literal("code"), f.c.code, func.count(func.distinct(f.c.asset_id))).select_from(codes)
                      .where(*self.hits(code=False)).group_by(f.c.code))
        counts.append(select(literal("code"), literal(svc.ANY_CODE), func.count(func.distinct(f.c.asset_id)))
                      .select_from(codes).where(*self.hits(code=False)))
        counts.append(select(literal("disc_status"), f.c.status, func.count()).select_from(f)
                      .where(*self.hits(status=False)).group_by(f.c.status))
        counts.append(select(literal("disc_overdue"), literal(""), func.count()).select_from(f)
                      .where(*self.hits(status=False, overdue=False), self.expired()))
        facets: dict[str, Any] = {"source": dict.fromkeys(svc.SOURCES, 0), "code": dict.fromkeys((*CODES, svc.ANY_CODE), 0), "zone": {},
            "criticality": dict.fromkeys((*svc.CRITICALITY, "none"), 0), "placement": dict.fromkeys(PLACEMENTS, 0),
            "disc_status": dict.fromkeys(STATUSES, 0), "disc_overdue": 0,
            "laps": dict.fromkeys(svc.LAPS, 0), "cluster": dict.fromkeys(svc.CLUSTER_KINDS, 0)}
        total = 0
        for kind, value, count in self.db.execute(union_all(*counts)):
            if kind == "total":
                total = count
            elif kind == "disc_overdue":
                facets[kind] = count
            else:
                facets[kind][value] = count
        return total, facets

    def page(self, ids: list[int], now: dt.datetime) -> list[dict[str, Any]]:
        if not ids:
            return []
        db = self.db
        rows: dict[int, list[AssetObservation]] = defaultdict(list)
        tracked: dict[int, list[svc.Tracked]] = defaultdict(list)
        for r in db.scalars(select(AssetObservation).where(AssetObservation.asset_id.in_(ids))
                            .options(defer(AssetObservation.extra)).order_by(AssetObservation.id)):
            rows[r.asset_id].append(r)
        raw = list(db.scalars(select(Finding).where(Finding.generation == self.generation, Finding.asset_id.in_(ids))
                              .order_by(Finding.asset_id, Finding.ordinal)))
        states = findings.state_map(db, svc.FINDINGS_MODULE, svc.FINDINGS_SCOPE, [r.key for r in raw])
        for finding in raw:
            tracked[finding.asset_id].append(svc.Tracked(Discrepancy(**finding.payload), finding.key, states.get(finding.key)))
        cards = {a.id: a for a in db.scalars(select(Asset).where(Asset.id.in_(ids)))}
        entries = {e.asset_id: e for e in db.scalars(select(Entry).where(Entry.generation == self.generation, Entry.asset_id.in_(ids)))}
        net_ids = {a.network_id for a in cards.values() if a.network_id is not None}
        networks = {n.id: n for n in db.scalars(select(Network).where(Network.id.in_(net_ids)))} if net_ids else {}
        zones, settings = svc._zones(db), svc.load_settings(db)
        result = []
        for id_ in ids:
            # A concurrent source deletion is caught by the caller's final revision check.
            if id_ not in cards or id_ not in entries:
                continue
            asset = cards[id_]
            net = networks.get(asset.network_id) if asset.network_id is not None else None
            result.append(svc._item(asset, rows[id_], tracked[id_], net, now, int(settings["stale_days"]),
                                    self.counted, entries[id_].cluster, svc._zone_of(net, zones)))
        return result


def start_snapshot(db: Session) -> None:
    """Read-route boundary: release auth's read transaction, reuse its pool slot."""
    if db.new or db.dirty or db.deleted:
        raise RuntimeError("Cannot start a read snapshot with pending writes")
    db.rollback()
    db.connection(execution_options={"isolation_level": "REPEATABLE READ"})


def export_items(db: Session, **filters: Any) -> Iterator[dict[str, Any]]:
    """Stable snapshot and one connection for the entire download."""
    from api.modules.assets.services.read_model import private_export_generation
    from api.timeutil import utcnow
    start_snapshot(db)
    try:
        now = utcnow()
        generation = svc._sql_generation(db, now) or private_export_generation(db, now)
        query = Query(db, generation, **filters)
        offset = 0
        while ids := query.ids(limit=500, offset=offset):
            yield from query.page(ids, now)
            offset += len(ids)
    finally:
        db.rollback()  # Also drops private tables when the client closes the stream early.
