"""Активы в базе: привязка наблюдения, пересчёт карточки, ручные действия, список и карточка.

Assets читает таблицы модулей (находки AD, хосты VM) только для ссылок карточки;
модули об Assets знают одним вызовом `services.sync.request_sync`.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
from collections import defaultdict
from collections.abc import Callable, Iterable
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from api.modules.assets.core.discrepancies import CODES, Discrepancy, discrepancies
from api.modules.assets.core.matching import (
    FIELDS,
    Candidate,
    Observed,
    candidate_tokens,
    canonical,
    match,
    normalize_fqdn,
    normalize_name,
    tokens,
)
from api.modules.assets.models import Asset, AssetObservation, AssetSettings, Network
from api.timeutil import utcnow

DEFAULT_SETTINGS: dict[str, Any] = {"inactive_days": 30, "stale_days": 30, "sync_after_import": True}
SOURCES = ("vm", "ksc", "ad", "scan", "dns")
CRITICALITY = ("Critical", "High", "Medium", "Low")

ScanProbes = tuple[Callable[[str], bool], Callable[[str], bool | None]]
NetworkList = list[tuple[int, ipaddress.IPv4Network | ipaddress.IPv6Network]]


class AssetNotFound(LookupError):
    pass


class AssetConflict(Exception):
    """Действие противоречит состоянию актива (уже объединён, последнее наблюдение)."""


def load_settings(db: Session) -> dict[str, Any]:
    row = db.execute(select(AssetSettings).order_by(AssetSettings.id)).scalars().first()
    return {**DEFAULT_SETTINGS, **(row.data if row else {})}


def scan_probes(db: Session) -> ScanProbes:
    """Чем расхождения узнают о скане. Сканера пока нет (задача 4): ни одна сеть не сканируется,
    поэтому «не отвечает» и «запись DNS без хоста» не срабатывают."""
    return (lambda _ip: False), (lambda _ip: None)


def observed(row: AssetObservation) -> Observed:
    return Observed(
        source=row.source, source_key=row.source_key, name=row.name, fqdn=row.fqdn, domain=row.domain, ip=row.ip,
        ips=list(row.ips or []), os=row.os, seen_at=row.seen_at, extra=dict(row.extra or {}), gone_at=row.gone_at,
    )


# ---- Сети -----------------------------------------------------------------


def load_networks(db: Session) -> NetworkList:
    out: NetworkList = []
    for network_id, cidr in db.execute(select(Network.id, Network.cidr)):
        try:
            out.append((network_id, ipaddress.ip_network(cidr, strict=False)))
        except ValueError:
            continue
    return out


def narrowest_network(networks: NetworkList, ip: str) -> int | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    best: tuple[int, int] | None = None
    for network_id, net in networks:
        if addr.version == net.version and addr in net and (best is None or net.prefixlen > best[1]):
            best = (network_id, net.prefixlen)
    return best[0] if best else None


# ---- Индекс кандидатов ----------------------------------------------------


def _candidate(asset: Asset, observations: list[Observed]) -> Candidate:
    return Candidate(asset_id=asset.id, name=asset.name, fqdn=asset.fqdn, domain=asset.domain, ip=asset.ip, observations=observations)


class MatchIndex:
    """Кандидаты по FQDN, именам и адресам в памяти: синхронизация привязывает тысячи
    наблюдений подряд, и запрос к базе на каждое было бы дороже самой работы."""

    def __init__(self) -> None:
        self._candidates: dict[int, Candidate] = {}
        self._tokens: dict[int, set[str]] = {}
        self._by_token: dict[str, set[int]] = defaultdict(set)
        self._by_key: dict[tuple[str, str], int] = {}

    @classmethod
    def load(cls, db: Session, asset_ids: Iterable[int] | None = None) -> MatchIndex:
        index = cls()
        stmt = select(Asset).where(Asset.merged_into.is_(None))
        if asset_ids is not None:
            ids = list(asset_ids)
            if not ids:
                return index
            stmt = stmt.where(Asset.id.in_(ids))
        assets = {a.id: a for a in db.execute(stmt).scalars()}
        per_asset: dict[int, list[Observed]] = defaultdict(list)
        if assets:
            rows = db.execute(
                select(AssetObservation).where(AssetObservation.asset_id.in_(list(assets))).order_by(AssetObservation.id)
            ).scalars()
            for row in rows:
                per_asset[row.asset_id].append(observed(row))
        for asset_id, asset in assets.items():
            index.put(asset, per_asset[asset_id])
        return index

    @classmethod
    def for_observation(cls, db: Session, obs: Observed) -> MatchIndex:
        """Только активы, у которых есть общий с наблюдением ключ: одиночная привязка (скан, DNS, отвязка)."""
        toks = tokens(obs)
        fqdns = [t[2:] for t in toks if t.startswith("f:")]
        shorts = [t[2:] for t in toks if t.startswith("n:")]
        ips = [t[2:] for t in toks if t.startswith("i:")]
        by_asset = select(Asset.id).where(or_(Asset.fqdn.in_(fqdns), Asset.name_key.in_(shorts), Asset.ip.in_(ips)))
        by_obs = select(AssetObservation.asset_id).where(or_(
            and_(AssetObservation.source == obs.source, AssetObservation.source_key == obs.source_key),
            AssetObservation.fqdn.in_(fqdns),
            AssetObservation.ip.in_(ips),
            func.lower(AssetObservation.name).in_(shorts),
        ))
        ids = set(db.execute(by_asset).scalars()) | set(db.execute(by_obs).scalars())
        return cls.load(db, ids)

    def put(self, asset: Asset, observations: list[Observed]) -> None:
        self.drop(asset.id)
        if asset.merged_into is not None:
            return
        cand = _candidate(asset, observations)
        toks = candidate_tokens(cand)
        self._candidates[asset.id] = cand
        self._tokens[asset.id] = toks
        for t in toks:
            self._by_token[t].add(asset.id)
        for o in observations:
            self._by_key[(o.source, o.source_key)] = asset.id

    def drop(self, asset_id: int) -> None:
        cand = self._candidates.pop(asset_id, None)
        for t in self._tokens.pop(asset_id, set()):
            self._by_token[t].discard(asset_id)
        if cand is not None:
            for o in cand.observations:
                if self._by_key.get((o.source, o.source_key)) == asset_id:
                    del self._by_key[(o.source, o.source_key)]

    def candidates_for(self, obs: Observed) -> list[Candidate]:
        ids: set[int] = set()
        if (owner := self._by_key.get((obs.source, obs.source_key))) is not None:
            ids.add(owner)
        for t in tokens(obs):
            ids |= self._by_token.get(t, set())
        return [self._candidates[i] for i in sorted(ids)]


# ---- Привязка и пересчёт --------------------------------------------------


def _observations(db: Session, asset_id: int) -> list[AssetObservation]:
    return list(db.execute(
        select(AssetObservation).where(AssetObservation.asset_id == asset_id).order_by(AssetObservation.id)
    ).scalars())


def recompute(db: Session, asset: Asset, networks: NetworkList | None = None) -> None:
    """Каноническая карточка из наблюдений; ручные поля и закреплённые значения не трогаются."""
    rows = _observations(db, asset.id)
    card = canonical([observed(r) for r in rows], dict(asset.pinned or {}), {f: getattr(asset, f) for f in FIELDS})
    for name in FIELDS:
        setattr(asset, name, card[name])
    asset.name_key = normalize_name(asset.name)[0] or normalize_name(asset.fqdn)[0]
    asset.first_seen = card["first_seen"]
    asset.last_seen = card["last_seen"]
    if not asset.network_manual:
        asset.network_id = narrowest_network(networks if networks is not None else load_networks(db), asset.ip)
    db.flush()


def apply_observation(
    db: Session,
    obs: Observed,
    *,
    index: MatchIndex | None = None,
    rows: dict[tuple[str, str], AssetObservation] | None = None,
    networks: NetworkList | None = None,
) -> tuple[Asset, int]:
    """match + upsert наблюдения + пересчёт актива; (актив, правило; 0 — новый актив).
    `index`, `rows`, `networks` — заготовки синхронизации; без них всё читается из базы."""
    idx = index if index is not None else MatchIndex.for_observation(db, obs)
    asset_id, rule = match(obs, idx.candidates_for(obs))
    asset = db.get(Asset, asset_id) if asset_id is not None else None
    if asset is None:
        asset = Asset()
        db.add(asset)
        db.flush()
    key = (obs.source, obs.source_key)
    row = rows.get(key) if rows is not None else db.execute(
        select(AssetObservation).where(AssetObservation.source == obs.source, AssetObservation.source_key == obs.source_key)
    ).scalar_one_or_none()
    if row is None:
        row = AssetObservation(source=obs.source, source_key=obs.source_key)
        db.add(row)
        if rows is not None:
            rows[key] = row
    row.asset_id = asset.id
    row.name, row.fqdn, row.domain, row.ip, row.os = obs.name, obs.fqdn, obs.domain, obs.ip, obs.os
    row.ips = list(obs.ips)
    row.seen_at = obs.seen_at or utcnow()
    row.extra = dict(obs.extra)
    row.gone_at = None
    db.flush()
    recompute(db, asset, networks)
    idx.put(asset, [observed(r) for r in _observations(db, asset.id)])
    return asset, rule


def _asset_or_404(db: Session, asset_id: int) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise AssetNotFound("актив не найден")
    return asset


def merge_assets(db: Session, into_id: int, other_id: int) -> Asset:
    """Наблюдения второго переезжают к первому; ручные поля второго не теряются:
    теги объединяются, заметка дописывается, пустые поля первого берутся у второго."""
    if into_id == other_id:
        raise ValueError("актив нельзя объединить с самим собой")
    into, other = _asset_or_404(db, into_id), _asset_or_404(db, other_id)
    if into.merged_into is not None or other.merged_into is not None:
        raise AssetConflict("актив уже объединён с другим")
    for row in _observations(db, other.id):
        row.asset_id = into.id
    into.tags = list(dict.fromkeys([*(into.tags or []), *(other.tags or [])]))
    if other.note:
        into.note = f"{into.note}\n{other.note}" if into.note else other.note
    into.criticality = into.criticality or other.criticality
    if other.network_manual and not into.network_manual:
        into.network_id, into.network_manual = other.network_id, True
    into.pinned = {**(other.pinned or {}), **(into.pinned or {})}
    other.merged_into = into.id
    # Цепочка объединений сводится к одному активу: ссылки на второго ведут к первому.
    for earlier in db.execute(select(Asset).where(Asset.merged_into == other.id)).scalars():
        earlier.merged_into = into.id
    db.flush()
    recompute(db, into)
    return into


def detach_observation(db: Session, observation_id: int) -> Asset:
    """Наблюдение — в новый актив; правило 1 держит его там при следующих синхронизациях."""
    row = db.get(AssetObservation, observation_id)
    if row is None:
        raise AssetNotFound("наблюдение не найдено")
    source = _asset_or_404(db, row.asset_id)
    if len(_observations(db, source.id)) < 2:
        raise AssetConflict("у актива одно наблюдение — отвязывать некуда")
    fresh = Asset()
    db.add(fresh)
    db.flush()
    row.asset_id = fresh.id
    db.flush()
    recompute(db, fresh)
    recompute(db, source)
    return fresh


def pin_field(db: Session, asset_id: int, field: str, pinned: bool) -> Asset:
    if field not in FIELDS:
        raise ValueError(f"закрепить можно только {', '.join(FIELDS)}")
    asset = _asset_or_404(db, asset_id)
    current = dict(asset.pinned or {})
    if pinned:
        current[field] = True
    else:
        current.pop(field, None)
    asset.pinned = current
    recompute(db, asset)
    return asset


def update_manual(db: Session, asset_id: int, values: dict[str, Any]) -> Asset:
    """Ручные поля: criticality, tags, note, network_id + network_manual."""
    asset = _asset_or_404(db, asset_id)
    if "criticality" in values:
        asset.criticality = values["criticality"] or ""
    if "tags" in values:
        asset.tags = list(dict.fromkeys(t.strip() for t in values["tags"] or [] if t.strip()))
    if "note" in values:
        asset.note = values["note"] or ""
    if "network_id" in values:
        network_id = values["network_id"]
        if network_id is not None and db.get(Network, network_id) is None:
            raise AssetNotFound("сеть не найдена")
        asset.network_id = network_id
        # Сеть, выбранная руками, — ручная, пока не сказано иное; сброс сети возвращает её расчёт.
        asset.network_manual = bool(values.get("network_manual", network_id is not None))
    elif "network_manual" in values:
        asset.network_manual = bool(values["network_manual"])
    recompute(db, asset)
    return asset


# ---- Список и карточка ----------------------------------------------------


def _iso(value: dt.datetime | None) -> str | None:
    return value.isoformat() if value else None


def _card(asset: Asset) -> dict[str, Any]:
    return {f: getattr(asset, f) for f in FIELDS}


def _sources(rows: list[AssetObservation], now: dt.datetime, stale_days: int) -> list[dict[str, Any]]:
    """Значок на источник: серый, если источник хост больше не видит или видел давно."""
    out = []
    for source in SOURCES:
        mine = [r for r in rows if r.source == source]
        if not mine:
            continue
        live = [r for r in mine if r.gone_at is None]
        seen = max(r.seen_at for r in (live or mine))
        out.append({"source": source, "live": bool(live), "fresh": bool(live) and now - seen < dt.timedelta(days=stale_days), "seen_at": seen.isoformat()})
    return out


def _network_view(network: Network | None) -> dict[str, Any] | None:
    if network is None:
        return None
    return {"id": network.id, "cidr": network.cidr, "title": network.title, "zone": network.zone}


def _found(asset: Asset, rows: list[AssetObservation], settings: dict[str, Any], probes: ScanProbes, now: dt.datetime) -> list[Discrepancy]:
    scanned, alive = probes
    return discrepancies(
        _card(asset), [observed(r) for r in rows], stale_days=int(settings["stale_days"]), inactive_days=int(settings["inactive_days"]),
        scanned_networks=scanned, scan_alive=alive, now=now,
    )


def _item(asset: Asset, rows: list[AssetObservation], found: list[Discrepancy], network: Network | None, now: dt.datetime, stale_days: int) -> dict[str, Any]:
    return {
        "id": asset.id, "name": asset.name, "fqdn": asset.fqdn, "domain": asset.domain, "ip": asset.ip, "os": asset.os,
        "network": _network_view(network), "first_seen": _iso(asset.first_seen), "last_seen": _iso(asset.last_seen),
        "criticality": asset.criticality, "tags": list(asset.tags or []), "pinned": dict(asset.pinned or {}),
        "sources": _sources(rows, now, stale_days), "discrepancy_count": len(found), "codes": sorted({d.code for d in found}, key=CODES.index),
    }


def _matches_query(asset: Asset, rows: list[AssetObservation], needle: str) -> bool:
    texts = [asset.name, asset.fqdn, asset.ip, asset.os]
    for r in rows:
        texts += [r.name, r.fqdn, r.ip, *(r.ips or [])]
    return any(needle in (t or "").lower() for t in texts)


def _open_ports(rows: list[AssetObservation]) -> set[int]:
    return {int(p) for r in rows if r.source == "scan" and r.gone_at is None for p in (r.extra or {}).get("ports", [])}


def list_assets(
    db: Session,
    *,
    q: str | None = None,
    source_has: str | None = None,
    source_missing: str | None = None,
    code: str | None = None,
    network_id: int | None = None,
    zone: str | None = None,
    port: int | None = None,
    tag: str | None = None,
    criticality: str | None = None,
    limit: int = 200,
    offset: int = 0,
    now: dt.datetime | None = None,
) -> tuple[list[dict[str, Any]], int, dict[str, Any]]:
    """items, total, facets. Расхождения считаются на лету, поэтому фильтры и фасеты — в памяти,
    как у хостов KSC; `criticality='none'` — критичность не задана."""
    now = now or utcnow()
    settings = load_settings(db)
    probes = scan_probes(db)
    assets = list(db.execute(select(Asset).where(Asset.merged_into.is_(None))).scalars())
    per_asset: dict[int, list[AssetObservation]] = defaultdict(list)
    for row in db.execute(select(AssetObservation).order_by(AssetObservation.id)).scalars():
        per_asset[row.asset_id].append(row)
    networks = {n.id: n for n in db.execute(select(Network)).scalars()}
    needle = (q or "").strip().lower()

    picked: list[tuple[Asset, list[AssetObservation], list[Discrepancy]]] = []
    for asset in assets:
        rows = per_asset[asset.id]
        live = {r.source for r in rows if r.gone_at is None}
        if source_has and source_has not in live:
            continue
        if source_missing and source_missing in live:
            continue
        if network_id is not None and asset.network_id != network_id:
            continue
        net = networks.get(asset.network_id) if asset.network_id is not None else None
        if zone and (net is None or net.zone != zone):
            continue
        if tag and tag not in (asset.tags or []):
            continue
        if criticality and asset.criticality != ("" if criticality == "none" else criticality):
            continue
        if port is not None and port not in _open_ports(rows):
            continue
        if needle and not _matches_query(asset, rows, needle):
            continue
        found = _found(asset, rows, settings, probes, now)
        if code and code not in {d.code for d in found}:
            continue
        picked.append((asset, rows, found))

    facets: dict[str, Any] = {
        "source": dict.fromkeys(SOURCES, 0), "code": dict.fromkeys(CODES, 0), "zone": {},
        "criticality": dict.fromkeys([*CRITICALITY, "none"], 0),
    }
    for asset, rows, found in picked:
        for source in {r.source for r in rows if r.gone_at is None}:
            facets["source"][source] += 1
        for c in {d.code for d in found}:
            facets["code"][c] += 1
        net = networks.get(asset.network_id) if asset.network_id is not None else None
        if net is not None and net.zone:
            facets["zone"][net.zone] = facets["zone"].get(net.zone, 0) + 1
        facets["criticality"][asset.criticality or "none"] = facets["criticality"].get(asset.criticality or "none", 0) + 1

    picked.sort(key=lambda t: (t[0].name_key or normalize_fqdn(t[0].fqdn) or "~", t[0].ip, t[0].id))
    stale_days = int(settings["stale_days"])
    page = [
        _item(asset, rows, found, networks.get(asset.network_id) if asset.network_id is not None else None, now, stale_days)
        for asset, rows, found in picked[offset : offset + limit]
    ]
    return page, len(picked), facets


def _marks(row: AssetObservation, found: list[Discrepancy]) -> dict[str, str]:
    """Какие ячейки строки источника подсветить: поле → stale | conflict."""
    marks: dict[str, str] = {}
    for d in found:
        if d.code in ("stale", "conflict") and d.source == row.source and getattr(row, d.field, None) == d.value:
            marks[d.field] = d.code
    return marks


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _links(db: Session, rows: list[AssetObservation]) -> dict[str, Any]:
    """«Где засветился»: находки AD по компьютеру, хост антивируса, хост VM."""
    from api.modules.ad.models import AdFinding
    from api.modules.ad.services.snapshots import latest_snapshot as latest_ad_snapshot
    from api.modules.vm.models import VmHost

    links: dict[str, Any] = {
        "ad_finding_count": None, "ad_domain_id": None, "ad_query": None,
        "ksc_host_id": None, "ksc_server_id": None, "vm_host_id": None, "vm_cve_count": None,
    }
    live_first = sorted(rows, key=lambda r: (r.gone_at is not None, -r.seen_at.timestamp()))
    ad = next((r for r in live_first if r.source == "ad"), None)
    if ad is not None and ad.extra.get("domain_id") is not None:
        links["ad_domain_id"] = ad.extra["domain_id"]
        links["ad_query"] = ad.name
        snap = latest_ad_snapshot(db, int(ad.extra["domain_id"]))
        if snap is not None and ad.name:
            pattern = _like(ad.name)
            links["ad_finding_count"] = int(db.execute(
                select(func.count()).select_from(AdFinding).where(
                    AdFinding.snapshot_id == snap.id,
                    or_(AdFinding.identity.ilike(pattern, escape="\\"), AdFinding.target.ilike(pattern, escape="\\"),
                        AdFinding.right.ilike(pattern, escape="\\")),
                )
            ).scalar() or 0)
    ksc = next((r for r in live_first if r.source == "ksc"), None)
    if ksc is not None:
        links["ksc_host_id"] = ksc.source_key
        links["ksc_server_id"] = ksc.extra.get("server_id")
    vm = next((r for r in live_first if r.source == "vm"), None)
    if vm is not None:
        hostname, _, ip = vm.source_key.rpartition("|")
        links["vm_host_id"] = db.execute(select(VmHost.id).where(VmHost.hostname == hostname, VmHost.ip == ip)).scalar()
        links["vm_cve_count"] = vm.extra.get("cve_count")
    return links


def asset_detail(db: Session, asset_id: int, now: dt.datetime | None = None) -> dict[str, Any]:
    """Карточка: каноническое, наблюдения с подсветкой ячеек, расхождения, ссылки в модули."""
    now = now or utcnow()
    asset = _asset_or_404(db, asset_id)
    settings = load_settings(db)
    rows = _observations(db, asset.id)
    found = _found(asset, rows, settings, scan_probes(db), now)
    network = db.get(Network, asset.network_id) if asset.network_id is not None else None
    return {
        **_item(asset, rows, found, network, now, int(settings["stale_days"])),
        "network_manual": asset.network_manual, "note": asset.note, "merged_into": asset.merged_into,
        "created_at": _iso(asset.created_at), "updated_at": _iso(asset.updated_at),
        "observations": [
            {
                "id": r.id, "source": r.source, "source_key": r.source_key, "name": r.name, "fqdn": r.fqdn, "domain": r.domain,
                "ip": r.ip, "ips": list(r.ips or []), "os": r.os, "seen_at": _iso(r.seen_at), "gone_at": _iso(r.gone_at),
                "extra": dict(r.extra or {}), "marks": _marks(r, found),
            }
            for r in rows
        ],
        "discrepancies": [
            {"code": d.code, "source": d.source, "field": d.field, "value": d.value, "current": d.current, "text": d.text}
            for d in found
        ],
        "links": _links(db, rows),
    }
