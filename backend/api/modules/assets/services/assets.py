"""Активы в базе: привязка наблюдения, пересчёт карточки, ручные действия, список и карточка.

Assets читает таблицы модулей (находки AD, хосты VM) только для ссылок карточки;
модули об Assets знают одним вызовом `services.sync.request_sync`.
"""
from __future__ import annotations

import datetime as dt
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session, defer

from api.modules.assets.core.discrepancies import CODES, Discrepancy, discrepancies, finding_key
from api.modules.assets.core.matching import (
    FIELDS,
    Candidate,
    Observed,
    address_reused,
    candidate_tokens,
    canonical,
    keyed_by_address,
    match,
    normalize_fqdn,
    normalize_ip,
    normalize_name,
    tokens,
)
from api.modules.assets.models import Asset, AssetObservation, AssetSettings, Network
from api.modules.assets.services.networks import NetworkList, network_for_ip
from api.platform.filters import Values, is_all, matches, multi
from api.platform.findings import service as finding_svc
from api.platform.findings.core import STATUS_TITLES, STATUSES, is_overdue
from api.platform.findings.models import FindingState
from api.timeutil import utcnow

DEFAULT_SETTINGS: dict[str, Any] = {"inactive_days": 30, "stale_days": 30, "sync_after_import": True}
SOURCES = ("vm", "ksc", "ad", "scan", "dns", "rt")
CRITICALITY = ("Critical", "High", "Medium", "Low")
#: Фильтр и фасет LAPS: есть ли срок пароля LAPS у компьютера AD.
LAPS = ("yes", "no")
#: Фильтр и фасет «Кластер»: вид кластера Windows у компьютера AD (`extra.cluster`).
CLUSTER_KINDS = ("cluster", "role", "node")
#: Фильтр и фасет «хоть одно расхождение».
ANY_CODE = "any"
#: Расхождения — находки платформы статусов (`findings_adapter`): модуль и единственная область.
FINDINGS_MODULE = "assets"
FINDINGS_SCOPE = 0

ScanProbes = tuple[Callable[[str], bool], Callable[[str], bool | None]]


class AssetNotFound(LookupError):
    pass


class AssetConflict(Exception):
    """Действие противоречит состоянию актива (уже объединён, последнее наблюдение)."""


def load_settings(db: Session) -> dict[str, Any]:
    row = db.execute(select(AssetSettings).order_by(AssetSettings.id)).scalars().first()
    return {**DEFAULT_SETTINGS, **(row.data if row else {})}


def settings_row(db: Session) -> AssetSettings:
    """Строка настроек под блокировкой; нет — заводится. В ней же служебная просьба синхронизации."""
    row = db.execute(
        select(AssetSettings).order_by(AssetSettings.id).with_for_update().execution_options(populate_existing=True)
    ).scalars().first()
    if row is None:
        row = AssetSettings(data={})
        db.add(row)
    return row


def save_settings(db: Session, values: dict[str, Any]) -> dict[str, Any]:
    """Пороги и автосинхронизация; прочие ключи строки (просьба синхронизации) остаются."""
    row = settings_row(db)
    row.data = {**(row.data or {}), **{k: values[k] for k in DEFAULT_SETTINGS}}
    db.flush()
    return {k: row.data[k] for k in DEFAULT_SETTINGS}


def scan_probes(db: Session) -> ScanProbes:
    """Чем расхождения узнают о скане: сканируется ли сеть адреса и ответил ли он последнему скану."""
    # Импорт здесь: services.scan сам импортирует этот модуль.
    from api.modules.assets.services.scan import scan_probes as probes

    return probes(db)


def observed(row: AssetObservation, extra: dict[str, Any] | None = None) -> Observed:
    """`extra` — вместо `row.extra`: сопоставлению он не нужен (`{}`), список читает его не у всех."""
    return Observed(
        source=row.source, source_key=row.source_key, name=row.name, fqdn=row.fqdn, domain=row.domain, ip=row.ip,
        ips=list(row.ips or []), os=row.os, seen_at=row.seen_at, gone_at=row.gone_at,
        extra=dict(row.extra or {}) if extra is None else extra,
    )


# ---- Индекс кандидатов ----------------------------------------------------


def domain_map(db: Session) -> dict[str, str]:
    """NetBIOS-имя домена → DNS-домен по доменам AD (их заполняет импорт выгрузки)."""
    from api.modules.ad.models import AdDomain

    return {
        d.netbios.lower(): d.dns_root.lower()
        for d in db.execute(select(AdDomain).order_by(AdDomain.id)).scalars() if d.netbios and d.dns_root
    }


def _short_name_sql(column: Any) -> Any:
    """`normalize_name(...)[0]` в SQL: `CORP\\WS01$`, `ws01.corp.local.` → `ws01` (Postgres)."""
    text = func.regexp_replace(func.lower(func.trim(column)), r"^.*\\", "")
    return func.rtrim(func.split_part(text, ".", 1), "$")


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
        self.domain_map: dict[str, str] = {}

    @classmethod
    def load(cls, db: Session, asset_ids: Iterable[int] | None = None) -> MatchIndex:
        index = cls()
        index.domain_map = domain_map(db)
        stmt = select(Asset).where(Asset.merged_into.is_(None))
        if asset_ids is not None:
            ids = list(asset_ids)
            if not ids:
                return index
            stmt = stmt.where(Asset.id.in_(ids))
        assets = {a.id: a for a in db.execute(stmt).scalars()}
        per_asset: dict[int, list[Observed]] = defaultdict(list)
        if assets:
            # extra сопоставлению не нужен, а у KSC и VM он самый тяжёлый.
            rows = db.execute(
                select(AssetObservation).options(defer(AssetObservation.extra))
                .where(AssetObservation.asset_id.in_(list(assets))).order_by(AssetObservation.id)
            ).scalars()
            for row in rows:
                per_asset[row.asset_id].append(observed(row, extra={}))
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
            _short_name_sql(AssetObservation.name).in_(shorts),
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
    card = canonical([observed(r, extra={}) for r in rows], dict(asset.pinned or {}), {f: getattr(asset, f) for f in FIELDS})
    for name in FIELDS:
        setattr(asset, name, card[name])
    asset.name_key = normalize_name(asset.name)[0] or normalize_name(asset.fqdn)[0]
    asset.first_seen = card["first_seen"]
    asset.last_seen = card["last_seen"]
    if not asset.network_manual:
        asset.network_id = network_for_ip(networks if networks is not None else db, asset.ip)
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
    `index`, `rows`, `networks` — заготовки синхронизации; без них всё читается из базы.
    Адрес, перешедший к другому хосту (скан или PTR с незнакомым активу именем), не переименовывает
    старый актив: его наблюдение уходит в историю, а новое сопоставляется заново по правилам 2–5."""
    idx = index if index is not None else MatchIndex.for_observation(db, obs)
    candidates = idx.candidates_for(obs)
    asset_id, rule = match(obs, candidates, idx.domain_map)
    if asset_id is not None and rule == 1 and keyed_by_address(obs) and address_reused(obs, next(c for c in candidates if c.asset_id == asset_id)):
        _release_address(db, obs, asset_id, idx, rows, networks)
        asset_id, rule = match(obs, idx.candidates_for(obs), idx.domain_map)
    asset = db.get(Asset, asset_id) if asset_id is not None else None
    if asset is None:
        asset = Asset()
        db.add(asset)
        db.flush()
    key = (obs.source, obs.source_key)
    row = _row(db, key, rows)
    if row is None:
        row = AssetObservation(source=obs.source, source_key=obs.source_key)
        db.add(row)
        if rows is not None:
            rows[key] = row
    row.asset_id = asset.id
    row.name, row.fqdn, row.domain, row.ip, row.os = obs.name, obs.fqdn, obs.domain, normalize_ip(obs.ip), obs.os
    row.ips = list(dict.fromkeys(a for a in (normalize_ip(x) for x in obs.ips) if a))
    row.seen_at = obs.seen_at or utcnow()
    row.extra = dict(obs.extra)
    row.gone_at = None
    db.flush()
    recompute(db, asset, networks)
    idx.put(asset, [observed(r, extra={}) for r in _observations(db, asset.id)])
    return asset, rule


def _row(db: Session, key: tuple[str, str], rows: dict[tuple[str, str], AssetObservation] | None) -> AssetObservation | None:
    if rows is not None:
        return rows.get(key)
    return db.execute(
        select(AssetObservation).where(AssetObservation.source == key[0], AssetObservation.source_key == key[1])
    ).scalar_one_or_none()


def _release_address(
    db: Session, obs: Observed, asset_id: int, idx: MatchIndex,
    rows: dict[tuple[str, str], AssetObservation] | None, networks: NetworkList | None,
) -> None:
    """Наблюдение старого хоста по этому адресу — в историю: ключ `<адрес>#<id строки>` (ключ
    уникален, а адрес теперь у другого), gone_at; правило 1 его больше не находит."""
    key = (obs.source, obs.source_key)
    row = _row(db, key, rows)
    if row is None:
        return
    row.source_key = f"{row.source_key}#{row.id}"
    row.gone_at = obs.seen_at or utcnow()
    if rows is not None:
        del rows[key]
        rows[(row.source, row.source_key)] = row
    db.flush()
    old = db.get(Asset, asset_id)
    if old is not None:
        recompute(db, old, networks)
        idx.put(old, [observed(r, extra={}) for r in _observations(db, old.id)])


def lookup_asset(db: Session, source: str, key: str) -> int:
    """Актив по ключу наблюдения источника — ссылка «в Assets» у хоста модуля. Объединение
    переносит наблюдения к первому активу, поэтому ссылка ведёт к живому."""
    asset_id = db.execute(
        select(AssetObservation.asset_id).where(AssetObservation.source == source, AssetObservation.source_key == key)
    ).scalar()
    if asset_id is None:
        raise AssetNotFound("хост не сопоставлен с активом")
    return int(asset_id)


def _asset_or_404(db: Session, asset_id: int) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise AssetNotFound("актив не найден")
    return asset


def merge_assets(db: Session, into_id: int, other_id: int, actor: str) -> Asset:
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
    _move_decisions(db, other.id, into.id, actor)
    return into


def _move_decisions(db: Session, old_id: int, new_id: int, actor: str) -> None:
    """Решения по расхождениям поглощённого актива — к оставшемуся: в ключе находки id актива.
    Если у оставшегося решение по тому же ключу уже есть, прежнее остаётся при старом ключе
    (расхождения у объединённого актива нет — сверка его закроет)."""
    prefix = f"{old_id}|"
    keys = list(db.scalars(select(FindingState.key).where(
        FindingState.module == FINDINGS_MODULE, FindingState.scope_id == FINDINGS_SCOPE,
        FindingState.key.startswith(prefix, autoescape=True),
    )))
    for key in keys:
        finding_svc.rekey(db, FINDINGS_MODULE, FINDINGS_SCOPE, key, f"{new_id}|{key[len(prefix):]}", actor=actor)


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


def delete_assets(db: Session, ids: list[int]) -> int:
    """Удалить активы с наблюдениями; число удалённых. У активов, объединённых в удалённый, ссылка
    `merged_into` обнуляется; решения по его расхождениям закроет сверка находок как исчезнувшие.
    Актив, которого источник всё ещё видит, вернётся при следующей синхронизации — удаление не
    скрывает хост, а чистит реестр от того, чего уже нет."""
    deleted = 0
    for start in range(0, len(ids), BULK_CHUNK):
        chunk = ids[start : start + BULK_CHUNK]
        for asset in db.execute(select(Asset).where(Asset.id.in_(chunk))).scalars():
            db.delete(asset)
            deleted += 1
    db.flush()
    return deleted


#: Столько id за раз уходит в один запрос массового изменения (параметров у запроса не больше 65 535).
BULK_CHUNK = 10_000


def bulk_update(
    db: Session, ids: list[int], *, criticality: str | None = None, tags_add: Iterable[str] = (), tags_remove: Iterable[str] = (),
) -> int:
    """Критичность и теги у многих активов разом: теги добавляются к имеющимся и снимаются, а не
    заменяются; `criticality=None` — не менять. Несуществующие и объединённые пропускаются; число изменённых."""
    add = [t.strip() for t in tags_add if t.strip()]
    remove = {t.strip() for t in tags_remove}
    updated = 0
    for start in range(0, len(ids), BULK_CHUNK):
        chunk = ids[start : start + BULK_CHUNK]
        for asset in db.execute(select(Asset).where(Asset.id.in_(chunk), Asset.merged_into.is_(None))).scalars():
            if criticality is not None:
                asset.criticality = criticality
            if add or remove:
                asset.tags = [t for t in dict.fromkeys([*(asset.tags or []), *add]) if t not in remove]
            updated += 1
    db.flush()
    return updated


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


def _found(asset: Asset, observations: list[Observed], settings: dict[str, Any], probes: ScanProbes, now: dt.datetime) -> list[Discrepancy]:
    scanned, alive = probes
    found = discrepancies(
        _card(asset), observations, stale_days=int(settings["stale_days"]), inactive_days=int(settings["inactive_days"]),
        scanned_networks=scanned, scan_alive=alive, now=now,
    )
    if asset.ip and asset.network_id is None and any(o.gone_at is None for o in observations):
        found.append(Discrepancy("no_network", "", "network", asset.ip, "", f"сеть не описана: адрес {asset.ip} не входит ни в одну сеть"))
    return found


@dataclass(slots=True)
class Tracked:
    """Расхождение с решением людей по нему (строка состояния; None — решений не было, `new`)."""

    d: Discrepancy
    key: str
    state: FindingState | None

    @property
    def status(self) -> str:
        return finding_svc.effective_status(self.state)

    @property
    def assignee(self) -> str | None:
        return self.state.assignee if self.state is not None else None

    @property
    def due_date(self) -> dt.date | None:
        return self.state.due_date if self.state is not None else None


def _tracked(asset_id: int, found: list[Discrepancy], states: dict[str, FindingState]) -> list[Tracked]:
    out = []
    for d in found:
        key = finding_key(asset_id, d)
        out.append(Tracked(d, key, states.get(key)))
    return out


@dataclass(frozen=True)
class DiscFilter:
    """Фильтр «есть расхождение под всеми условиями»: коды (`any` — любой), статусы (None — любые),
    исполнители (логины и `none`), просрочено. Без статусов в запросе — учитываемые
    (`counted_statuses`): так и до статусов фильтр по коду не видел решённого."""

    code: frozenset[str] | None = None
    statuses: frozenset[str] | None = None
    assignee: frozenset[str] | None = None
    overdue: bool = False
    #: Задан ли фильтр по расхождениям вообще; нет — активы не отбираются по ним.
    active: bool = False


def disc_filter(
    counted: frozenset[str], *, code: frozenset[str] | None = None, disc_status: Values = None,
    assignee: Values = None, overdue: bool | None = None, login: str = "",
) -> DiscFilter:
    """`disc_status` — коды статусов (повтором или через запятую) или `all`; неизвестный статус —
    ValueError. `assignee` — `me`, `none` и логины."""
    picked = multi(disc_status, commas=True)
    # Фильтр по расхождениям включает разобранный статус, а не сырая строка: `disc_status=,` — не задан.
    by_status = picked is not None or is_all(disc_status)
    statuses: frozenset[str] | None
    if is_all(disc_status):
        statuses = None
    elif picked is None:
        statuses = counted
    elif unknown := picked - set(STATUSES):
        raise ValueError(f"неизвестный статус: {', '.join(sorted(unknown))}")
    else:
        statuses = picked
    who = multi(assignee)
    whom = frozenset(login if a == "me" else a for a in who) if who else None
    return DiscFilter(code, statuses, whom, bool(overdue), active=bool(code or by_status or whom or overdue))


def _hits(t: Tracked, f: DiscFilter, today: dt.date, *, code: bool = True, status: bool = True, overdue: bool = True) -> bool:
    """Подходит ли расхождение под фильтр; `code`/`status`/`overdue=False` — без этой части (фасеты)."""
    if code and f.code and ANY_CODE not in f.code and t.d.code not in f.code:
        return False
    if status and f.statuses is not None and t.status not in f.statuses:
        return False
    if not matches(t.assignee or "none", f.assignee):
        return False
    return not (overdue and f.overdue and not is_overdue(t.status, t.due_date, today))


def _item(asset: Asset, rows: list[AssetObservation], tracked: list[Tracked], network: Network | None, now: dt.datetime,
          stale_days: int, counted: frozenset[str], cluster: str | None) -> dict[str, Any]:
    """Счётчик и коды расхождений — только с учитываемым статусом: принятый риск не «висит».
    `cluster` — cluster | role | node из наблюдения AD: учётка кластера и роль — виртуальные имена."""
    live = [t.d for t in tracked if t.status in counted]
    return {
        "cluster": cluster,
        "id": asset.id, "name": asset.name, "fqdn": asset.fqdn, "domain": asset.domain, "ip": asset.ip, "os": asset.os,
        "network": _network_view(network), "first_seen": _iso(asset.first_seen), "last_seen": _iso(asset.last_seen),
        "criticality": asset.criticality, "tags": list(asset.tags or []), "pinned": dict(asset.pinned or {}),
        "sources": _sources(rows, now, stale_days), "discrepancy_count": len(live), "codes": sorted({d.code for d in live}, key=CODES.index),
    }


def cluster_kinds(db: Session) -> dict[int, str]:
    """asset_id → cluster | role | node по живым наблюдениям AD (`extra.cluster`) — одним запросом на список."""
    kind = AssetObservation.extra["cluster"].as_string()
    return dict(db.execute(
        select(AssetObservation.asset_id, kind).where(AssetObservation.source.in_(("ad",)), AssetObservation.gone_at.is_(None), kind.is_not(None))
    ).tuples().all())


def laps_flags(db: Session) -> dict[int, bool]:
    """asset_id → есть ли LAPS по живым наблюдениям AD (`extra.laps`); актива без них в словаре нет,
    как и наблюдений до появления признака (до следующей синхронизации). Компьютер в двух
    доменах — LAPS есть, если он есть хоть в одном."""
    flag = AssetObservation.extra["laps"].as_boolean()
    out: dict[int, bool] = {}
    for asset_id, laps in db.execute(
        select(AssetObservation.asset_id, flag).where(AssetObservation.source.in_(("ad",)), AssetObservation.gone_at.is_(None), flag.is_not(None))
    ).tuples():
        out[asset_id] = out.get(asset_id, False) or bool(laps)
    return out


def _matches_query(asset: Asset, rows: list[AssetObservation], needle: str) -> bool:
    texts = [asset.name, asset.fqdn, asset.ip, asset.os]
    for r in rows:
        texts += [r.name, r.fqdn, r.ip, *(r.ips or [])]
    return any(needle in (t or "").lower() for t in texts)


def _open_ports(observations: list[Observed]) -> set[int]:
    return {int(p) for o in observations if o.source == "scan" and o.gone_at is None for p in o.extra.get("ports", [])}


#: Чей extra нужен списку: порты скана, вход и включённость AD, тип записи DNS. У KSC и VM
#: extra тяжёлый (компоненты, группы) и списку не нужен — его читает только карточка.
LIST_EXTRA_SOURCES = ("scan", "ad", "dns")


Picked = list[tuple[Asset, list[AssetObservation], list[Discrepancy]]]


def _pick(
    db: Session,
    *,
    networks: dict[int, Network],
    settings: dict[str, Any],
    now: dt.datetime,
    with_found: bool,
    q: str | None = None,
    source_has: frozenset[str] | None = None,
    source_missing: frozenset[str] | None = None,
    network_id: frozenset[int] | None = None,
    zone: frozenset[str] | None = None,
    port: int | None = None,
    tag: str | None = None,
    criticality: frozenset[str] | None = None,
    laps: frozenset[str] | None = None,
    cluster: frozenset[str] | None = None,
    ad_keys: frozenset[str] | None = None,
) -> Picked:
    """Активы под фильтрами списка по данным: (актив, наблюдения, расхождения). Многозначные фильтры —
    «любое из»: `source_has` — есть хоть один из источников, `source_missing` — нет хоть одного,
    `criticality` `none` — не задана, `laps` — yes | no (актив без наблюдения AD не подходит ни под одно), `cluster` — cluster | role | node,
    `ad_keys` — есть наблюдение AD (и пропавшее) с ключом из состава ячейки сводки AD. Расхождения
    считаются на лету, поэтому фильтры — в памяти; фильтр по расхождениям и их статусам — у
    вызывающего (`DiscFilter`). `with_found=False` — расхождения не считаются и остаются пустыми
    (выбор id для массового изменения без фильтра по расхождениям)."""
    probes = scan_probes(db) if with_found else None
    # Наблюдения с extra нужны расхождениям и фильтру по порту; без них extra не читается вовсе.
    need_observed = probes is not None or port is not None
    assets = list(db.execute(select(Asset).where(Asset.merged_into.is_(None))).scalars())
    per_asset: dict[int, list[AssetObservation]] = defaultdict(list)
    for row in db.execute(select(AssetObservation).options(defer(AssetObservation.extra)).order_by(AssetObservation.id)).scalars():
        per_asset[row.asset_id].append(row)
    extras: dict[int, dict[str, Any]] = dict(db.execute(
        select(AssetObservation.id, AssetObservation.extra).where(AssetObservation.source.in_(LIST_EXTRA_SOURCES))
    ).tuples().all()) if need_observed else {}
    needle = (q or "").strip().lower()
    laps_of = laps_flags(db) if laps else {}
    kind_of = cluster_kinds(db) if cluster else {}

    picked: Picked = []
    for asset in assets:
        rows = per_asset[asset.id]
        live = {r.source for r in rows if r.gone_at is None}
        if source_has and not source_has & live:
            continue
        if source_missing and source_missing <= live:
            continue
        if network_id is not None and asset.network_id not in network_id:
            continue
        net = networks.get(asset.network_id) if asset.network_id is not None else None
        # '' в наборе (`-` в запросе) — актив без зоны: вне сетей или в сети без зоны.
        if not matches(net.zone if net is not None else None, zone):
            continue
        if tag and tag not in (asset.tags or []):
            continue
        # «Не задана» — `none` (как в фасете) или '' (`-` в запросе, общий знак пустого значения).
        if criticality is not None and not {asset.criticality or "none", asset.criticality or ""} & criticality:
            continue
        if laps and (asset.id not in laps_of or ("yes" if laps_of[asset.id] else "no") not in laps):
            continue
        if cluster and kind_of.get(asset.id) not in cluster:
            continue
        if ad_keys is not None and not any(r.source == "ad" and r.source_key in ad_keys for r in rows):
            continue
        if needle and not _matches_query(asset, rows, needle):
            continue
        observations = [observed(r, extra=dict(extras.get(r.id) or {})) for r in rows] if need_observed else []
        if port is not None and port not in _open_ports(observations):
            continue
        found = _found(asset, observations, settings, probes, now) if probes is not None else []
        picked.append((asset, rows, found))
    return picked


def current_discrepancies(db: Session, now: dt.datetime | None = None) -> list[tuple[Asset, list[Discrepancy]]] | None:
    """Все расхождения всех активов — тем же расчётом, что список и карточка: статусы находок
    (`findings_adapter`) видят ровно то, что люди. None — в реестре нет ни одного актива."""
    if db.scalar(select(Asset.id).where(Asset.merged_into.is_(None)).limit(1)) is None:
        return None
    networks = {n.id: n for n in db.execute(select(Network)).scalars()}
    picked = _pick(db, networks=networks, settings=load_settings(db), now=now or utcnow(), with_found=True)
    return [(asset, found) for asset, _, found in picked]


def finding_title(asset: Asset, d: Discrepancy) -> str:
    """Подпись расхождения для «Моих находок»: «<актив>: <текст>»."""
    return f"{asset.name or asset.fqdn or asset.ip or f'актив #{asset.id}'}: {d.text}"


def discrepancy_keys(db: Session, ids: Iterable[int], code: str) -> list[str]:
    """Ключи расхождений кода у этих активов — тех, что есть сейчас (у расхождений полей — все
    ключи кода у актива): массовая смена не заводит строк для расхождений, которых нет."""
    wanted = set(ids)
    keys: dict[str, None] = {}
    for asset, found in current_discrepancies(db) or []:
        if asset.id in wanted:
            keys.update((finding_key(asset.id, d), None) for d in found if d.code == code)
    return list(keys)


def _states(db: Session) -> dict[str, FindingState]:
    return finding_svc.state_map(db, FINDINGS_MODULE, FINDINGS_SCOPE)


def _disc_split(picked: Picked, f: DiscFilter, states: dict[str, FindingState], today: dt.date) -> tuple[list[tuple[Asset, list[AssetObservation], list[Tracked]]], list[list[Tracked]]]:
    """(активы под фильтром по расхождениям, расхождения всех активов под фильтрами по данным)."""
    all_tracked = [_tracked(asset.id, found, states) for asset, _, found in picked]
    passed = [
        (asset, rows, tracked) for (asset, rows, _), tracked in zip(picked, all_tracked, strict=True)
        if not f.active or any(_hits(t, f, today) for t in tracked)
    ]
    return passed, all_tracked


def matching_ids(
    db: Session, *, code: frozenset[str] | None = None, disc_status: Values = None, assignee: Values = None,
    overdue: bool | None = None, login: str = "", **filters: Any,
) -> list[int]:
    """Id всех активов под фильтрами списка — без фасетов и строк, а расхождения считаются,
    только если задан фильтр по ним."""
    f = disc_filter(finding_svc.counted_statuses(db), code=code, disc_status=disc_status, assignee=assignee,
                    overdue=overdue, login=login)
    networks = {n.id: n for n in db.execute(select(Network)).scalars()}
    picked = _pick(db, networks=networks, settings=load_settings(db), now=utcnow(), with_found=f.active, **filters)
    if not f.active:
        return [asset.id for asset, _, _ in picked]
    passed, _ = _disc_split(picked, f, _states(db), finding_svc.today())
    return [asset.id for asset, _, _ in passed]


def list_assets(
    db: Session,
    *,
    limit: int = 200,
    offset: int = 0,
    now: dt.datetime | None = None,
    code: frozenset[str] | None = None,
    disc_status: Values = None,
    assignee: Values = None,
    overdue: bool | None = None,
    login: str = "",
    **filters: Any,
) -> tuple[list[dict[str, Any]], int, dict[str, Any]]:
    """items, total, facets; `filters` — как у `_pick`, фильтр по расхождениям — `disc_filter`.
    Фасеты — в памяти, как у хостов KSC; `criticality='none'` — критичность не задана;
    `code='any'` — хоть одно расхождение (фасет `code.any` — сколько таких). Фасет `code` считает
    расхождения под статусами фильтра (по умолчанию учитываемые); `disc_status` — расхождения по
    статусам без фильтра статуса, `disc_overdue` — просроченные без фильтра статуса и срока: оба
    по активам под фильтрами по данным."""
    now = now or utcnow()
    settings = load_settings(db)
    counted = finding_svc.counted_statuses(db)
    f = disc_filter(counted, code=code, disc_status=disc_status, assignee=assignee, overdue=overdue, login=login)
    today = finding_svc.today()
    networks = {n.id: n for n in db.execute(select(Network)).scalars()}
    data = _pick(db, networks=networks, settings=settings, now=now, with_found=True, **filters)
    picked, all_tracked = _disc_split(data, f, _states(db), today)

    facets: dict[str, Any] = {
        "source": dict.fromkeys(SOURCES, 0), "code": dict.fromkeys((*CODES, ANY_CODE), 0), "zone": {},
        "criticality": dict.fromkeys([*CRITICALITY, "none"], 0),
        "disc_status": dict.fromkeys(STATUSES, 0), "disc_overdue": 0, "laps": dict.fromkeys(LAPS, 0),
        "cluster": dict.fromkeys(CLUSTER_KINDS, 0),
    }
    laps_of = laps_flags(db)
    clusters = cluster_kinds(db)
    for tracked in all_tracked:
        for t in tracked:
            if _hits(t, f, today, status=False):
                facets["disc_status"][t.status] += 1
            if _hits(t, f, today, status=False, overdue=False) and is_overdue(t.status, t.due_date, today):
                facets["disc_overdue"] += 1
    for asset, rows, tracked in picked:
        for source in {r.source for r in rows if r.gone_at is None}:
            facets["source"][source] += 1
        codes = {t.d.code for t in tracked if _hits(t, f, today, code=False)}
        for c in codes:
            facets["code"][c] += 1
        if codes:
            facets["code"][ANY_CODE] += 1
        net = networks.get(asset.network_id) if asset.network_id is not None else None
        if net is not None and net.zone:
            facets["zone"][net.zone] = facets["zone"].get(net.zone, 0) + 1
        facets["criticality"][asset.criticality or "none"] = facets["criticality"].get(asset.criticality or "none", 0) + 1
        if asset.id in laps_of:
            facets["laps"]["yes" if laps_of[asset.id] else "no"] += 1
        if asset.id in clusters:
            facets["cluster"][clusters[asset.id]] += 1

    picked.sort(key=lambda t: (t[0].name_key or normalize_fqdn(t[0].fqdn) or "~", t[0].ip, t[0].id))
    stale_days = int(settings["stale_days"])
    page = [
        _item(asset, rows, tracked, networks.get(asset.network_id) if asset.network_id is not None else None, now, stale_days, counted, clusters.get(asset.id))
        for asset, rows, tracked in picked[offset : offset + limit]
    ]
    return page, len(picked), facets


def _marks(row: AssetObservation, found: list[Discrepancy]) -> dict[str, str]:
    """Какие ячейки строки источника подсветить: поле → stale | conflict."""
    marks: dict[str, str] = {}
    for d in found:
        if d.code in ("stale", "conflict") and d.source == row.source and getattr(row, d.field, None) == d.value:
            marks[d.field] = d.code
    return marks


def _computer_names(ad: AssetObservation, domains: Iterable[str]) -> set[str]:
    """Как компьютер записан в находках AD: `CORP\\ws01$`, `ws01$`, `ws01`, FQDN, DN — целиком,
    без учёта регистра (подстрока `ws01` нашла бы и `ws010`)."""
    name = ad.name.lower()
    names = {name, f"{name}$", ad.fqdn.lower(), str(ad.extra.get("dn") or "").lower()}
    for prefix in (d.lower() for d in domains if d):
        names |= {f"{prefix}\\{name}$", f"{prefix}\\{name}"}
    return {n for n in names if n}


def _links(db: Session, rows: list[AssetObservation]) -> dict[str, Any]:
    """«Где засветился»: находки AD по компьютеру, хост антивируса, хост VM."""
    from api.modules.ad.models import AdDomain, AdFinding
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
            domain = db.get(AdDomain, int(ad.extra["domain_id"]))
            names = _computer_names(ad, (domain.netbios, domain.dns_root) if domain is not None else ())
            keys = list(db.scalars(select(AdFinding.key).where(
                AdFinding.snapshot_id == snap.id,
                or_(func.lower(AdFinding.identity).in_(names), func.lower(AdFinding.target).in_(names),
                    AdFinding.identity_sid == ad.source_key),
            )))
            # Как обзор AD: только находки с учитываемым статусом (настройка `counted`).
            counted = finding_svc.counted_statuses(db)
            states = finding_svc.state_map(db, "ad", snap.domain_id, keys)
            links["ad_finding_count"] = sum(finding_svc.is_counted(states.get(k), counted) for k in keys)
    ksc = next((r for r in live_first if r.source == "ksc"), None)
    if ksc is not None:
        # Ключ KSC — «server_id:host_id».
        links["ksc_host_id"] = ksc.source_key.partition(":")[2] or ksc.source_key
        links["ksc_server_id"] = ksc.extra.get("server_id")
    vm = next((r for r in live_first if r.source == "vm"), None)
    if vm is not None:
        hostname, _, ip = vm.source_key.rpartition("|")
        links["vm_host_id"] = db.execute(select(VmHost.id).where(VmHost.hostname == hostname, VmHost.ip == ip)).scalar()
        links["vm_cve_count"] = vm.extra.get("cve_count")
    return links


def asset_detail(db: Session, asset_id: int, now: dt.datetime | None = None) -> dict[str, Any]:
    """Карточка: каноническое, наблюдения с подсветкой ячеек, расхождения, ссылки в модули,
    пользователи хоста (`services.user_views.host_users`)."""
    # Импорт здесь: services.users (его берёт user_views) сам импортирует этот модуль.
    from api.modules.assets.services.user_views import host_users

    now = now or utcnow()
    asset = _asset_or_404(db, asset_id)
    settings = load_settings(db)
    rows = _observations(db, asset.id)
    found = _found(asset, [observed(r) for r in rows], settings, scan_probes(db), now)
    network = db.get(Network, asset.network_id) if asset.network_id is not None else None
    counted = finding_svc.counted_statuses(db)
    keys = [finding_key(asset.id, d) for d in found]
    tracked = _tracked(asset.id, found, finding_svc.state_map(db, FINDINGS_MODULE, FINDINGS_SCOPE, keys))
    today = finding_svc.today()
    cluster = next((str(r.extra["cluster"]) for r in rows if r.source == "ad" and r.gone_at is None and (r.extra or {}).get("cluster")), None)
    return {
        **_item(asset, rows, tracked, network, now, int(settings["stale_days"]), counted, cluster),
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
        # Все расхождения, и с неучитываемым статусом тоже: решение видно там, где его приняли.
        "discrepancies": [
            {"code": t.d.code, "source": t.d.source, "field": t.d.field, "value": t.d.value, "current": t.d.current,
             "text": t.d.text, "key": t.key, "status": t.status, "status_title": STATUS_TITLES[t.status],
             "assignee": t.assignee, "due_date": t.due_date.isoformat() if t.due_date else None,
             "overdue": is_overdue(t.status, t.due_date, today),
             "risk_until": t.state.risk_until.isoformat() if t.state is not None and t.state.risk_until else None,
             "counted": t.status in counted}
            for t in tracked
        ],
        "links": _links(db, rows),
        **host_users(db, asset.id, rows),
    }
