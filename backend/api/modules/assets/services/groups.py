"""Синхронизация групп (спека «Группы как активы» §3, §5): шаг прохода `assets/sync` после пользователей —
участникам нужны уже записанные пользователи и активы-хосты.

- AD — все объекты `group` с SID последнего снапшота каждого домена из файла выгрузки (общий `AdExportCache`
  прохода), встроенные группы Builtin (`S-1-5-32-*`) — тоже, ключ с доменом (`core.groups.group_key`).
- Участники из `member` (DN → объект выгрузки): учётка — пользователь (`asset_user` по SID; не пользователь-актив,
  например gMSA, — `user` без связи), компьютер — актив по наблюдению `ad` с ключом `o.sid or o.dn` (через
  `Asset.merged_into` — к выжившему), группа — группа этого домена; DN из ForeignSecurityPrincipals — по SID:
  встроенный субъект (`well_known`), пользователь, доменная группа другого домена, иначе `unknown`; DN, которого
  нет в выгрузке, — `unknown` с DN в имени. Плюс пользователи и компьютеры, чья основная группа (`primaryGroupID`)
  — эта группа, с `primary`; уже пришедший через `member` остаётся одной строкой. Строка участника уникальна по
  (SID, имя); состав AD группы прочитанного домена заменяется целиком.
- Пропавшие: группа AD, которой нет в выгрузке своего домена, — `gone_at`, её участники AD удаляются; домен,
  чей файл не прочитан, не трогается; домен, которого в модуле AD больше нет, — как прочитанный пустой. Если её
  ещё видит VM (источник `vm`), она не пропавшая: источник только `vm`, `in_ad=False`, состав AD снимается.
- VM (`_sync_vm`): локальные группы хостов из `vm_host_group` последнего снимка `vm_group_import`, хост — актив
  (`_match_vm_hosts`), кроме контроллеров домена; состав — строками `source="vm"` той же сверкой, что у AD.
  Доменная группа-участник, которой нет в AD, заводится с `sources=["vm"]`, `in_ad=False`.
- Права по политике: `ad.core.gpo_rights` — строки `asset_group_gpo` домена (замена), хостов не больше
  `GPO_HOSTS_MAX`; оговорки ответа — служебный ключ настроек `groups_gpo_notes` по DNS-домену.
"""
from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy import delete, func, insert, or_, select, tuple_, update
from sqlalchemy.orm import Session

from api.jobs import JobHandle
from api.modules.assets.core.groups import group_key, is_well_known, normalize_sid
from api.modules.assets.core.matching import Observed, match, normalize_fqdn
from api.modules.assets.models import (
    Asset,
    AssetGroup,
    AssetGroupGpo,
    AssetGroupMember,
    AssetObservation,
    AssetUser,
)
from api.modules.assets.services.assets import MatchIndex, domain_map, load_settings, settings_row
from api.modules.assets.services.users import CHUNK, TICK_EVERY, AdExportCache, read_ad_export

if TYPE_CHECKING:
    from api.modules.ad.core.export import AdObject, ExportIndex

log = logging.getLogger("stools.assets")

GPO_NOTES_KEY = "groups_gpo_notes"
#: Хостов в строке `asset_group_gpo` не больше; полное число — `hosts_total`.
GPO_HOSTS_MAX = 1000
#: Классы учёток AD, участники-«пользователи» (связь — только если учётка стала пользователем-активом).
USER_CLASSES = frozenset({"user", "inetOrgPerson", "msDS-GroupManagedServiceAccount", "msDS-ManagedServiceAccount"})
#: Состав сверяется пачками: не больше стольких групп за раз (и примерно `CHUNK` строк).
MEMBER_BATCH_GROUPS = 2000
FIELD_LEN = 255
NAME_LEN = 512
KEY_LEN = 600
DN_LEN = 1024


def _cut(value: Any, size: int = FIELD_LEN) -> str:
    return str(value or "")[:size]


def _text(value: Any) -> str:
    """Атрибут, которого нет в модели выгрузки (`description`): строка или список строк."""
    if isinstance(value, list):
        return "\n".join(str(v) for v in value if v)
    return str(value or "")


@dataclass
class _AdDomainRead:
    dns: str
    seen_at: dt.datetime
    idx: ExportIndex


@dataclass
class _AdRead:
    domains: list[_AdDomainRead] = field(default_factory=list)
    #: Домены (DNS, иначе NetBIOS), чья последняя выгрузка не прочитана: их группы не трогаются.
    failed: set[str] = field(default_factory=set)


def _read_ad(db: Session, data_dir: Path, cache: AdExportCache | None) -> _AdRead:
    from api.modules.ad.core.export import ExportFormatError, ExportIndex
    from api.modules.ad.models import AdDomain
    from api.modules.ad.services.snapshots import latest_snapshot

    out = _AdRead()
    for domain in db.execute(select(AdDomain).order_by(AdDomain.id)).scalars():
        snap = latest_snapshot(db, domain.id)
        if snap is None:
            continue
        try:
            export = read_ad_export(cache, data_dir, snap.id)
        except (ExportFormatError, OSError, ValueError) as exc:
            out.failed.add((domain.dns_root or domain.netbios or "").lower())
            log.warning("снапшот AD #%s не прочитан для групп: %s", snap.id, type(exc).__name__)
            continue
        dns = (export.domain.dns_root or domain.dns_root or export.domain.netbios or domain.netbios or "").lower()
        out.domains.append(_AdDomainRead(dns, snap.collected_at, ExportIndex(export)))
    return out


def _alive(db: Session) -> Callable[[int], int]:
    """Актив → выживший по цепочке `Asset.merged_into`."""
    merged = {a: m for a, m in db.execute(select(Asset.id, Asset.merged_into).where(Asset.merged_into.is_not(None))).tuples() if m is not None}

    def alive(asset_id: int) -> int:
        seen: set[int] = set()
        while asset_id in merged and asset_id not in seen:
            seen.add(asset_id)
            asset_id = merged[asset_id]
        return asset_id

    return alive


def _live_assets(db: Session) -> dict[str, int]:
    """Ключ наблюдения AD компьютера → актив-выживший."""
    alive = _alive(db)
    rows = db.execute(select(AssetObservation.source_key, AssetObservation.asset_id).where(AssetObservation.source == "ad")).tuples()
    return {key: alive(int(asset_id)) for key, asset_id in rows}


def _upsert_ad_groups(db: Session, handle: JobHandle, ad: _AdRead, now: dt.datetime) -> tuple[dict[str, int], int]:
    """Группы AD прочитанных доменов и пропавшие; (ключ группы → id, групп без SID пропущено)."""
    existing = {g.group_key: g for g in db.execute(select(AssetGroup).where(AssetGroup.local.is_(False))).scalars()}
    seen: set[str] = set()
    skipped = done = 0
    total = sum(len(d.idx.objects("group")) for d in ad.domains)
    handle.stage("groups", total=total, message=f"группы: AD {total}")
    for d in ad.domains:
        for o in d.idx.objects("group"):
            done += 1
            if done % TICK_EVERY == 0:
                handle.tick(done)
            if not o.sid:
                skipped += 1
                continue
            name = _cut(o.sam or o.name, NAME_LEN)
            key = _cut(group_key(local=False, domain=d.dns, host_asset_id=None, sid=o.sid, name=name), KEY_LEN)
            if key in seen:
                continue
            seen.add(key)
            values: dict[str, Any] = {
                "sid": _cut(normalize_sid(o.sid)), "name": name, "domain": _cut(d.dns), "description": _text(getattr(o, "description", None)),
                "in_ad": True, "last_seen": d.seen_at, "gone_at": None,
            }
            g = existing.get(key)
            if g is None:
                g = AssetGroup(group_key=key, local=False, sources=["ad"], first_seen=d.seen_at, **values)
                db.add(g)
                existing[key] = g
                continue
            if "ad" not in (g.sources or []):
                values["sources"] = sorted({*(g.sources or []), "ad"})
            if g.first_seen is None or g.first_seen > d.seen_at:
                values["first_seen"] = d.seen_at
            for attr, value in values.items():
                if getattr(g, attr) != value:
                    setattr(g, attr, value)
    for key, g in existing.items():
        if key in seen or "ad" not in (g.sources or []) or g.domain in ad.failed:
            continue
        if "vm" in g.sources:
            # Её ещё видит VM (участником локальной группы): не пропавшая, источник — только VM, состав AD снимается.
            g.sources = [s for s in g.sources if s != "ad"]
            g.in_ad = False
        elif g.gone_at is None:
            g.gone_at = now
    db.flush()
    return {key: g.id for key, g in existing.items() if key in seen}, skipped


@dataclass
class _Lookup:
    users: dict[str, int]
    assets: dict[str, int]
    #: SID доменной группы (S-1-5-21-…) → живая группа AD любого домена: для участников из FSP.
    groups_by_sid: dict[str, int]
    keys: dict[str, int]


def _member_key(sid: str, name: str) -> tuple[str, str]:
    """Личность участника в группе: SID, без SID — имя (DN); смена имени при том же SID — правка строки."""
    return (sid, "") if sid else ("", name)


def _member_rows(d: _AdDomainRead, o: AdObject, look: _Lookup) -> dict[tuple[str, str], dict[str, Any]]:
    """Прямой состав группы `o` по `_member_key`; основная группа — `primary` на той же строке."""
    from api.modules.ad.core.export import fsp_sid

    rows: dict[tuple[str, str], dict[str, Any]] = {}

    def put(kind: str, sid: str, name: str, domain: str = "", *, user_id: int | None = None, group_id: int | None = None,
            asset_id: int | None = None, primary: bool = False) -> None:
        sid, name = _cut(sid), _cut(name, NAME_LEN)
        k = _member_key(sid, name)
        row = rows.get(k)
        if row is not None:
            row["primary"] = row["primary"] or primary
            return
        rows[k] = {"member_kind": kind, "user_id": user_id, "member_group_id": group_id, "asset_id": asset_id,
                   "member_sid": sid, "member_name": name, "member_domain": _cut(domain), "primary": primary}

    def put_object(m: AdObject, primary: bool = False) -> None:
        sid = normalize_sid(m.sid or "")
        name = m.sam or m.name or m.dn
        if m.cls in USER_CLASSES:
            put("user", sid, name, d.dns, user_id=look.users.get(sid), primary=primary)
        elif m.cls == "computer":
            put("computer", sid, name, d.dns, asset_id=look.assets.get(m.sid or m.dn), primary=primary)
        elif m.cls == "group":
            key = _cut(group_key(local=False, domain=d.dns, host_asset_id=None, sid=sid, name=_cut(name, NAME_LEN)), KEY_LEN)
            put("group", sid, name, d.dns, group_id=look.keys.get(key))
        else:
            put("unknown", sid, name, d.dns)

    for member_dn in o.member:
        m = d.idx.get(member_dn)
        if m is not None:
            put_object(m)
            continue
        sid = fsp_sid(member_dn)
        if sid is None:
            put("unknown", "", member_dn)
            continue
        sid = normalize_sid(sid)
        name = d.idx.principal_name(sid) or sid
        if is_well_known(sid):
            put("well_known", sid, name)
        elif sid in look.users:
            put("user", sid, name, user_id=look.users[sid])
        elif sid in look.groups_by_sid:
            put("group", sid, name, group_id=look.groups_by_sid[sid])
        else:
            put("unknown", sid, name)
    for m in _primary_members(d.idx).get(normalize_sid(o.sid or ""), []):
        put_object(m, primary=True)
    return rows


def _primary_members(idx: ExportIndex) -> dict[str, list[AdObject]]:
    """SID основной группы → учётки и компьютеры домена с этим `primaryGroupID`; один раз на выгрузку."""
    cached: dict[str, list[AdObject]] | None = idx.cache.get("assets_primary_members")
    if cached is not None:
        return cached
    out: dict[str, list[AdObject]] = {}
    for cls in (*sorted(USER_CLASSES), "computer"):
        for o in idx.objects(cls):
            if o.primaryGroupID is not None:
                out.setdefault(normalize_sid(idx.domain_rid_sid(o.primaryGroupID)), []).append(o)
    idx.cache["assets_primary_members"] = out
    return out


#: Поля строки участника, которые сверяются с прежней (ключ — группа и `_member_key`).
_MEMBER_FIELDS = ("member_kind", "user_id", "member_group_id", "asset_id", "member_sid", "member_name", "member_domain", "primary")


def _apply_members(db: Session, batch: dict[int, dict[tuple[str, str], dict[str, Any]]], source: str = "ad") -> None:
    """Сверка состава пачки групп с прежними строками источника `source` (ad | vm): новые вставляются,
    пропавшие удаляются, изменённые правятся, неизменные не трогаются; строки другого источника не видны.
    Удаление — первым: строка-дубль прежнего SID освобождает пару (SID, имя) для правки имени."""
    old: dict[int, dict[tuple[str, str], dict[str, Any]]] = {}
    drop: list[int] = []
    cols = [getattr(AssetGroupMember, f) for f in _MEMBER_FIELDS]
    for row in db.execute(
        select(AssetGroupMember.id, AssetGroupMember.group_id, *cols)
        .where(AssetGroupMember.source == source, AssetGroupMember.group_id.in_(sorted(batch)))
        .order_by(AssetGroupMember.id)
    ).mappings():
        per = old.setdefault(row["group_id"], {})
        k = _member_key(row["member_sid"], row["member_name"])
        if k in per:
            drop.append(row["id"])
        else:
            per[k] = dict(row)
    inserts: list[dict[str, Any]] = []
    updates: list[dict[str, Any]] = []
    for gid, rows in batch.items():
        have = old.get(gid, {})
        for k, new in rows.items():
            got = have.get(k)
            if got is None:
                inserts.append({**new, "group_id": gid, "source": source})
            elif any(got[f] != new[f] for f in _MEMBER_FIELDS):
                updates.append({"id": got["id"], **new})
        drop.extend(got["id"] for k, got in have.items() if k not in rows)
    for i in range(0, len(drop), CHUNK):
        db.execute(delete(AssetGroupMember).where(AssetGroupMember.id.in_(drop[i : i + CHUNK])))
    for rows_, stmt in ((updates, update(AssetGroupMember)), (inserts, insert(AssetGroupMember))):
        for i in range(0, len(rows_), CHUNK):
            db.execute(stmt, rows_[i : i + CHUNK])


def _sync_ad_members(db: Session, handle: JobHandle, ad: _AdRead, keys: dict[str, int]) -> int:
    """Состав AD групп сверкой по пачкам групп (не больше `MEMBER_BATCH_GROUPS` групп или примерно `CHUNK`
    строк за раз). Строки AD пропавших групп (и доменов, которых больше нет) удаляются; домен с непрочитанным
    файлом не трогается. Возвращает число строк AD после записи."""
    look = _Lookup(
        users=dict(db.execute(
            select(AssetUser.sid, AssetUser.id).where(AssetUser.merged_into.is_(None), AssetUser.local.is_(False), AssetUser.sid != "")
            .order_by(AssetUser.id.desc())
        ).tuples().all()),
        assets=_live_assets(db),
        groups_by_sid=dict(db.execute(
            select(AssetGroup.sid, AssetGroup.id).where(
                AssetGroup.local.is_(False), AssetGroup.gone_at.is_(None), AssetGroup.sid.like("S-1-5-21-%"),
            ).order_by(AssetGroup.id.desc())
        ).tuples().all()),
        keys=keys,
    )
    gone = select(AssetGroup.id).where(
        AssetGroup.local.is_(False), or_(AssetGroup.gone_at.is_not(None), AssetGroup.in_ad.is_(False)),
        AssetGroup.domain.not_in(sorted(ad.failed)),
    )
    db.execute(delete(AssetGroupMember).where(AssetGroupMember.source == "ad", AssetGroupMember.group_id.in_(gone)))
    total = sum(len(d.idx.objects("group")) for d in ad.domains)
    handle.stage("group_members", total=total, message=f"состав групп AD: {total}")
    done = 0
    done_gids: set[int] = set()
    batch: dict[int, dict[tuple[str, str], dict[str, Any]]] = {}
    pending = 0
    for d in ad.domains:
        for o in d.idx.objects("group"):
            done += 1
            if not o.sid:
                continue
            gid = keys.get(_cut(group_key(local=False, domain=d.dns, host_asset_id=None, sid=o.sid, name=_cut(o.sam or o.name, NAME_LEN)), KEY_LEN))
            # Одна группа дважды в выгрузке (тот же ключ) — её состав по первой записи.
            if gid is None or gid in done_gids:
                continue
            done_gids.add(gid)
            batch[gid] = _member_rows(d, o, look)
            pending += len(batch[gid])
            if len(batch) >= MEMBER_BATCH_GROUPS or pending >= CHUNK:
                _apply_members(db, batch)
                batch, pending = {}, 0
                handle.tick(done)
    if batch:
        _apply_members(db, batch)
    handle.tick(done)
    return int(db.execute(select(func.count()).select_from(AssetGroupMember).where(AssetGroupMember.source == "ad")).scalar_one())


def _sync_gpo(db: Session, handle: JobHandle, ad: _AdRead) -> int:
    """Права по GPO заменой по домену; домен с непрочитанным файлом сохраняет строки и заметки,
    строки доменов, которых больше нет, удаляются."""
    from api.modules.ad.core.gpo_rights import gpo_rights

    db.execute(delete(AssetGroupGpo).where(AssetGroupGpo.domain.not_in(sorted(ad.failed | {d.dns for d in ad.domains}))))
    handle.stage("group_gpo", total=len(ad.domains), message=f"права групп по GPO: доменов {len(ad.domains)}")
    count = 0
    notes: dict[str, dict[str, Any]] = {}
    for n, d in enumerate(ad.domains, start=1):
        got = gpo_rights(d.idx)
        rows: list[dict[str, Any]] = []
        notes[d.dns] = {"links_known": bool(got["links_known"]), "files_known": bool(got["files_known"]), "notes": list(got["notes"])}
        for r in got["rights"]:
            rows.append({
                "domain": _cut(d.dns), "group_sid": _cut(normalize_sid(r["group_sid"] or "")), "group_name": _cut(r["group_name"], NAME_LEN),
                "local_group": _cut(r["local_group"]), "local_group_sid": _cut(normalize_sid(r["local_group_sid"] or "")),
                "via": _cut(r["via"], 32), "action": _cut(r["action"], 16),
                "gpo_name": _cut(r["gpo"]["name"], NAME_LEN), "gpo_dn": _cut(r["gpo"]["dn"], DN_LEN),
                "filtered": r["filtered"], "hosts": list(r["hosts"][:GPO_HOSTS_MAX]), "hosts_total": int(r["hosts_total"]),
                "seen_at": d.seen_at,
            })
        db.execute(delete(AssetGroupGpo).where(AssetGroupGpo.domain == d.dns))
        for i in range(0, len(rows), CHUNK):
            db.execute(insert(AssetGroupGpo), rows[i : i + CHUNK])
        count += len(rows)
        handle.tick(n)
    row = settings_row(db)
    data = dict(row.data or {})
    old = data.get(GPO_NOTES_KEY) or {}
    notes.update({k: v for k, v in old.items() if k in ad.failed and k not in notes})
    if data.get(GPO_NOTES_KEY) != notes:
        row.data = {**data, GPO_NOTES_KEY: notes}
    db.flush()
    return count


# ---- Локальные группы из VM --------------------------------------------------------------------------

#: Хост строки `vm_host_group`: (os_family, fqdn, hostname, ip).
VmHostKey = tuple[str, str, str, str]
#: Столько активов-хостов за раз: их строки VM читаются одним запросом (~75 строк на хост Linux).
VM_HOSTS_BATCH = 200


def _put(index: dict[str, int | None], key: str, asset_id: int) -> None:
    """Ключ → актив; второй другой актив на тот же ключ — неоднозначно (None)."""
    if key:
        index[key] = asset_id if index.get(key, asset_id) == asset_id else None


#: Источник наблюдения-запроса: ни одно записанное наблюдение не совпадает с ним по ключу (правило 1).
_VM_GROUPS_PROBE = "vm_groups"


def _match_vm_hosts(db: Session, hosts: list[VmHostKey]) -> tuple[dict[VmHostKey, int], int]:
    """Хост VM → актив. Сначала живое наблюдение `vm` с ключом `hostname|ip` (без учёта регистра), где
    `hostname` — FQDN или имя строки групп, либо адрес (`ip|ip`, `ip|` — у хоста VM без DNS-имени `@Host`
    — адрес); иначе правила 2–5 общего сопоставителя (`core.matching.match`) по живым активам: FQDN, имя с тем
    же доменом, короткое имя — только если у одной стороны нет домена, адрес — только если у одной стороны нет
    имени. Неоднозначно или нигде — хост без актива (второе в ответе — их число). Контроллеры домена (признак
    `dc` наблюдения AD) в ответ не входят: локальных групп у них нет."""
    alive = _alive(db)
    by_vm: dict[str, int | None] = {}
    obs = select(AssetObservation.source, AssetObservation.source_key, AssetObservation.asset_id, AssetObservation.extra).where(
        AssetObservation.source.in_(("vm", "ad")), AssetObservation.gone_at.is_(None))
    dcs: set[int] = set()
    for source, key, aid, extra in db.execute(obs).tuples():
        if source == "vm":
            _put(by_vm, key.lower(), alive(aid))
        elif (extra or {}).get("dc"):
            dcs.add(alive(aid))
    index = MatchIndex.load(db)

    def match_host(fqdn: str, hostname: str, ip: str) -> int | None:
        keys = {f"{h}|{ip}".lower() for h in (fqdn, hostname, ip) if h} | ({f"{ip}|"} if ip else set())
        hits = {by_vm[k] for k in keys if k in by_vm}
        if hits:
            return hits.pop() if len(hits) == 1 else None
        probe = Observed(source=_VM_GROUPS_PROBE, source_key="", name=hostname or fqdn, fqdn=normalize_fqdn(fqdn),
                         ip=ip, ips=[ip] if ip else [])
        return match(probe, index.candidates_for(probe), index.domain_map)[0]

    out: dict[VmHostKey, int] = {}
    unmatched = 0
    for host in hosts:
        aid = match_host(host[1], host[2], host[3])
        if aid is None:
            unmatched += 1
        elif aid not in dcs:
            out[host] = aid
    return out, unmatched


@dataclass
class _VmLookup:
    dmap: dict[str, str]
    #: SID доменной учётки → живой пользователь.
    users: dict[str, int]
    #: Доменные группы (и пропавшие — ключ уникален) по ключу; по SID `S-1-5-21-*` — живая, иначе любая.
    groups: dict[str, AssetGroup]
    groups_by_sid: dict[str, AssetGroup]
    seen_at: dt.datetime
    #: Доменные группы, которые VM видит участниками в этом проходе.
    refs: set[int] = field(default_factory=set)

    def domain_group(self, db: Session, domain: str, sid: str, name: str) -> int:
        """Доменная группа-участник: по ключу (домен, SID), иначе по SID `S-1-5-21-*` (он уникален между
        доменами), иначе новая запись `sources=["vm"]`, `in_ad=False` — домен как пришёл."""
        key = _cut(group_key(local=False, domain=domain, host_asset_id=None, sid=sid, name=name), KEY_LEN)
        g = self.groups.get(key) or (self.groups_by_sid.get(sid) if sid.startswith("S-1-5-21-") else None)
        if g is None:
            g = AssetGroup(group_key=key, sid=sid, name=name, domain=_cut(domain), local=False, description="", sources=["vm"],
                           in_ad=False, first_seen=self.seen_at, last_seen=self.seen_at, gone_at=None)
            db.add(g)
            db.flush()
            self.groups[key] = g
            if sid:
                self.groups_by_sid.setdefault(sid, g)
        self.refs.add(g.id)
        return g.id


def _vm_lookup(db: Session, seen_at: dt.datetime) -> _VmLookup:
    groups = list(db.execute(select(AssetGroup).where(AssetGroup.local.is_(False)).order_by(AssetGroup.id)).scalars())
    by_sid: dict[str, AssetGroup] = {}
    for g in sorted(groups, key=lambda g: (g.gone_at is None, g.id)):  # живые — последними, перекрывают
        if g.sid:
            by_sid[g.sid] = g
    return _VmLookup(
        dmap=domain_map(db),
        users=dict(db.execute(
            select(AssetUser.sid, AssetUser.id).where(AssetUser.merged_into.is_(None), AssetUser.local.is_(False), AssetUser.sid != "")
        ).tuples().all()),
        groups={g.group_key: g for g in groups},
        groups_by_sid=by_sid,
        seen_at=seen_at,
    )


def _upsert_local_groups(db: Session, assets: list[int], groups: dict[str, dict[str, Any]]) -> dict[str, int]:
    """Локальные группы пачки хостов: новые вставляются, изменённые правятся, вернувшиеся снимают `gone_at`.
    Ключ группы → id."""
    cols = (AssetGroup.id, AssetGroup.group_key, AssetGroup.sid, AssetGroup.name, AssetGroup.description, AssetGroup.sources,
            AssetGroup.first_seen, AssetGroup.last_seen, AssetGroup.gone_at)
    old = {r["group_key"]: r for r in db.execute(
        select(*cols).where(AssetGroup.local.is_(True), AssetGroup.host_asset_id.in_(assets))).mappings()}
    ids: dict[str, int] = {}
    inserts: list[dict[str, Any]] = []
    updates: list[dict[str, Any]] = []
    for key, g in groups.items():
        values = {"sid": g["sid"], "name": g["name"], "description": g["description"], "sources": ["vm"],
                  "last_seen": g["last_seen"], "gone_at": None}
        got = old.get(key)
        if got is None:
            inserts.append({"group_key": key, "local": True, "host_asset_id": g["asset_id"], "domain": "", "in_ad": False,
                            "first_seen": g["last_seen"], **values})
            continue
        ids[key] = got["id"]
        values["first_seen"] = min(got["first_seen"] or g["last_seen"], g["last_seen"])
        if any(got[k] != v for k, v in values.items()):
            updates.append({"id": got["id"], **values})
    for i in range(0, len(updates), CHUNK):
        db.execute(update(AssetGroup), updates[i : i + CHUNK])
    for i in range(0, len(inserts), CHUNK):
        ids.update(db.execute(insert(AssetGroup).returning(AssetGroup.group_key, AssetGroup.id), inserts[i : i + CHUNK]).tuples().all())
    return ids


def _vm_member_rows(asset_id: int, rows: list[Any], ids: dict[str, int], local_users: dict[str, int],
                    look: _VmLookup, db: Session) -> dict[tuple[str, str], dict[str, Any]]:
    """Состав локальной группы по строкам VM (`_member_key`, первая строка участника решает). Вид: встроенный
    субъект по SID; `IsLocal` — локальная учётка хоста (`local:<asset_id>\\<имя>`) или локальная группа хоста;
    иначе доменный: группа (`_VmLookup.domain_group`) или пользователь по SID. Не связавшийся пользователь —
    `user` без `user_id` с именем и SID. Домен — DNS по карте NetBIOS, иначе как пришёл (нижний регистр)."""
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        sid, name = _cut(normalize_sid(r["member_sid"])), _cut(r["member_name"], NAME_LEN)
        k = _member_key(sid, name)
        if k in out:
            continue
        raw = (r["member_domain"] or "").strip().lower()
        domain = look.dmap.get(raw, raw)
        row: dict[str, Any] = {"member_kind": "user", "user_id": None, "member_group_id": None, "asset_id": None,
                               "member_sid": sid, "member_name": name, "member_domain": _cut(domain), "primary": False}
        is_group = r["member_type"] == "group"
        if sid and is_well_known(sid):
            row["member_kind"] = "well_known"
        elif r["member_local"]:
            if is_group:
                key = _cut(group_key(local=True, domain="", host_asset_id=asset_id, sid=sid, name=name), KEY_LEN)
                row.update(member_kind="group", member_group_id=ids.get(key))
            else:
                row["user_id"] = local_users.get(_local_user_key(asset_id, name))
        elif is_group:
            row.update(member_kind="group", member_group_id=look.domain_group(db, domain, sid, name))
        else:
            row["user_id"] = look.users.get(sid) if sid else None
        out[k] = row
    return out


def _local_user_key(asset_id: int, name: str) -> str:
    """`name_key` локальной учётки этапа пользователей (`core.users.user_key`)."""
    sam = name.strip().rpartition("\\")[2].lower()
    return f"local:{asset_id}\\{sam}"


def _sync_vm_batch(db: Session, assets: list[int], hosts: dict[VmHostKey, int], look: _VmLookup,
                   seen_at: dict[str, dt.datetime]) -> None:
    from api.modules.vm.models import VmHostGroup

    host_cols = (VmHostGroup.os_family, VmHostGroup.fqdn, VmHostGroup.hostname, VmHostGroup.ip)
    rows = db.execute(
        select(VmHostGroup.__table__).where(tuple_(*host_cols).in_(list(hosts))).order_by(VmHostGroup.id)
    ).mappings().all()
    groups: dict[str, dict[str, Any]] = {}
    members: dict[str, list[Any]] = {}
    for r in rows:
        aid = hosts[(r["os_family"], r["fqdn"], r["hostname"], r["ip"])]
        name = _cut(r["group_name"], NAME_LEN)
        key = _cut(group_key(local=True, domain="", host_asset_id=aid, sid=r["group_sid"], name=name), KEY_LEN)
        if key not in groups:
            linux = r["os_family"] == "linux"
            groups[key] = {
                "asset_id": aid, "sid": _cut(normalize_sid(r["group_sid"])), "name": name,
                "description": (f"GID {r['group_gid']}" if r["group_gid"] else "") if linux else r["group_description"],
                "last_seen": seen_at[r["os_family"]],
            }
            members[key] = []
        if r["member_name"] or r["member_sid"]:
            members[key].append(r)
    ids = _upsert_local_groups(db, assets, groups)
    wanted = sorted({_local_user_key(groups[k]["asset_id"], r["member_name"])
                     for k, rs in members.items() for r in rs if r["member_local"] and r["member_type"] != "group"})
    local_users: dict[str, int] = {}
    for i in range(0, len(wanted), CHUNK):
        local_users.update(db.execute(select(AssetUser.name_key, AssetUser.id).where(
            AssetUser.local.is_(True), AssetUser.merged_into.is_(None), AssetUser.name_key.in_(wanted[i : i + CHUNK]))).tuples().all())
    batch = {ids[k]: _vm_member_rows(groups[k]["asset_id"], members[k], ids, local_users, look, db) for k in groups}
    _apply_members(db, batch, "vm")


def _sync_vm_domain_refs(db: Session, look: _VmLookup, now: dt.datetime) -> None:
    """Источник `vm` доменных групп — по тому, видит ли их VM участниками сейчас. Видит пропавшую — она
    возвращается без AD (`in_ad=False`); больше не видит — `vm` снимается, без источников — пропавшая."""
    for g in look.groups.values():
        sources = list(g.sources or [])
        if g.id in look.refs:
            if g.gone_at is not None:
                g.gone_at = None
                g.in_ad = False
                sources = [s for s in sources if s != "ad"]
            if "vm" not in sources:
                sources = sorted({*sources, "vm"})
            if not g.in_ad and (g.last_seen is None or g.last_seen < look.seen_at):
                g.last_seen = look.seen_at
        elif "vm" in sources:
            sources = [s for s in sources if s != "vm"]
            if not sources and g.gone_at is None:
                g.gone_at = now
        if sources != (g.sources or []):
            g.sources = sources


def _sync_vm(db: Session, handle: JobHandle, now: dt.datetime) -> int:
    """Локальные группы хостов из последнего снимка групп VM (спека §3). Без снимка — ничего не трогается.
    Пропавшие — локальные группы семейства, чей запрос прошёл в последнем снимке, не встреченные в нём
    (`last_seen` раньше снимка семейства); семейство — по SID (у Linux его нет). Возвращает число хостов
    VM без актива."""
    from api.modules.vm.models import VmGroupImport, VmHostGroup

    snap = db.execute(select(VmGroupImport).order_by(VmGroupImport.finished_at.desc(), VmGroupImport.id.desc()).limit(1)).scalar()
    if snap is None:
        return 0
    seen_at = {
        family: db.execute(select(func.max(VmGroupImport.finished_at)).where(flag.is_(True))).scalar() or snap.finished_at
        for family, flag in (("windows", VmGroupImport.windows_ok), ("linux", VmGroupImport.linux_ok))
    }
    host_cols = (VmHostGroup.os_family, VmHostGroup.fqdn, VmHostGroup.hostname, VmHostGroup.ip)
    hosts: list[VmHostKey] = [(f, q, h, ip) for f, q, h, ip in db.execute(select(*host_cols).distinct().order_by(*host_cols)).tuples()]
    matched, unmatched = _match_vm_hosts(db, hosts)
    # Хосты одного актива (запись Windows и Linux, FQDN и имя) — в одной пачке: состав группы не делится.
    by_asset: dict[int, list[VmHostKey]] = {}
    for host, aid in matched.items():
        by_asset.setdefault(aid, []).append(host)
    assets = sorted(by_asset)
    look = _vm_lookup(db, seen_at["windows"])
    handle.stage("group_vm", total=len(assets), message=f"локальные группы VM: хостов {len(assets)}, без актива {unmatched}")
    for i in range(0, len(assets), VM_HOSTS_BATCH):
        chunk = assets[i : i + VM_HOSTS_BATCH]
        _sync_vm_batch(db, chunk, {h: a for a in chunk for h in by_asset[a]}, look, seen_at)
        handle.tick(i + len(chunk))
    _sync_vm_domain_refs(db, look, now)
    for family, has_sid, ok in (("windows", AssetGroup.sid != "", snap.windows_ok), ("linux", AssetGroup.sid == "", snap.linux_ok)):
        if ok:
            db.execute(update(AssetGroup).where(
                AssetGroup.local.is_(True), AssetGroup.gone_at.is_(None), has_sid,
                or_(AssetGroup.last_seen.is_(None), AssetGroup.last_seen < seen_at[family]),
            ).values(gone_at=now).execution_options(synchronize_session=False))
    gone = select(AssetGroup.id).where(AssetGroup.local.is_(True), AssetGroup.gone_at.is_not(None))
    db.execute(delete(AssetGroupMember).where(AssetGroupMember.source == "vm", AssetGroupMember.group_id.in_(gone)))
    db.flush()
    return unmatched


def sync_groups(db: Session, handle: JobHandle, data_dir: Path, now: dt.datetime, ad_cache: AdExportCache | None = None) -> dict[str, int]:
    """Группы, их состав и права по GPO. `ad_cache` — выгрузки AD, уже разобранные этим проходом.
    `groups` — сколько групп AD видели выгрузки этого прохода."""
    ad = _read_ad(db, data_dir, ad_cache)
    keys, skipped = _upsert_ad_groups(db, handle, ad, now)
    members = _sync_ad_members(db, handle, ad, keys)
    gpo = _sync_gpo(db, handle, ad)
    db.flush()
    unmatched = _sync_vm(db, handle, now)
    return {"groups": len(keys), "members": members, "gpo": gpo, "vm_hosts_unmatched": unmatched, "skipped": skipped}


def gpo_notes(db: Session) -> dict[str, dict[str, Any]]:
    """DNS-домен → оговорки `gpo_rights` последней синхронизации: `links_known`, `files_known`, `notes`."""
    return {str(k): dict(v) for k, v in (load_settings(db).get(GPO_NOTES_KEY) or {}).items()}
