"""Синхронизация пользователей (спека «Пользователи как активы» §2.1, §3, §4): последний шаг прохода
`assets/sync`, после хостов — связям «пользователь → хост» нужны уже сопоставленные активы.

- AD — учётки `user` последнего снапшота каждого домена из файла выгрузки (компьютеры и gMSA — не
  пользователи): включённость, флаги, группы прямые и вложенные (`ad.core.account_groups`),
  привилегированность — рекурсивный член групп `admin_rids ∪ privileged_rids` или групп из
  `privileged_groups` по имени, либо учётка RID 500 (настройки модуля AD). Заметки `account_groups`
  («список участников мог быть обрезан») — в `data.group_notes` каждого наблюдения AD домена: обрезанный
  список группы задевает любую учётку домена, не только перечисленные.
- KSC — `ksc_host.extra_json` последнего снапшота каждого сервера: `users` (список | null),
  `users_collected`, `owner`. Хост → актив по наблюдению `ksc` с ключом `"{server_id}:{host_id}"`
  (через `Asset.merged_into` — к выжившему). Действующее «собрано» (`users_collected` и `users` —
  список) и группы с сеансом пишутся в `extra` наблюдения хоста KSC (`users_collected`,
  `session_groups`): карточкам Assets не нужно читать `ksc_host`.
- Ключ наблюдения: AD — SID; KSC — `"{server_id}:{SID}"`, без SID — `"{server_id}:{домен}\\{имя}"`
  как пришли, у локальной — `"{server_id}:{host_id}\\{имя}"`. Одно наблюдение KSC на учётку сервера,
  хосты — связи `asset_user_host`.
- Пропавшие: AD — только учётки доменов, чья выгрузка прочитана (файл не читается — его учётки живы);
  связь KSC — только на хосте, где пользователи собраны, или на хосте, которого в KSC больше нет;
  наблюдение KSC — если его нет в проходе и у пользователя нет живой связи на несобранном хосте.
- Домены, чьи выгрузки прочитаны в последнем проходе, — служебный ключ `users_ad_domains` строки
  настроек Assets (`ad_domains`): «нет в AD» (§5.2) судится только по ним.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import delete, insert, select, update
from sqlalchemy.orm import Session

from api.jobs import JobHandle
from api.modules.assets.core.users import UserSeen, match_user, user_key
from api.modules.assets.models import (
    Asset,
    AssetObservation,
    AssetUser,
    AssetUserGroup,
    AssetUserHost,
    AssetUserObservation,
)
from api.modules.assets.services.assets import domain_map, load_settings, settings_row

log = logging.getLogger("stools.assets")

#: Прогресс и проверка отмены — раз в столько записей.
TICK_EVERY = 2000
#: Столько id за раз в одном запросе удаления.
CHUNK = 10_000
RID_ADMINISTRATOR = 500
AD_DOMAINS_KEY = "users_ad_domains"

#: Группа учётки AD: (SID, имя `ДОМЕН\\имя`, прямая).
GroupRow = tuple[str, str, bool]


@dataclass
class AdUsers:
    seen: list[UserSeen] = field(default_factory=list)
    #: SID учётки (ключ наблюдения AD) → группы.
    groups: dict[str, list[GroupRow]] = field(default_factory=dict)
    #: DNS-домены, чья последняя выгрузка прочитана; и те, чья не прочитана.
    read: set[str] = field(default_factory=set)
    failed: set[str] = field(default_factory=set)


@dataclass
class KscUsers:
    #: Одна запись на ключ наблюдения (первая встреченная).
    seen: list[UserSeen] = field(default_factory=list)
    #: (ключ наблюдения, актив-хост, session | owner, в системе на момент сбора, время снапшота).
    links: list[tuple[str, int, str, bool, dt.datetime]] = field(default_factory=list)
    #: Активы хостов последних снапшотов; из них — где пользователи собраны.
    hosts: set[int] = field(default_factory=set)
    collected: set[int] = field(default_factory=set)
    #: Ключ наблюдения хоста KSC → что дописать в его `extra`.
    host_flags: dict[str, dict[str, Any]] = field(default_factory=dict)


# ---- AD -------------------------------------------------------------------


def users_from_ad(db: Session, data_dir: Path) -> AdUsers:
    from api.modules.ad.core.account_groups import account_groups
    from api.modules.ad.core.export import (
        UAC_DONT_EXPIRE_PASSWORD,
        ExportFormatError,
        ExportIndex,
        filetime_to_datetime,
        load_export_path,
    )
    from api.modules.ad.models import AdDomain
    from api.modules.ad.services.settings import load_config
    from api.modules.ad.services.snapshots import latest_snapshot, snapshot_path

    cfg = load_config(db)
    rids = {*cfg.admin_rids, *cfg.privileged_rids}
    names = {n.strip().lower() for n in cfg.privileged_groups}
    out = AdUsers()
    for domain in db.execute(select(AdDomain).order_by(AdDomain.id)).scalars():
        snap = latest_snapshot(db, domain.id)
        if snap is None:
            continue
        try:
            export = load_export_path(snapshot_path(data_dir, snap.id))
        except (ExportFormatError, OSError, ValueError) as exc:
            out.failed.add((domain.dns_root or "").lower())
            log.warning("снапшот AD #%s не прочитан для пользователей: %s", snap.id, type(exc).__name__)
            continue
        idx = ExportIndex(export)
        acc = account_groups(idx)
        dns = (export.domain.dns_root or domain.dns_root or "").lower()
        privileged_sids = {f"S-1-5-32-{r}" if 544 <= r <= 582 else idx.domain_rid_sid(r) for r in rids}
        for o in idx.objects("user"):
            if not o.sid or (o.sam or "").endswith("$"):
                continue
            refs = acc.groups.get(o.sid, [])
            privileged = o.rid == RID_ADMINISTRATOR or any(
                g["sid"] in privileged_sids or g["name"].rpartition("\\")[2].lower() in names for g in refs
            )
            last = filetime_to_datetime(o.lastLogonTimestamp)
            out.seen.append(UserSeen(
                source="ad", source_key=o.sid, seen_at=snap.collected_at, sid=o.sid, sam=o.sam or "",
                upn=getattr(o, "userPrincipalName", None) or "", display_name=getattr(o, "displayName", None) or "",
                domain=dns, enabled=o.enabled, privileged=privileged,
                data={
                    "dn": o.dn, "uac": o.uac, "pwd_never_expires": bool((o.uac or 0) & UAC_DONT_EXPIRE_PASSWORD),
                    "last_logon": last.isoformat() if last else None, "admin_count": o.adminCount,
                    "domain_id": domain.id, "group_notes": list(acc.notes),
                },
            ))
            out.groups[o.sid] = [(g["sid"], g["name"], g["direct"]) for g in refs]
        out.read.add(dns)
    return out


# ---- KSC ------------------------------------------------------------------


def _ksc_seen(server_id: int, host_id: str, asset_id: int, rec: dict[str, Any], seen_at: dt.datetime) -> UserSeen:
    sid = str(rec.get("sid") or "").strip().upper()
    sam = str(rec.get("sam") or "").strip()
    domain = str(rec.get("domain") or "").strip()
    local = bool(rec.get("local"))
    prefix, _, bare = sam.rpartition("\\")
    if local:
        who = f"{host_id}\\{bare.lower()}"
    else:
        who = sid or f"{(prefix or domain).lower()}\\{bare.lower()}"
    return UserSeen(
        source="ksc", source_key=f"{server_id}:{who}", seen_at=seen_at, sid=sid, sam=sam,
        upn=str(rec.get("upn") or ""), display_name=str(rec.get("display_name") or ""), domain=domain,
        local=local, group=bool(rec.get("group")), host_asset_id=asset_id if local else None,
        data={"server_id": server_id},
    )


def _owner_record(owner: Any, people: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Запись владельца среди пользователей хоста; `{owner_id}` (не в списке) и null — None."""
    if not isinstance(owner, dict) or not (owner.get("sid") or owner.get("sam")):
        return None
    sid = str(owner.get("sid") or "").upper()
    sam = str(owner.get("sam") or "").lower()
    for rec in people:
        if (sid and str(rec.get("sid") or "").upper() == sid) or (sam and str(rec.get("sam") or "").lower() == sam):
            return rec
    return {"sid": owner.get("sid") or "", "sam": owner.get("sam") or "", "display_name": owner.get("display_name") or ""}


def users_from_ksc(db: Session) -> KscUsers:
    from api.modules.ksc.models import KscHost, KscServer
    from api.modules.ksc.services.snapshots import latest_snapshot

    host_assets = dict(db.execute(
        select(AssetObservation.source_key, AssetObservation.asset_id).where(AssetObservation.source == "ksc")
    ).tuples().all())
    merged = {a: m for a, m in db.execute(select(Asset.id, Asset.merged_into).where(Asset.merged_into.is_not(None))).tuples() if m is not None}

    def alive(asset_id: int) -> int:
        seen: set[int] = set()
        while asset_id in merged and asset_id not in seen:
            seen.add(asset_id)
            asset_id = merged[asset_id]
        return asset_id

    out = KscUsers()
    by_key: dict[str, UserSeen] = {}
    for server in db.execute(select(KscServer).order_by(KscServer.id)).scalars():
        snap = latest_snapshot(db, server.id)
        if snap is None:
            continue
        rows = db.execute(
            select(KscHost.host_id, KscHost.extra_json).where(KscHost.snapshot_id == snap.id).order_by(KscHost.id)
        ).tuples()
        for host_id, extra_json in rows:
            obs_key = f"{server.id}:{host_id}"
            if obs_key not in host_assets:
                continue
            asset_id = alive(int(host_assets[obs_key]))
            extra = json.loads(extra_json or "{}")
            users = extra.get("users")
            collected = bool(extra.get("users_collected")) and isinstance(users, list)
            out.hosts.add(asset_id)
            records = [u for u in users if isinstance(u, dict)] if isinstance(users, list) else []
            people = [u for u in records if not u.get("group")]
            out.host_flags[obs_key] = {
                "users_collected": collected,
                "session_groups": [{"sid": u.get("sid") or "", "sam": u.get("sam") or "", "active": bool(u.get("active"))}
                                   for u in records if u.get("group")],
            }
            if not collected:
                continue
            out.collected.add(asset_id)
            for rec in people:
                s = _ksc_seen(server.id, host_id, asset_id, rec, snap.collected_at)
                by_key.setdefault(s.source_key, s)
                out.links.append((s.source_key, asset_id, "session", bool(rec.get("active")), snap.collected_at))
            owner = _owner_record(extra.get("owner"), people)
            if owner is not None:
                s = _ksc_seen(server.id, host_id, asset_id, owner, snap.collected_at)
                by_key.setdefault(s.source_key, s)
                out.links.append((s.source_key, asset_id, "owner", False, snap.collected_at))
    out.seen = list(by_key.values())
    return out


# ---- Запись ---------------------------------------------------------------


class _Index:
    """Живые пользователи по SID и name_key для `match_user`; id новых до вставки — отрицательные."""

    def __init__(self, users: Iterable[AssetUser]) -> None:
        self.objs: dict[int, AssetUser] = {}
        self.by_sid: dict[str, set[int]] = defaultdict(set)
        self.by_name: dict[str, set[tuple[int, str]]] = defaultdict(set)
        for u in users:
            self.objs[u.id] = u
            if u.merged_into is None:
                self._put(u.id, u)

    def _put(self, uid: int, u: AssetUser) -> None:
        if u.sid:
            self.by_sid[u.sid].add(uid)
        if u.name_key:
            self.by_name[u.name_key].add((uid, u.sid))

    def _drop(self, uid: int, u: AssetUser) -> None:
        self.by_sid.get(u.sid, set()).discard(uid)
        self.by_name.get(u.name_key, set()).discard((uid, u.sid))

    def survivor(self, uid: int) -> int | None:
        seen: set[int] = set()
        u = self.objs.get(uid)
        while u is not None and u.merged_into is not None and uid not in seen:
            seen.add(uid)
            uid = u.merged_into
            u = self.objs.get(uid)
        return uid if u is not None else None

    def add(self, uid: int, u: AssetUser) -> None:
        self.objs[uid] = u
        self._put(uid, u)

    def refine(self, uid: int, key: tuple[str, str], authoritative: bool) -> None:
        """Дополнить ключи пользователя: SID — если его не было и он ничей; name_key — если пуст,
        у локальной (актив хоста сменился при объединении) или по AD (переименование), и имя ничьё."""
        u = self.objs[uid]
        sid, name = key
        if sid and not u.sid and not self.by_sid.get(sid):
            self._drop(uid, u)
            u.sid = sid
            self._put(uid, u)
        if (name and name != u.name_key and (not u.name_key or u.local or authoritative)
                and not any(other != uid for other, _ in self.by_name.get(name, ()))):
            self._drop(uid, u)
            u.name_key = name
            self._put(uid, u)


def _obs_data(s: UserSeen, name_key: str) -> dict[str, Any]:
    data: dict[str, Any] = {
        "sid": s.sid, "sam": s.sam, "upn": s.upn, "display_name": s.display_name, "domain": s.domain, "local": s.local,
        "name_key": name_key, **s.data,
    }
    if s.source == "ad":
        data["enabled"], data["privileged"] = s.enabled, bool(s.privileged)
    return data


def _recompute(u: AssetUser, rows: list[AssetUserObservation]) -> None:
    """Поля — из самого свежего наблюдения (AD главнее при равенстве), пустые — из следующего;
    `enabled`/`privileged` — только из живого AD."""
    live = [r for r in rows if r.gone_at is None] or rows
    order = sorted(live, key=lambda r: (r.seen_at, r.source == "ad"), reverse=True)

    def first(name: str) -> str:
        return next((str(r.data[name]) for r in order if (r.data or {}).get(name)), "")

    sam = first("sam").rpartition("\\")[2]
    domain = "" if u.local or u.name_key.startswith("local:") else u.name_key.rpartition("\\")[0]
    ad = sorted((r for r in rows if r.source == "ad" and r.gone_at is None), key=lambda r: r.seen_at, reverse=True)
    enabled = ad[0].data.get("enabled") if ad else None
    privileged = bool(ad[0].data.get("privileged")) if ad else False
    first_seen = min(r.seen_at for r in rows)
    last_seen = max(r.seen_at for r in rows)
    values: dict[str, Any] = {
        "sam": sam, "upn": first("upn"), "display_name": first("display_name"), "domain": domain,
        "enabled": None if enabled is None else bool(enabled), "privileged": privileged,
        "first_seen": min(first_seen, u.first_seen) if u.first_seen else first_seen, "last_seen": last_seen,
    }
    for name, value in values.items():
        if getattr(u, name) != value:
            setattr(u, name, value)


def _sync_groups(db: Session, ad: AdUsers, key_user: dict[tuple[str, str], int], live_ad_users: set[int]) -> int:
    """Группы AD заменой по пользователю (разницей: строки, которые не менялись, не трогаются);
    у пользователя без живого наблюдения AD группы снимаются. Возвращает число строк групп после записи."""
    have: dict[int, dict[str, tuple[int, str, bool]]] = defaultdict(dict)
    for gid, uid, sid, name, direct in db.execute(
        select(AssetUserGroup.id, AssetUserGroup.user_id, AssetUserGroup.group_sid, AssetUserGroup.group_name, AssetUserGroup.direct)
        .where(AssetUserGroup.source == "ad")
    ).tuples():
        have[uid][sid] = (gid, name, direct)
    want: dict[int, dict[str, tuple[str, bool]]] = defaultdict(dict)
    for key, rows in ad.groups.items():
        owner = key_user.get(("ad", key))
        if owner is not None:
            bucket = want[owner]  # учётка без групп тоже заменяет прежние
            for sid, name, direct in rows:
                bucket.setdefault(sid, (name, direct))
    inserts: list[dict[str, Any]] = []
    updates: list[dict[str, Any]] = []
    drop: list[int] = []
    for user_id in set(have) | set(want):
        if user_id not in want and user_id in live_ad_users:
            continue  # домен не прочитан: группы прежние
        old, new = have.get(user_id, {}), want.get(user_id, {})
        for sid, (name, direct) in new.items():
            got = old.get(sid)
            if got is None:
                inserts.append({"user_id": user_id, "group_sid": sid, "group_name": name, "direct": direct, "source": "ad"})
            elif (got[1], got[2]) != (name, direct):
                updates.append({"id": got[0], "group_name": name, "direct": direct})
        drop.extend(got[0] for sid, got in old.items() if sid not in new)
    for start in range(0, len(drop), CHUNK):
        db.execute(delete(AssetUserGroup).where(AssetUserGroup.id.in_(drop[start : start + CHUNK])))
    if updates:
        db.execute(update(AssetUserGroup), updates)
    if inserts:
        db.execute(insert(AssetUserGroup), inserts)
    return sum(len(v) for v in have.values()) + len(inserts) - len(drop)


def sync_users(db: Session, handle: JobHandle, data_dir: Path, now: dt.datetime) -> dict[str, int]:
    """Пользователи, наблюдения, группы и связи с хостами из AD и KSC; пересчёт карточек.
    `users` — сколько пользователей видели источники в этом проходе."""
    dmap = domain_map(db)
    ad = users_from_ad(db, data_dir)
    ksc = users_from_ksc(db)
    found = [*ad.seen, *ksc.seen]
    handle.stage("users", total=len(found), message=f"пользователи: AD {len(ad.seen)}, KSC {len(ksc.seen)}")

    index = _Index(db.execute(select(AssetUser)).scalars())
    obs_rows = {(r.source, r.source_key): r for r in db.execute(select(AssetUserObservation)).scalars()}

    # 1. Сопоставление: готовое наблюдение → его пользователь; иначе SID, потом name_key.
    resolved: list[tuple[UserSeen, int, str]] = []
    new: list[AssetUser] = []
    skipped = ambiguous = 0
    for i, s in enumerate(found, start=1):
        if i % TICK_EVERY == 0:
            handle.tick(i)
        key = user_key(s, dmap)
        if key is None:
            skipped += 1
            continue
        row = obs_rows.get((s.source, s.source_key))
        uid = index.survivor(row.user_id) if row is not None else None
        if uid is None:
            m = match_user(key, index.by_sid, index.by_name)
            if m.ambiguous:
                ambiguous += 1
                log.warning("пользователь %s «%s» из %s: неоднозначное сопоставление, пропущен", s.source_key, s.sam, s.source)
                continue
            uid = m.user_id
        if uid is None:
            uid = -(len(new) + 1)
            u = AssetUser(sid=key[0], name_key=key[1], local=s.local, first_seen=s.seen_at, last_seen=s.seen_at)
            new.append(u)
            index.add(uid, u)
        else:
            index.refine(uid, key, authoritative=s.source == "ad")
        resolved.append((s, uid, index.objs[uid].name_key or key[1]))
    db.add_all(new)
    db.flush()

    # 2. Наблюдения.
    key_user: dict[tuple[str, str], int] = {}
    for s, uid, name_key in resolved:
        k = (s.source, s.source_key)
        if k in key_user:
            continue
        real = index.objs[uid].id
        key_user[k] = real
        data = _obs_data(s, name_key)
        row = obs_rows.get(k)
        if row is None:
            row = AssetUserObservation(source=s.source, source_key=s.source_key, user_id=real, seen_at=s.seen_at, data=data)
            db.add(row)
            obs_rows[k] = row
            continue
        if row.user_id != real:
            row.user_id = real
        if row.seen_at != s.seen_at:
            row.seen_at = s.seen_at
        if row.gone_at is not None:
            row.gone_at = None
        if row.data != data:
            row.data = data
    for (src, _key), row in obs_rows.items():
        if (src, _key) in key_user or row.gone_at is not None or src != "ad":
            continue
        if str((row.data or {}).get("domain") or "").lower() not in ad.failed:
            row.gone_at = now

    # 3. Связи с хостами KSC.
    desired: dict[tuple[int, int, str], tuple[bool, dt.datetime]] = {}
    for skey, asset_id, kind, active, seen_at in ksc.links:
        real_uid = key_user.get(("ksc", skey))
        if real_uid is None:
            continue
        prev = desired.get((real_uid, asset_id, kind))
        desired[(real_uid, asset_id, kind)] = ((prev[0] if prev else False) or active, seen_at)
    existing = {(lk.user_id, lk.asset_id, lk.kind): lk
                for lk in db.execute(select(AssetUserHost).where(AssetUserHost.source == "ksc")).scalars()}
    for lk_key, (active, seen_at) in desired.items():
        lk = existing.get(lk_key)
        if lk is None:
            lk = AssetUserHost(user_id=lk_key[0], asset_id=lk_key[1], source="ksc", kind=lk_key[2], active=active, seen_at=seen_at)
            db.add(lk)
            existing[lk_key] = lk
            continue
        if lk.active != active:
            lk.active = active
        if lk.seen_at != seen_at:
            lk.seen_at = seen_at
        if lk.gone_at is not None:
            lk.gone_at = None
    for lk_key, lk in existing.items():
        if lk_key not in desired and lk.gone_at is None and (lk.asset_id in ksc.collected or lk.asset_id not in ksc.hosts):
            lk.gone_at = now
    # Живая связь на хосте, где пользователи не собраны, держит наблюдение KSC пользователя.
    held = {lk.user_id for lk in existing.values() if lk.gone_at is None and lk.asset_id not in ksc.collected}
    for (src, _key), row in obs_rows.items():
        if src == "ksc" and (src, _key) not in key_user and row.gone_at is None and row.user_id not in held:
            row.gone_at = now

    # 4. «Собрано» и группы с сеансом — в extra наблюдений хостов KSC.
    if ksc.host_flags:
        for host_row in db.execute(
            select(AssetObservation).where(AssetObservation.source == "ksc", AssetObservation.source_key.in_(list(ksc.host_flags)))
        ).scalars():
            extra = {**(host_row.extra or {}), **ksc.host_flags[host_row.source_key]}
            if extra != host_row.extra:
                host_row.extra = extra
    db.flush()

    # 5. Группы AD и карточки.
    live_ad_users = {row.user_id for (src, _k), row in obs_rows.items() if src == "ad" and row.gone_at is None}
    group_rows = _sync_groups(db, ad, key_user, live_ad_users)
    per_user: dict[int, list[AssetUserObservation]] = defaultdict(list)
    for row in obs_rows.values():
        per_user[row.user_id].append(row)
    users_by_id = {u.id: u for u in index.objs.values()}
    for uid, rows in per_user.items():
        user = users_by_id.get(uid)
        if user is not None and user.merged_into is None:
            _recompute(user, rows)
    db.flush()

    # 6. Осиротевшие локальные: связей нет вовсе (хост удалён — связи ушли каскадом) и живых наблюдений нет.
    linked = set(db.execute(select(AssetUserHost.user_id).distinct()).scalars())
    live_obs = {row.user_id for row in obs_rows.values() if row.gone_at is None}
    orphans = [u.id for u in users_by_id.values() if u.local and u.merged_into is None and u.id not in linked and u.id not in live_obs]
    for start in range(0, len(orphans), CHUNK):
        db.execute(delete(AssetUser).where(AssetUser.id.in_(orphans[start : start + CHUNK])))

    _store_ad_domains(db, ad.read)
    return {
        "users": len(set(key_user.values())), "observations": len(key_user), "links": len(desired), "groups": group_rows,
        "skipped": skipped, "ambiguous": ambiguous, "removed": len(orphans),
    }


def _store_ad_domains(db: Session, domains: set[str]) -> None:
    value = sorted(d for d in domains if d)
    row = settings_row(db)
    if (row.data or {}).get(AD_DOMAINS_KEY) != value:
        row.data = {**(row.data or {}), AD_DOMAINS_KEY: value}
    db.flush()


def ad_domains(db: Session) -> set[str]:
    """DNS-домены, чьи выгрузки AD прочитаны последней синхронизацией: «нет в AD» — только для них."""
    return {str(d) for d in load_settings(db).get(AD_DOMAINS_KEY) or []}
