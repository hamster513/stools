"""Синхронизация пользователей (спека «Пользователи как активы» §2.1, §3, §4): последний шаг прохода
`assets/sync`, после хостов — связям «пользователь → хост» нужны уже сопоставленные активы.

- AD — учётки `user` последнего снапшота каждого домена из файла выгрузки (компьютеры и gMSA — не
  пользователи): включённость, флаги, группы прямые и вложенные (`ad.core.account_groups`),
  привилегированность — рекурсивный член групп `admin_rids ∪ privileged_rids` или групп из
  `privileged_groups` по имени (sAMAccountName или CN, как `ExportIndex.group_by_name`), либо учётка
  RID 500 (настройки модуля AD). Выгрузка разбирается один раз на проход: хосты и пользователи берут
  её из общего `AdExportCache`.
- KSC — `ksc_host.extra_json` последнего снапшота каждого сервера: `users` (список | null),
  `users_collected`, `owner`. Хост → актив по наблюдению `ksc` с ключом `"{server_id}:{host_id}"`
  (через `Asset.merged_into` — к выжившему). Действующее «собрано» (`users_collected` и `users` —
  список) и группы с сеансом пишет в `extra` наблюдения хоста сама синхронизация хостов
  (`ksc_host_users`, ключи `users_collected`, `session_groups`): карточкам Assets не нужно читать `ksc_host`.
- Ключ наблюдения: AD — SID; KSC — `"{server_id}:{SID}"`, без SID — `"{server_id}:{домен}\\{имя}"`
  как пришли, у локальной — `"{server_id}:{host_id}\\{имя}"`. Одно наблюдение KSC на учётку сервера,
  хосты — связи `asset_user_host`. Запись KSC без SID сопоставляется заново каждый проход: учётка,
  заведённая до выгрузки AD (NetBIOS без карты доменов), переезжает к пользователю AD, когда ключи сошлись.
- Пропавшие: AD — только учётки доменов, чья выгрузка прочитана (файл не читается — его учётки живы);
  связь KSC — только если все хосты KSC её актива (по всем серверам) собраны или актива в KSC больше нет;
  наблюдение KSC — если его нет в проходе и у пользователя нет живой связи на несобранном активе.
- Служебные ключи строки настроек Assets (API настроек их не отдаёт): `users_ad_domains` — DNS-домены,
  чьи выгрузки прочитаны последним проходом (`ad_domains`: «нет в AD» §5.2 судится только по ним);
  `users_ad_group_notes` — заметки `account_groups` по id домена AD («список участников мог быть
  обрезан», `ad_group_notes`): обрезанный список группы задевает любую учётку домена.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeGuard

from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.orm import Session

from api.jobs import JobHandle
from api.modules.assets.core.users import ACCOUNT_SID_PREFIX, UserSeen, match_user, user_key
from api.modules.assets.models import (
    Asset,
    AssetObservation,
    AssetUser,
    AssetUserGroup,
    AssetUserHost,
    AssetUserObservation,
)
from api.modules.assets.services.assets import domain_map, load_settings, settings_row

if TYPE_CHECKING:
    from api.modules.ad.core.export import AdExport

log = logging.getLogger("stools.assets")

#: Прогресс и проверка отмены — раз в столько записей.
TICK_EVERY = 2000
#: Столько строк за раз в одном запросе вставки или удаления.
CHUNK = 10_000
#: Столько пользователей за раз сверяет группы.
GROUP_USERS_CHUNK = 5_000
RID_ADMINISTRATOR = 500
AD_DOMAINS_KEY = "users_ad_domains"
AD_NOTES_KEY = "users_ad_group_notes"
#: Длины столбцов: у AD displayName до 256 символов, UPN до 1024 — длиннее столбца обрезается.
FIELD_LEN = 255
KEY_LEN = 512
GROUP_NAME_LEN = 512

#: Группа учётки AD: (SID, имя `ДОМЕН\\имя`, прямая).
GroupRow = tuple[str, str, bool]
#: Разобранные выгрузки AD прохода: id снапшота → выгрузка или ошибка чтения.
AdExportCache = dict[int, Any]


def _cut(value: Any, size: int = FIELD_LEN) -> str:
    return str(value or "")[:size]


def ad_user_managed(sid: str | None, sam: str | None) -> TypeGuard[str]:
    """Заводят ли «Активы» учётку `user` из AD: нужен SID, и это не учётка доверия (sam на `$`).
    Одно правило у синхронизации и у сверки с ячейкой сводки AD (`services.ad_cells`); `TypeGuard` —
    после «да» SID известен и проверщику типов."""
    return bool(sid) and not (sam or "").endswith("$")


def read_ad_export(cache: AdExportCache | None, data_dir: Path, snapshot_id: int) -> AdExport:
    """Выгрузка снапшота AD — один разбор файла на проход; ошибка чтения запоминается и поднимается снова."""
    from api.modules.ad.core.export import ExportFormatError, load_export_path
    from api.modules.ad.services.snapshots import snapshot_path

    if cache is not None and snapshot_id in cache:
        got = cache[snapshot_id]
        if isinstance(got, Exception):
            raise got
        export: AdExport = got
        return export
    try:
        export = load_export_path(snapshot_path(data_dir, snapshot_id))
    except (ExportFormatError, OSError, ValueError) as exc:
        if cache is not None:
            cache[snapshot_id] = exc
        raise
    if cache is not None:
        cache[snapshot_id] = export
    return export


@dataclass
class AdUsers:
    seen: list[UserSeen] = field(default_factory=list)
    #: SID учётки (ключ наблюдения AD) → группы.
    groups: dict[str, list[GroupRow]] = field(default_factory=dict)
    #: DNS-домены, чья последняя выгрузка прочитана.
    read: set[str] = field(default_factory=set)
    #: id доменов AD, чья последняя выгрузка не прочитана.
    failed: set[int] = field(default_factory=set)
    #: id прочитанного домена → заметки `account_groups`.
    notes: dict[int, list[str]] = field(default_factory=dict)


@dataclass
class KscUsers:
    #: Одна запись на ключ наблюдения (первая встреченная).
    seen: list[UserSeen] = field(default_factory=list)
    #: (ключ наблюдения, актив-хост, session | owner, в системе на момент сбора, время снапшота).
    links: list[tuple[str, int, str, bool, dt.datetime]] = field(default_factory=list)
    #: Активы хостов последних снапшотов; из них — где хоть у одного хоста KSC (сервер, host_id)
    #: пользователи не собраны.
    hosts: set[int] = field(default_factory=set)
    uncollected: set[int] = field(default_factory=set)


# ---- AD -------------------------------------------------------------------


def users_from_ad(db: Session, data_dir: Path, cache: AdExportCache | None = None) -> AdUsers:
    from api.modules.ad.core.account_groups import account_groups
    from api.modules.ad.core.export import (
        UAC_DONT_EXPIRE_PASSWORD,
        ExportFormatError,
        ExportIndex,
        filetime_to_datetime,
    )
    from api.modules.ad.models import AdDomain
    from api.modules.ad.services.settings import load_config
    from api.modules.ad.services.snapshots import latest_snapshot

    cfg = load_config(db)
    rids = {*cfg.admin_rids, *cfg.privileged_rids}
    names = {n.strip().lower() for n in cfg.privileged_groups}
    out = AdUsers()
    for domain in db.execute(select(AdDomain).order_by(AdDomain.id)).scalars():
        snap = latest_snapshot(db, domain.id)
        if snap is None:
            continue
        try:
            export = read_ad_export(cache, data_dir, snap.id)
        except (ExportFormatError, OSError, ValueError) as exc:
            out.failed.add(domain.id)
            log.warning("снапшот AD #%s не прочитан для пользователей: %s", snap.id, type(exc).__name__)
            continue
        idx = ExportIndex(export)
        acc = account_groups(idx)
        dns = (export.domain.dns_root or domain.dns_root or "").lower()
        privileged = {f"S-1-5-32-{r}" if 544 <= r <= 582 else idx.domain_rid_sid(r) for r in rids}
        privileged |= {
            g.sid for g in idx.objects("group")
            if g.sid and ((g.sam or "").lower() in names or (g.name or "").lower() in names)
        }
        for o in idx.objects("user"):
            if not ad_user_managed(o.sid, o.sam):
                continue
            refs = acc.groups.get(o.sid, [])
            last = filetime_to_datetime(o.lastLogonTimestamp)
            manager = idx.get(o.manager) if o.manager else None
            out.seen.append(UserSeen(
                source="ad", source_key=_cut(o.sid, KEY_LEN), seen_at=snap.collected_at, sid=_cut(o.sid), sam=_cut(o.sam),
                upn=_cut(getattr(o, "userPrincipalName", None)), display_name=_cut(getattr(o, "displayName", None)),
                domain=_cut(dns), enabled=o.enabled,
                privileged=o.rid == RID_ADMINISTRATOR or any(g["sid"] in privileged for g in refs),
                data={
                    "mail": o.mail or "", "manager": o.manager or "",
                    "manager_name": _cut(manager.displayName or manager.name or manager.sam) if manager else "",
                    "dn": o.dn, "uac": o.uac, "pwd_never_expires": bool((o.uac or 0) & UAC_DONT_EXPIRE_PASSWORD),
                    "last_logon": last.isoformat() if last else None, "admin_count": o.adminCount, "domain_id": domain.id,
                },
            ))
            out.groups[_cut(o.sid, KEY_LEN)] = [(_cut(g["sid"]), _cut(g["name"], GROUP_NAME_LEN), g["direct"]) for g in refs]
        if dns:
            out.read.add(dns)
        out.notes[domain.id] = list(acc.notes)
    return out


# ---- KSC ------------------------------------------------------------------


def ksc_host_users(extra: dict[str, Any]) -> tuple[bool, list[dict[str, Any]], list[dict[str, Any]]]:
    """(собрано, записи пользователей, группы с сеансом) хоста KSC по `extra_json` (контракт §2.1).
    Собрано — `users_collected` и `users` списком: `users` null (отказ, нет агента) — «не собрано»."""
    users = extra.get("users")
    collected = bool(extra.get("users_collected")) and isinstance(users, list)
    records = [u for u in users if isinstance(u, dict)] if isinstance(users, list) else []
    groups = [{"sid": _cut(u.get("sid")), "sam": _cut(u.get("sam")), "active": bool(u.get("active"))} for u in records if u.get("group")]
    return collected, [u for u in records if not u.get("group")], groups


def _ksc_seen(server_id: int, host_id: str, asset_id: int, rec: dict[str, Any], seen_at: dt.datetime) -> UserSeen:
    sid = _cut(rec.get("sid")).strip().upper()
    sam = _cut(rec.get("sam")).strip()
    domain = _cut(rec.get("domain")).strip()
    local = bool(rec.get("local"))
    prefix, _, bare = sam.rpartition("\\")
    if local:
        who = f"{host_id}\\{bare.lower()}"
    else:
        who = sid or f"{(prefix or domain).lower()}\\{bare.lower()}"
    return UserSeen(
        source="ksc", source_key=_cut(f"{server_id}:{who}", KEY_LEN), seen_at=seen_at, sid=sid, sam=sam,
        upn=_cut(rec.get("upn")), display_name=_cut(rec.get("display_name")), domain=domain,
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


#: RID встроенных групп домена (Domain Admins … Enterprise Key Admins, RAS, группы репликации паролей RODC):
#: SID такой группы — не учётка, даже если AD-выгрузки ещё нет.
DOMAIN_GROUP_RIDS = frozenset({*range(512, 528), 553, 571, 572})


def known_group_sids(db: Session) -> set[str]:
    """SID групп AD, уже известных Assets (группы пользователей прошлой синхронизации)."""
    return {s.upper() for s in db.execute(select(AssetUserGroup.group_sid).distinct()).scalars() if s}


def owner_unresolved(
    owner: Any, people: list[dict[str, Any]], groups: list[dict[str, Any]], group_sids: Iterable[str] = (),
) -> bool:
    """Владелец хоста задан в KSC, но пользователем хоста не становится: `{owner_id}` без SID и имени
    или запись владельца — группа (с сеансом на хосте — `groups`, известная AD — `group_sids`, встроенная
    группа домена по RID), служебная учётка (`$`, SID не учётки) либо запись, которой `user_key` не даёт
    ключа. Такой владелец — только показ (`owner_unresolved` у хоста): ни связи, ни пользователя."""
    if not isinstance(owner, dict):
        return False
    if not (owner.get("sid") or owner.get("sam")):
        return bool(owner.get("owner_id"))
    sid = str(owner.get("sid") or "").upper()
    sam = str(owner.get("sam") or "").lower()
    if any((sid and str(g.get("sid") or "").upper() == sid) or (sam and str(g.get("sam") or "").lower() == sam) for g in groups):
        return True
    rec = _owner_record(owner, people)
    if rec is None:
        return True
    rec_sid = str(rec.get("sid") or "").upper()
    if rec_sid and (rec_sid in {g.upper() for g in group_sids} or _domain_group_rid(rec_sid)):
        return True
    # Локальной записи нужен актив хоста — для проверки ключа подходит любой.
    return user_key(_ksc_seen(0, "", 0, rec, dt.datetime.now(dt.UTC)), {}) is None


def _domain_group_rid(sid: str) -> bool:
    head, _, rid = sid.rpartition("-")
    return head.startswith(ACCOUNT_SID_PREFIX) and rid.isdigit() and int(rid) in DOMAIN_GROUP_RIDS


def users_from_ksc(db: Session, group_sids: Iterable[str] = ()) -> KscUsers:
    """`group_sids` — SID групп AD (`owner_unresolved`): владелец-группа связи и пользователя не даёт."""
    groups_ad = {g.upper() for g in group_sids}
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
            collected, people, groups = ksc_host_users(extra)
            out.hosts.add(asset_id)
            if not collected:
                out.uncollected.add(asset_id)
                continue
            for rec in people:
                s = _ksc_seen(server.id, host_id, asset_id, rec, snap.collected_at)
                by_key.setdefault(s.source_key, s)
                out.links.append((s.source_key, asset_id, "session", bool(rec.get("active")), snap.collected_at))
            owner = _owner_record(extra.get("owner"), people)
            if owner is not None and not owner_unresolved(extra.get("owner"), people, groups, groups_ad):
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
        у локальной (актив хоста сменился при объединении), по AD (переименование) или по записи без SID
        у пользователя без SID (карта доменов появилась), и имя ничьё."""
        u = self.objs[uid]
        sid, name = key
        if sid and not u.sid and not self.by_sid.get(sid):
            self._drop(uid, u)
            u.sid = sid
            self._put(uid, u)
        replace = not u.name_key or u.local or authoritative or (not sid and not u.sid)
        if name and name != u.name_key and replace and not any(other != uid for other, _ in self.by_name.get(name, ())):
            self._drop(uid, u)
            u.name_key = name
            self._put(uid, u)


def _obs_data(s: UserSeen, name_key: str) -> dict[str, Any]:
    data: dict[str, Any] = {
        "sid": _cut(s.sid), "sam": _cut(s.sam), "upn": _cut(s.upn), "display_name": _cut(s.display_name),
        "domain": _cut(s.domain), "local": s.local, "name_key": _cut(name_key, KEY_LEN), **s.data,
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
        return next((_cut(r.data[name]) for r in order if (r.data or {}).get(name)), "")

    sam = first("sam").rpartition("\\")[2]
    domain = "" if u.local or u.name_key.startswith("local:") else u.name_key.rpartition("\\")[0]
    ad = sorted((r for r in rows if r.source == "ad" and r.gone_at is None), key=lambda r: r.seen_at, reverse=True)
    enabled = ad[0].data.get("enabled") if ad else None
    privileged = bool(ad[0].data.get("privileged")) if ad else False
    first_seen = min(r.seen_at for r in rows)
    last_seen = max(r.seen_at for r in rows)
    values: dict[str, Any] = {
        "sam": sam, "upn": first("upn"), "display_name": first("display_name"), "domain": _cut(domain),
        "enabled": None if enabled is None else bool(enabled), "privileged": privileged,
        "first_seen": min(first_seen, u.first_seen) if u.first_seen else first_seen, "last_seen": last_seen,
    }
    for name, value in values.items():
        if getattr(u, name) != value:
            setattr(u, name, value)


def _digest(name: str) -> str:
    """Как `md5(group_name)` в Postgres: имена групп сверяются по отпечатку, не держатся в памяти."""
    return hashlib.md5(name.encode("utf-8"), usedforsecurity=False).hexdigest()


def _sync_groups(db: Session, ad: AdUsers, key_user: dict[tuple[str, str], int]) -> int:
    """Группы AD заменой по пользователю, частями по `GROUP_USERS_CHUNK` пользователей; строки, которые
    не менялись, не трогаются, имя обновляется только при смене отпечатка. У пользователя без живого
    наблюдения AD группы снимаются; домен, чей файл не прочитан, свои группы сохраняет (наблюдение живо).
    Возвращает число строк групп AD после записи."""
    keys: dict[int, str] = {}
    for (src, key), uid in key_user.items():
        if src == "ad" and key in ad.groups:
            keys[uid] = key
    uids = sorted(keys)
    for start in range(0, len(uids), GROUP_USERS_CHUNK):
        chunk = uids[start : start + GROUP_USERS_CHUNK]
        have: dict[int, dict[str, tuple[int, bool, str]]] = defaultdict(dict)
        for gid, uid, sid, direct, digest in db.execute(
            select(AssetUserGroup.id, AssetUserGroup.user_id, AssetUserGroup.group_sid, AssetUserGroup.direct, func.md5(AssetUserGroup.group_name))
            .where(AssetUserGroup.source == "ad", AssetUserGroup.user_id.in_(chunk))
        ).tuples():
            have[uid][sid] = (gid, direct, digest)
        inserts: list[dict[str, Any]] = []
        updates: list[dict[str, Any]] = []
        drop: list[int] = []
        for uid in chunk:
            old = have.get(uid, {})
            new: dict[str, tuple[str, bool]] = {}
            for sid, name, direct in ad.groups[keys[uid]]:
                new.setdefault(sid, (name, direct))
            for sid, (name, direct) in new.items():
                got = old.get(sid)
                if got is None:
                    inserts.append({"user_id": uid, "group_sid": sid, "group_name": name, "direct": direct, "source": "ad"})
                elif got[1] != direct or got[2] != _digest(name):
                    updates.append({"id": got[0], "group_name": name, "direct": direct})
            drop.extend(got[0] for sid, got in old.items() if sid not in new)
        if drop:
            db.execute(delete(AssetUserGroup).where(AssetUserGroup.id.in_(drop)))
        for rows, stmt in ((updates, update(AssetUserGroup)), (inserts, insert(AssetUserGroup))):
            for i in range(0, len(rows), CHUNK):
                db.execute(stmt, rows[i : i + CHUNK])
    live_ad = select(AssetUserObservation.user_id).where(AssetUserObservation.source == "ad", AssetUserObservation.gone_at.is_(None))
    db.execute(delete(AssetUserGroup).where(AssetUserGroup.source == "ad", AssetUserGroup.user_id.not_in(live_ad)))
    return int(db.execute(select(func.count()).select_from(AssetUserGroup).where(AssetUserGroup.source == "ad")).scalar_one())


def sync_users(db: Session, handle: JobHandle, data_dir: Path, now: dt.datetime, ad_cache: AdExportCache | None = None) -> dict[str, int]:
    """Пользователи, наблюдения, группы и связи с хостами из AD и KSC; пересчёт карточек.
    `ad_cache` — выгрузки AD, уже разобранные синхронизацией хостов этого прохода.
    `users` — сколько пользователей видели источники в этом проходе."""
    dmap = domain_map(db)
    ad = users_from_ad(db, data_dir, ad_cache)
    ksc = users_from_ksc(db, known_group_sids(db) | {sid.upper() for rows in ad.groups.values() for sid, _name, _direct in rows})
    found = [*ad.seen, *ksc.seen]
    handle.stage("users", total=len(found), message=f"пользователи: AD {len(ad.seen)}, KSC {len(ksc.seen)}")

    index = _Index(db.execute(select(AssetUser)).scalars())
    obs_rows = {(r.source, r.source_key): r for r in db.execute(select(AssetUserObservation)).scalars()}

    # 1. Сопоставление: готовое наблюдение → его пользователь; иначе SID, потом name_key.
    # Запись KSC без SID сопоставляется заново: ключ мог измениться (карта доменов, выгрузка AD).
    resolved: list[tuple[UserSeen, int, str]] = []
    new: list[AssetUser] = []
    moved_from: set[int] = set()
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
        if uid is None or (s.source == "ksc" and not key[0]):
            m = match_user(key, index.by_sid, index.by_name)
            if m.ambiguous and uid is None:
                ambiguous += 1
                log.warning("пользователь %s «%s» из %s: неоднозначное сопоставление, пропущен", s.source_key, s.sam, s.source)
                continue
            if m.user_id is not None and m.user_id != uid:
                if uid is not None and uid > 0:
                    moved_from.add(uid)
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
    for k, row in obs_rows.items():
        if k[0] == "ad" and k not in key_user and row.gone_at is None and (row.data or {}).get("domain_id") not in ad.failed:
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
    # Связь не судится, пока хоть один хост KSC её актива (другой сервер, другой host_id) не собран.
    for lk_key, lk in existing.items():
        if lk_key not in desired and lk.gone_at is None and (lk.asset_id not in ksc.hosts or lk.asset_id not in ksc.uncollected):
            lk.gone_at = now
    # Живая связь на несобранном активе держит наблюдение KSC пользователя.
    held = {lk.user_id for lk in existing.values() if lk.gone_at is None and lk.asset_id in ksc.uncollected}
    for k, row in obs_rows.items():
        if k[0] == "ksc" and k not in key_user and row.gone_at is None and row.user_id not in held:
            row.gone_at = now
    db.flush()

    # 4. Группы AD и карточки.
    group_rows = _sync_groups(db, ad, key_user)
    per_user: dict[int, list[AssetUserObservation]] = defaultdict(list)
    for row in obs_rows.values():
        per_user[row.user_id].append(row)
    users_by_id = {u.id: u for u in index.objs.values()}
    for uid, rows in per_user.items():
        user = users_by_id.get(uid)
        if user is not None and user.merged_into is None:
            _recompute(user, rows)
    db.flush()

    # 5. Удаляются: локальные без связей вовсе (хост удалён — связи ушли каскадом) и без живых наблюдений;
    # пользователи, от которых записи без SID переехали, если у них не осталось ничего живого.
    live_obs = {row.user_id for row in obs_rows.values() if row.gone_at is None}
    live_links = {lk.user_id for lk in existing.values() if lk.gone_at is None}
    linked = set(db.execute(select(AssetUserHost.user_id).distinct()).scalars())
    orphans = [
        u.id for u in users_by_id.values()
        if u.merged_into is None and u.id not in live_obs
        and ((u.local and u.id not in linked) or (u.id in moved_from and u.id not in live_links))
    ]
    for start in range(0, len(orphans), CHUNK):
        db.execute(delete(AssetUser).where(AssetUser.id.in_(orphans[start : start + CHUNK])))

    _store_ad_state(db, ad)
    return {
        "users": len(set(key_user.values())), "observations": len(key_user), "links": len(desired), "groups": group_rows,
        "skipped": skipped, "ambiguous": ambiguous, "removed": len(orphans),
    }


def _store_ad_state(db: Session, ad: AdUsers) -> None:
    """Прочитанные домены и заметки групп по домену; заметки домена, чей файл не прочитан, — прежние."""
    row = settings_row(db)
    data = dict(row.data or {})
    old_notes = data.get(AD_NOTES_KEY) or {}
    notes = {str(k): v for k, v in ad.notes.items() if v}
    notes.update({k: v for k, v in old_notes.items() if int(k) in ad.failed})
    domains = sorted(ad.read)
    if data.get(AD_DOMAINS_KEY) != domains or data.get(AD_NOTES_KEY) != notes:
        row.data = {**data, AD_DOMAINS_KEY: domains, AD_NOTES_KEY: notes}
    db.flush()


def ad_domains(db: Session) -> set[str]:
    """DNS-домены, чьи выгрузки AD прочитаны последней синхронизацией: «нет в AD» — только для них."""
    return {str(d) for d in load_settings(db).get(AD_DOMAINS_KEY) or []}


def ad_group_notes(db: Session) -> dict[int, list[str]]:
    """id домена AD → заметки «список участников группы мог быть обрезан» (у наблюдения AD — `data.domain_id`)."""
    return {int(k): list(v) for k, v in (load_settings(db).get(AD_NOTES_KEY) or {}).items()}
