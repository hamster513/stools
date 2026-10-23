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
  чей файл не прочитан, не трогается; домен, которого в модуле AD больше нет, — как прочитанный пустой.
- Права по политике: `ad.core.gpo_rights` — строки `asset_group_gpo` домена (замена), хостов не больше
  `GPO_HOSTS_MAX`; оговорки ответа — служебный ключ настроек `groups_gpo_notes` по DNS-домену.
"""
from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy import delete, insert, select
from sqlalchemy.orm import Session

from api.jobs import JobHandle
from api.modules.assets.core.groups import group_key, is_well_known, normalize_sid
from api.modules.assets.models import (
    Asset,
    AssetGroup,
    AssetGroupGpo,
    AssetGroupMember,
    AssetObservation,
    AssetUser,
)
from api.modules.assets.services.assets import load_settings, settings_row
from api.modules.assets.services.users import CHUNK, TICK_EVERY, AdExportCache, read_ad_export

if TYPE_CHECKING:
    from api.modules.ad.core.export import AdObject, ExportIndex

log = logging.getLogger("stools.assets")

GPO_NOTES_KEY = "groups_gpo_notes"
#: Хостов в строке `asset_group_gpo` не больше; полное число — `hosts_total`.
GPO_HOSTS_MAX = 1000
#: Классы учёток AD, участники-«пользователи» (связь — только если учётка стала пользователем-активом).
USER_CLASSES = frozenset({"user", "inetOrgPerson", "msDS-GroupManagedServiceAccount", "msDS-ManagedServiceAccount"})
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


def _live_assets(db: Session) -> dict[str, int]:
    """Ключ наблюдения AD компьютера → актив-выживший."""
    merged = {a: m for a, m in db.execute(select(Asset.id, Asset.merged_into).where(Asset.merged_into.is_not(None))).tuples() if m is not None}

    def alive(asset_id: int) -> int:
        seen: set[int] = set()
        while asset_id in merged and asset_id not in seen:
            seen.add(asset_id)
            asset_id = merged[asset_id]
        return asset_id

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
                values["sources"] = [*(g.sources or []), "ad"]
            if g.first_seen is None or g.first_seen > d.seen_at:
                values["first_seen"] = d.seen_at
            for attr, value in values.items():
                if getattr(g, attr) != value:
                    setattr(g, attr, value)
    for key, g in existing.items():
        if key not in seen and g.gone_at is None and "ad" in (g.sources or []) and g.domain not in ad.failed:
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


def _member_rows(d: _AdDomainRead, o: AdObject, look: _Lookup) -> list[dict[str, Any]]:
    """Прямой состав группы `o`: одна строка на (SID, имя); основная группа — `primary` на той же строке."""
    from api.modules.ad.core.export import fsp_sid

    rows: dict[tuple[str, str], dict[str, Any]] = {}

    def put(kind: str, sid: str, name: str, domain: str = "", *, user_id: int | None = None, group_id: int | None = None,
            asset_id: int | None = None, primary: bool = False) -> None:
        k = (_cut(sid), _cut(name, NAME_LEN))
        row = rows.get(k)
        if row is not None:
            row["primary"] = row["primary"] or primary
            return
        rows[k] = {"member_kind": kind, "user_id": user_id, "member_group_id": group_id, "asset_id": asset_id,
                   "member_sid": k[0], "member_name": k[1], "member_domain": _cut(domain), "primary": primary, "source": "ad"}

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
    return list(rows.values())


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


def _sync_ad_members(db: Session, ad: _AdRead, keys: dict[str, int]) -> int:
    """Состав AD групп заменой: удаляются строки AD всех доменных групп, кроме доменов с непрочитанным файлом
    (пропавшие группы и домены, которых больше нет, — тоже), затем вставляется состав прочитанных."""
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
    stale = select(AssetGroup.id).where(AssetGroup.local.is_(False), AssetGroup.domain.not_in(sorted(ad.failed)))
    db.execute(delete(AssetGroupMember).where(AssetGroupMember.source == "ad", AssetGroupMember.group_id.in_(stale)))
    rows: list[dict[str, Any]] = []
    for d in ad.domains:
        for o in d.idx.objects("group"):
            if not o.sid:
                continue
            gid = keys.get(_cut(group_key(local=False, domain=d.dns, host_asset_id=None, sid=o.sid, name=_cut(o.sam or o.name, NAME_LEN)), KEY_LEN))
            if gid is None:
                continue
            rows.extend({**r, "group_id": gid} for r in _member_rows(d, o, look))
    # Одна группа дважды в выгрузке (тот же ключ) — строки её состава один раз.
    unique = list({(r["group_id"], r["member_sid"], r["member_name"]): r for r in rows}.values())
    for i in range(0, len(unique), CHUNK):
        db.execute(insert(AssetGroupMember), unique[i : i + CHUNK])
    return len(unique)


def _sync_gpo(db: Session, ad: _AdRead) -> int:
    """Права по GPO заменой по домену; домен с непрочитанным файлом сохраняет строки и заметки."""
    from api.modules.ad.core.gpo_rights import gpo_rights

    db.execute(delete(AssetGroupGpo).where(AssetGroupGpo.domain.not_in(sorted(ad.failed))))
    rows: list[dict[str, Any]] = []
    notes: dict[str, dict[str, Any]] = {}
    for d in ad.domains:
        got = gpo_rights(d.idx)
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
    for i in range(0, len(rows), CHUNK):
        db.execute(insert(AssetGroupGpo), rows[i : i + CHUNK])
    row = settings_row(db)
    data = dict(row.data or {})
    old = data.get(GPO_NOTES_KEY) or {}
    notes.update({k: v for k, v in old.items() if k in ad.failed and k not in notes})
    if data.get(GPO_NOTES_KEY) != notes:
        row.data = {**data, GPO_NOTES_KEY: notes}
    db.flush()
    return len(rows)


def sync_groups(db: Session, handle: JobHandle, data_dir: Path, now: dt.datetime, ad_cache: AdExportCache | None = None) -> dict[str, int]:
    """Группы, их состав и права по GPO. `ad_cache` — выгрузки AD, уже разобранные этим проходом.
    `groups` — сколько групп AD видели выгрузки этого прохода."""
    ad = _read_ad(db, data_dir, ad_cache)
    keys, skipped = _upsert_ad_groups(db, handle, ad, now)
    members = _sync_ad_members(db, ad, keys)
    gpo = _sync_gpo(db, ad)
    db.flush()
    # Локальные группы из VM (задача 4) — следующим шагом здесь же; их счётчик — `vm_hosts_unmatched`.
    return {"groups": len(keys), "members": members, "gpo": gpo, "vm_hosts_unmatched": 0, "skipped": skipped}


def gpo_notes(db: Session) -> dict[str, dict[str, Any]]:
    """DNS-домен → оговорки `gpo_rights` последней синхронизации: `links_known`, `files_known`, `notes`."""
    return {str(k): dict(v) for k, v in (load_settings(db).get(GPO_NOTES_KEY) or {}).items()}
