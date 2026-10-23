"""Пользователи как активы — список, карточка, ручные поля, пользователи в карточке хоста
(спека «Пользователи как активы» §3–§5, план, задача 3).

Читаются только таблицы `asset_user*` и наблюдения хостов: ни AD, ни KSC при просмотре не спрашиваются.
Расхождения (`core.users.user_discrepancies`) считаются на лету, как у хостов: список отбирает
пользователей в базе по `q` и `host_id`, берёт их наблюдения (сводкой по источнику), связи, имена и ОС
активов и признак «пользователи собраны» несколькими запросами и фильтрует по осям в памяти.

- «Собраны» у актива — как в синхронизации: есть живые наблюдения `ksc`, и у всех `extra.users_collected`
  (пишет синхронизация хостов); нет наблюдения, нет ключа или хоть один хост KSC актива не собран — «не собрано».
- Связь устарела (`stale`) — живая связь на активе, где пользователи не собраны, виденная раньше
  `stale_days` (настройка Assets): в расхождениях не участвует — иначе «заходил раньше» на хосте,
  снятом с агента, висело бы вечно; в карточке показывается с пометкой, в `session` (как прошлый сеанс)
  и в `hosts_total` считается.
- Сеанс для фильтра `session`: active — хоть один живой сеанс «в системе на момент сбора» (на собранном
  хосте); past — живые сеансы есть, но все прошлые; none — живых сеансов нет.
- Фасет оси считается по пользователям под всеми фильтрами, кроме фильтра этой оси.
"""
from __future__ import annotations

import datetime as dt
from collections import defaultdict
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any

from sqlalchemy import exists, func, or_, select
from sqlalchemy.orm import Session

from api.modules.assets.core.groups import normalize_sid
from api.modules.assets.core.users import (
    USER_CODES,
    UserCard,
    UserDiscrepancy,
    UserHostLink,
    user_discrepancies,
)
from api.modules.assets.models import (
    Asset,
    AssetObservation,
    AssetUser,
    AssetUserGroup,
    AssetUserHost,
    AssetUserObservation,
)
from api.modules.assets.services.ad_cells import key_in
from api.modules.assets.services.assets import ANY_CODE, load_settings
from api.modules.assets.services.group_views import user_group_ids
from api.modules.assets.services.users import ad_domains, ad_group_notes
from api.timeutil import utcnow

USER_SOURCES = ("ad", "ksc")
STATES = ("enabled", "disabled", "unknown")
SESSIONS = ("active", "past", "none")
YES_NO = ("yes", "no")
#: Оси фильтров с фасетами; `q` и `host_id` сужают выборку до фасетов.
AXES = ("source", "state", "session", "local", "privileged", "code")
KIND_ORDER = ("session", "owner", "local_group")


class UserNotFound(LookupError):
    pass


class UserConflict(Exception):
    """Действие противоречит состоянию пользователя (объединён с другим)."""


@dataclass(slots=True)
class _Link:
    """Связь пользователя с активом-хостом — то, что нужно расхождениям, фильтру сеанса и счётчикам."""

    asset_id: int
    kind: str
    active: bool
    gone: bool
    collected: bool
    stale: bool


def _iso(value: dt.datetime | None) -> str | None:
    return value.isoformat() if value else None


def collected_assets(db: Session, asset_ids: Collection[int] | None = None) -> set[int]:
    """Активы, у которых пользователи собраны, — как в синхронизации: есть живые наблюдения `ksc`, и у всех
    `extra.users_collected` (хоть один хост KSC актива не собран — не собран и актив)."""
    flag = func.coalesce(AssetObservation.extra["users_collected"].as_boolean(), False)
    stmt = (
        select(AssetObservation.asset_id)
        .where(AssetObservation.source == "ksc", AssetObservation.gone_at.is_(None))
        .group_by(AssetObservation.asset_id)
        .having(func.bool_and(flag))
    )
    if asset_ids is not None:
        stmt = stmt.where(AssetObservation.asset_id.in_(list(asset_ids)))
    return set(db.execute(stmt).scalars())


def _discrepancies(
    enabled: bool | None, privileged: bool, local: bool, domain: str, in_ad: bool,
    links: list[_Link], hosts: dict[int, tuple[str, str]], domains: set[str],
) -> list[UserDiscrepancy]:
    """`hosts` — актив → (имя, ОС); устаревшие связи в расхождениях не участвуют."""
    card = UserCard(enabled=enabled, privileged=privileged, local=local, domain=domain, in_ad=in_ad)
    core = [
        UserHostLink(asset_id=lk.asset_id, name=hosts.get(lk.asset_id, ("", ""))[0], os=hosts.get(lk.asset_id, ("", ""))[1],
                     kind=lk.kind, active=lk.active, gone=lk.gone, users_collected=lk.collected)
        for lk in links if not lk.stale
    ]
    return user_discrepancies(card, core, domains)


def _session(links: list[_Link]) -> str:
    live = [lk for lk in links if lk.kind == "session" and not lk.gone]
    if any(lk.active and lk.collected for lk in live):
        return "active"
    return "past" if live else "none"


#: Наблюдения пользователя по источнику: (источник, есть живое, последнее живое, последнее вообще).
SourceAgg = tuple[str, bool, dt.datetime | None, dt.datetime]


def _sources(aggs: list[SourceAgg], now: dt.datetime, stale_days: int) -> list[dict[str, Any]]:
    """Значок на источник, как у активов: живой ли и свежее ли `stale_days`."""
    out = []
    by_source = {a[0]: a for a in aggs}
    for source in USER_SOURCES:
        if source not in by_source:
            continue
        _src, live, live_seen, seen = by_source[source]
        last = live_seen if live and live_seen is not None else seen
        out.append({"source": source, "live": live, "fresh": live and now - last < dt.timedelta(days=stale_days),
                    "seen_at": last.isoformat()})
    return out


def _counts(links: list[_Link]) -> tuple[int, int]:
    """(хостов «в системе на момент сбора», хостов с живыми связями — и устаревшими тоже)."""
    live = [lk for lk in links if not lk.gone]
    active = {lk.asset_id for lk in live if lk.kind == "session" and lk.active and lk.collected}
    return len(active), len({lk.asset_id for lk in live})


def _codes(found: list[UserDiscrepancy]) -> list[str]:
    return sorted({d.code for d in found}, key=USER_CODES.index)


def _matches(chosen: frozenset[str] | None, values: set[str], *, any_code: bool = False) -> bool:
    if chosen is None:
        return True
    if any_code and ANY_CODE in chosen and values:
        return True
    return bool(chosen & values)


def _user_conditions(q: str | None, host_id: frozenset[int] | None) -> list[Any]:
    """Отбор в базе: живые (не слитые), подстрока `q` без учёта регистра (`%` и `_` — буквально),
    связь с активами `host_id` (и пропавшая)."""
    conds: list[Any] = [AssetUser.merged_into.is_(None)]
    needle = (q or "").strip().lower()
    if needle:
        conds.append(or_(*(col.icontains(needle, autoescape=True)
                           for col in (AssetUser.sam, AssetUser.upn, AssetUser.display_name, AssetUser.sid))))
    if host_id is not None:
        conds.append(exists().where(AssetUserHost.user_id == AssetUser.id, AssetUserHost.asset_id.in_(sorted(host_id))))
    return conds


def list_users(
    db: Session,
    *,
    q: str | None = None,
    source: frozenset[str] | None = None,
    state: frozenset[str] | None = None,
    session: frozenset[str] | None = None,
    local: frozenset[str] | None = None,
    privileged: frozenset[str] | None = None,
    code: frozenset[str] | None = None,
    host_id: frozenset[int] | None = None,
    ad_keys: frozenset[str] | None = None,
    limit: int = 200,
    offset: int = 0,
    now: dt.datetime | None = None,
) -> tuple[list[dict[str, Any]], int, dict[str, Any]]:
    """items, total, facets. Слитые (`merged_into`) не показываются. `q` — подстрока sam, UPN,
    отображаемого имени или SID без учёта регистра; `host_id` — пользователи со связью с этими активами
    (и пропавшей тоже — как блок «Пользователи» карточки хоста); `code` — коды или `any`; `ad_keys` — SID
    из состава ячейки сводки AD (`services.ad_cells`).
    `q` и `host_id` отбирает база; наблюдения и связи читаются только у отобранных (подзапросом),
    без ORM-объектов: на 100 тыс. учёток список держит в памяти кортежи, а не карточки."""
    now = now or utcnow()
    stale_days = int(load_settings(db)["stale_days"])
    domains = ad_domains(db)
    conds = _user_conditions(q, host_id)
    if ad_keys is not None:
        conds.append(key_in(AssetUser.sid, ad_keys))
    picked_ids = select(AssetUser.id).where(*conds)
    # Core, не ORM: сотни тысяч строк-кортежей без обёртки загрузчика ORM.
    conn = db.connection()
    users = conn.execute(
        select(AssetUser.id, AssetUser.sam, AssetUser.upn, AssetUser.display_name, AssetUser.domain, AssetUser.local,
               AssetUser.enabled, AssetUser.privileged, AssetUser.last_seen).where(*conds)
    ).tuples().all()
    o = AssetUserObservation
    aggs: dict[int, list[SourceAgg]] = defaultdict(list)
    for uid, src, live, live_seen, seen in conn.execute(
        select(o.user_id, o.source, func.bool_or(o.gone_at.is_(None)), func.max(o.seen_at).filter(o.gone_at.is_(None)),
               func.max(o.seen_at))
        .where(o.user_id.in_(picked_ids)).group_by(o.user_id, o.source)
    ).tuples():
        aggs[uid].append((src, bool(live), live_seen, seen))
    lnk = AssetUserHost
    linked = select(lnk.asset_id).where(lnk.user_id.in_(picked_ids))
    hosts = {aid: (name, os) for aid, name, os in conn.execute(select(Asset.id, Asset.name, Asset.os).where(Asset.id.in_(linked))).tuples()}
    collected = collected_assets(db)
    cutoff = now - dt.timedelta(days=stale_days)
    links: dict[int, list[_Link]] = defaultdict(list)
    for uid, aid, kind, active, gone, old in conn.execute(
        select(lnk.user_id, lnk.asset_id, lnk.kind, lnk.active, lnk.gone_at.is_not(None), lnk.seen_at < cutoff).where(lnk.user_id.in_(picked_ids))
    ).tuples():
        col = aid in collected
        links[uid].append(_Link(aid, kind, active, gone, col, not gone and not col and old))
    chosen = {"source": source, "state": state, "session": session, "local": local, "privileged": privileged, "code": code}

    facets: dict[str, dict[str, int]] = {
        "source": dict.fromkeys(USER_SOURCES, 0), "state": dict.fromkeys(STATES, 0), "session": dict.fromkeys(SESSIONS, 0),
        "local": dict.fromkeys(YES_NO, 0), "privileged": dict.fromkeys(YES_NO, 0), "code": dict.fromkeys((*USER_CODES, ANY_CODE), 0),
    }
    picked: list[tuple[Any, list[str]]] = []
    for u in users:
        uid, _sam, _upn, _name, domain, is_local, enabled, is_privileged, _last = u
        mine = links.get(uid, [])
        live = {a[0] for a in aggs.get(uid, []) if a[1]}
        codes = _codes(_discrepancies(enabled, is_privileged, is_local, domain, "ad" in live, mine, hosts, domains))
        values = {
            "source": live,
            "state": {"unknown" if enabled is None else "enabled" if enabled else "disabled"},
            "session": {_session(mine)},
            "local": {"yes" if is_local else "no"},
            "privileged": {"yes" if is_privileged else "no"},
            "code": set(codes),
        }
        failed = [axis for axis in AXES if not _matches(chosen[axis], values[axis], any_code=axis == "code")]
        if len(failed) > 1:
            continue
        for axis in AXES:
            if failed and failed[0] != axis:
                continue
            for v in values[axis]:
                facets[axis][v] += 1
            if axis == "code" and codes:
                facets["code"][ANY_CODE] += 1
        if not failed:
            picked.append((u, codes))

    picked.sort(key=lambda t: (t[0][1].lower() or "~", t[0][4], t[0][0]))
    page = []
    for (uid, sam, upn, name, domain, is_local, enabled, is_privileged, last_seen), codes in picked[offset : offset + limit]:
        hosts_active, hosts_total = _counts(links.get(uid, []))
        page.append({
            "id": uid, "sam": sam, "upn": upn, "display_name": name, "domain": domain, "local": is_local,
            "enabled": enabled, "privileged": is_privileged, "sources": _sources(aggs.get(uid, []), now, stale_days),
            "hosts_active": hosts_active, "hosts_total": hosts_total, "last_seen": _iso(last_seen), "codes": codes,
        })
    return page, len(picked), facets


def _user_or_404(db: Session, user_id: int) -> AssetUser:
    user = db.get(AssetUser, user_id)
    if user is None:
        raise UserNotFound("пользователь не найден")
    return user


def user_detail(db: Session, user_id: int, now: dt.datetime | None = None) -> dict[str, Any]:
    """Карточка: поля, наблюдения, группы AD (прямые, затем вложенные), оговорка «список участников
    группы мог быть обрезан» по домену AD учётки, устройства, расхождения с текстами. Слитый
    пользователь отдаётся как есть, с `merged_into`."""
    now = now or utcnow()
    user = _user_or_404(db, user_id)
    stale_days = int(load_settings(db)["stale_days"])
    rows = list(db.execute(
        select(AssetUserObservation).where(AssetUserObservation.user_id == user.id).order_by(AssetUserObservation.id)
    ).scalars())
    device_rows = db.execute(
        select(AssetUserHost.asset_id, AssetUserHost.kind, AssetUserHost.active, AssetUserHost.seen_at, AssetUserHost.gone_at,
               Asset.name, Asset.ip, Asset.os)
        .join(Asset, Asset.id == AssetUserHost.asset_id)
        .where(AssetUserHost.user_id == user.id)
        .order_by(AssetUserHost.id)
    ).tuples().all()
    collected = collected_assets(db, {r[0] for r in device_rows})
    cutoff = now - dt.timedelta(days=stale_days)
    links = [
        _Link(aid, kind, active, gone_at is not None, aid in collected, gone_at is None and aid not in collected and seen_at < cutoff)
        for aid, kind, active, seen_at, gone_at, _name, _ip, _os in device_rows
    ]
    hosts = {r[0]: (r[5], r[7]) for r in device_rows}
    groups = sorted(
        db.execute(select(AssetUserGroup).where(AssetUserGroup.user_id == user.id)).scalars(),
        key=lambda g: (not g.direct, g.group_name.lower(), g.group_sid),
    )
    group_ids = user_group_ids(db, user.domain, [g.group_sid for g in groups])
    live_ad = [r for r in rows if r.source == "ad" and r.gone_at is None]
    notes_of = ad_group_notes(db)
    domain_ids = dict.fromkeys(int(r.data["domain_id"]) for r in live_ad if (r.data or {}).get("domain_id") is not None)
    notes = [n for d in domain_ids for n in notes_of.get(d, [])]
    found = _discrepancies(user.enabled, user.privileged, user.local, user.domain, bool(live_ad), links, hosts, ad_domains(db))
    hosts_active, hosts_total = _counts(links)
    devices = sorted(
        zip(device_rows, links, strict=True),
        key=lambda d: (d[1].gone, KIND_ORDER.index(d[1].kind) if d[1].kind in KIND_ORDER else 9, d[0][5].lower(), d[1].asset_id),
    )
    aggs: list[SourceAgg] = []
    for src in USER_SOURCES:
        mine = [r for r in rows if r.source == src]
        if mine:
            live_rows = [r.seen_at for r in mine if r.gone_at is None]
            aggs.append((src, bool(live_rows), max(live_rows) if live_rows else None, max(r.seen_at for r in mine)))
    return {
        "id": user.id, "sid": user.sid, "name_key": user.name_key, "sam": user.sam, "upn": user.upn,
        "display_name": user.display_name, "domain": user.domain, "local": user.local, "enabled": user.enabled,
        "privileged": user.privileged, "first_seen": _iso(user.first_seen), "last_seen": _iso(user.last_seen),
        "merged_into": user.merged_into, "note": user.note, "tags": list(user.tags or []),
        "created_at": _iso(user.created_at), "updated_at": _iso(user.updated_at),
        "sources": _sources(aggs, now, stale_days),
        "hosts_active": hosts_active, "hosts_total": hosts_total, "codes": _codes(found),
        "observations": [
            {"id": r.id, "source": r.source, "source_key": r.source_key, "seen_at": _iso(r.seen_at), "gone_at": _iso(r.gone_at),
             "data": dict(r.data or {})}
            for r in rows
        ],
        "groups": [{"sid": g.group_sid, "name": g.group_name, "direct": g.direct, "source": g.source,
                    "group_id": group_ids.get(normalize_sid(g.group_sid))} for g in groups],
        "group_notes": notes,
        "devices": [
            {"asset_id": aid, "name": name, "ip": ip, "os": os, "kind": kind, "active": active,
             "seen_at": _iso(seen_at), "gone_at": _iso(gone_at), "users_collected": lk.collected, "stale": lk.stale}
            for (aid, kind, active, seen_at, gone_at, name, ip, os), lk in devices
        ],
        "discrepancies": [{"code": d.code, "host_asset_id": d.host_asset_id, "text": d.text} for d in found],
    }


def update_user(db: Session, user_id: int, values: dict[str, Any]) -> AssetUser:
    """Ручные поля: note, tags — синхронизация их не трогает. Слитый пользователь не правится:
    его карточку заменяет та, в которую он слит."""
    user = _user_or_404(db, user_id)
    if user.merged_into is not None:
        raise UserConflict(f"пользователь объединён с #{user.merged_into} — правьте его карточку")
    if "tags" in values:
        user.tags = list(dict.fromkeys(t.strip() for t in values["tags"] or [] if t.strip()))
    if "note" in values:
        user.note = values["note"] or ""
    db.flush()
    return user


def host_users(db: Session, asset_id: int, rows: list[AssetObservation]) -> dict[str, Any]:
    """Блок «Пользователи» карточки хоста по его наблюдениям: `users` — связи с пользователями (и пропавшие,
    `gone`), None — пользователи хоста не собраны; `session_groups` — группы с сеансом из KSC (только показ);
    `owner_unresolved` — владелец задан в KSC, но среди пользователей хоста его нет."""
    ksc = [r for r in rows if r.source == "ksc" and r.gone_at is None]
    # Как `collected_assets`: хоть один живой хост KSC актива не собран — не собраны.
    collected = bool(ksc) and all((r.extra or {}).get("users_collected") for r in ksc)
    owner_unresolved = any((r.extra or {}).get("owner_unresolved") for r in ksc)
    if not collected:
        return {"users": None, "session_groups": None, "owner_unresolved": owner_unresolved}
    found = db.execute(
        select(AssetUserHost.user_id, AssetUser.sam, AssetUser.display_name, AssetUser.domain, AssetUser.local,
               AssetUserHost.kind, AssetUserHost.active, AssetUserHost.seen_at, AssetUserHost.gone_at)
        .join(AssetUser, AssetUser.id == AssetUserHost.user_id)
        .where(AssetUserHost.asset_id == asset_id, AssetUser.merged_into.is_(None))
    ).tuples().all()
    found = sorted(found, key=lambda r: (r[8] is not None, not r[6], KIND_ORDER.index(r[5]) if r[5] in KIND_ORDER else 9, r[1].lower(), r[0]))
    return {
        "users": [
            {"user_id": uid, "sam": sam, "display_name": name, "domain": domain, "local": local, "kind": kind, "active": active,
             "seen_at": _iso(seen_at), "gone": gone_at is not None}
            for uid, sam, name, domain, local, kind, active, seen_at, gone_at in found
        ],
        "session_groups": [g for r in ksc for g in (r.extra or {}).get("session_groups") or []],
        "owner_unresolved": owner_unresolved,
    }
