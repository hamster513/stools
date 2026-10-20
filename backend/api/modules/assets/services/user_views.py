"""Пользователи как активы — список, карточка, ручные поля, пользователи в карточке хоста
(спека «Пользователи как активы» §3–§5, план, задача 3).

Читаются только таблицы `asset_user*` и наблюдения хостов: ни AD, ни KSC при просмотре не спрашиваются.
Расхождения (`core.users.user_discrepancies`) считаются на лету, как у хостов: список берёт пользователей,
наблюдения, связи с именем и ОС актива и признак «пользователи собраны» несколькими запросами на всех
и фильтрует в памяти.

- «Собраны» у актива — есть живое наблюдение `ksc` с `extra.users_collected` (пишет синхронизация хостов);
  нет такого наблюдения или ключа — «не собрано».
- Связь устарела (`stale`) — живая связь на активе, где пользователи не собраны, виденная раньше
  `stale_days` (настройка Assets): в расхождениях не участвует — иначе «заходил раньше» на хосте,
  снятом с агента, висело бы вечно; в карточке показывается с пометкой.
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

from sqlalchemy import select
from sqlalchemy.orm import Session

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
from api.modules.assets.services.assets import ANY_CODE, load_settings
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


@dataclass(slots=True)
class _Link:
    asset_id: int
    name: str
    ip: str
    os: str
    kind: str
    active: bool
    seen_at: dt.datetime
    gone_at: dt.datetime | None
    collected: bool = False
    stale: bool = False


def _iso(value: dt.datetime | None) -> str | None:
    return value.isoformat() if value else None


def collected_assets(db: Session, asset_ids: Collection[int] | None = None) -> set[int]:
    """Активы, у которых пользователи собраны: живое наблюдение `ksc` с `extra.users_collected`."""
    flag = AssetObservation.extra["users_collected"].as_boolean()
    stmt = select(AssetObservation.asset_id).where(
        AssetObservation.source == "ksc", AssetObservation.gone_at.is_(None), flag.is_(True),
    )
    if asset_ids is not None:
        stmt = stmt.where(AssetObservation.asset_id.in_(list(asset_ids)))
    return set(db.execute(stmt).scalars())


def _links(db: Session, now: dt.datetime, stale_days: int, user_id: int | None = None) -> dict[int, list[_Link]]:
    """Связи пользователей (одного или всех) с именем, адресом и ОС актива; `collected`, `stale` — по правилам выше."""
    stmt = (
        select(AssetUserHost.user_id, AssetUserHost.asset_id, AssetUserHost.kind, AssetUserHost.active, AssetUserHost.seen_at,
               AssetUserHost.gone_at, Asset.name, Asset.ip, Asset.os)
        .join(Asset, Asset.id == AssetUserHost.asset_id)
        .order_by(AssetUserHost.id)
    )
    if user_id is not None:
        stmt = stmt.where(AssetUserHost.user_id == user_id)
    rows = db.execute(stmt).tuples().all()
    collected = collected_assets(db, {r[1] for r in rows} if user_id is not None else None)
    cutoff = now - dt.timedelta(days=stale_days)
    out: dict[int, list[_Link]] = defaultdict(list)
    for uid, asset_id, kind, active, seen_at, gone_at, name, ip, os in rows:
        lk = _Link(asset_id, name, ip, os, kind, active, seen_at, gone_at, collected=asset_id in collected)
        lk.stale = gone_at is None and not lk.collected and seen_at < cutoff
        out[uid].append(lk)
    return out


def _discrepancies(user: AssetUser, in_ad: bool, links: list[_Link], domains: set[str]) -> list[UserDiscrepancy]:
    card = UserCard(enabled=user.enabled, privileged=user.privileged, local=user.local, domain=user.domain, in_ad=in_ad)
    core = [
        UserHostLink(asset_id=lk.asset_id, name=lk.name, os=lk.os, kind=lk.kind, active=lk.active,
                     gone=lk.gone_at is not None, users_collected=lk.collected)
        for lk in links if not lk.stale
    ]
    return user_discrepancies(card, core, domains)


def _session(links: list[_Link]) -> str:
    live = [lk for lk in links if lk.kind == "session" and lk.gone_at is None]
    if any(lk.active and lk.collected for lk in live):
        return "active"
    return "past" if live else "none"


def _sources(obs: list[tuple[str, dt.datetime, dt.datetime | None]], now: dt.datetime, stale_days: int) -> list[dict[str, Any]]:
    """Значок на источник, как у активов: живой ли и свежее ли `stale_days`."""
    out = []
    for source in USER_SOURCES:
        mine = [o for o in obs if o[0] == source]
        if not mine:
            continue
        live = [o for o in mine if o[2] is None]
        seen = max(o[1] for o in (live or mine))
        out.append({"source": source, "live": bool(live), "fresh": bool(live) and now - seen < dt.timedelta(days=stale_days),
                    "seen_at": seen.isoformat()})
    return out


def _counts(links: list[_Link]) -> tuple[int, int]:
    """(хостов «в системе на момент сбора», хостов с живыми связями)."""
    live = [lk for lk in links if lk.gone_at is None]
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
    limit: int = 200,
    offset: int = 0,
    now: dt.datetime | None = None,
) -> tuple[list[dict[str, Any]], int, dict[str, Any]]:
    """items, total, facets. Слитые (`merged_into`) не показываются. `q` — подстрока sam, UPN,
    отображаемого имени или SID без учёта регистра; `host_id` — пользователи со связью с этими активами
    (и пропавшей тоже — как блок «Пользователи» карточки хоста); `code` — коды или `any`."""
    now = now or utcnow()
    stale_days = int(load_settings(db)["stale_days"])
    domains = ad_domains(db)
    users = list(db.execute(select(AssetUser).where(AssetUser.merged_into.is_(None))).scalars())
    obs: dict[int, list[tuple[str, dt.datetime, dt.datetime | None]]] = defaultdict(list)
    for uid, src, seen_at, gone_at in db.execute(
        select(AssetUserObservation.user_id, AssetUserObservation.source, AssetUserObservation.seen_at, AssetUserObservation.gone_at)
    ).tuples():
        obs[uid].append((src, seen_at, gone_at))
    links = _links(db, now, stale_days)
    needle = (q or "").strip().lower()
    chosen = {"source": source, "state": state, "session": session, "local": local, "privileged": privileged, "code": code}

    facets: dict[str, dict[str, int]] = {
        "source": dict.fromkeys(USER_SOURCES, 0), "state": dict.fromkeys(STATES, 0), "session": dict.fromkeys(SESSIONS, 0),
        "local": dict.fromkeys(YES_NO, 0), "privileged": dict.fromkeys(YES_NO, 0), "code": dict.fromkeys((*USER_CODES, ANY_CODE), 0),
    }
    picked: list[tuple[AssetUser, list[str]]] = []
    for u in users:
        if needle and not any(needle in (t or "").lower() for t in (u.sam, u.upn, u.display_name, u.sid)):
            continue
        mine = links.get(u.id, [])
        if host_id is not None and not any(lk.asset_id in host_id for lk in mine):
            continue
        rows = obs.get(u.id, [])
        live = {o[0] for o in rows if o[2] is None}
        codes = _codes(_discrepancies(u, "ad" in live, mine, domains))
        values = {
            "source": live,
            "state": {"unknown" if u.enabled is None else "enabled" if u.enabled else "disabled"},
            "session": {_session(mine)},
            "local": {"yes" if u.local else "no"},
            "privileged": {"yes" if u.privileged else "no"},
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

    picked.sort(key=lambda t: (t[0].sam.lower() or "~", t[0].domain, t[0].id))
    page = []
    for u, codes in picked[offset : offset + limit]:
        hosts_active, hosts_total = _counts(links.get(u.id, []))
        page.append({
            "id": u.id, "sam": u.sam, "upn": u.upn, "display_name": u.display_name, "domain": u.domain, "local": u.local,
            "enabled": u.enabled, "privileged": u.privileged, "sources": _sources(obs.get(u.id, []), now, stale_days),
            "hosts_active": hosts_active, "hosts_total": hosts_total, "last_seen": _iso(u.last_seen), "codes": codes,
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
    links = _links(db, now, stale_days, user.id).get(user.id, [])
    groups = sorted(
        db.execute(select(AssetUserGroup).where(AssetUserGroup.user_id == user.id)).scalars(),
        key=lambda g: (not g.direct, g.group_name.lower(), g.group_sid),
    )
    live_ad = [r for r in rows if r.source == "ad" and r.gone_at is None]
    notes_of = ad_group_notes(db)
    domain_ids = dict.fromkeys(int(r.data["domain_id"]) for r in live_ad if (r.data or {}).get("domain_id") is not None)
    notes = [n for d in domain_ids for n in notes_of.get(d, [])]
    found = _discrepancies(user, bool(live_ad), links, ad_domains(db))
    hosts_active, hosts_total = _counts(links)
    devices = sorted(links, key=lambda lk: (lk.gone_at is not None, KIND_ORDER.index(lk.kind) if lk.kind in KIND_ORDER else 9,
                                            lk.name.lower(), lk.asset_id))
    return {
        "id": user.id, "sid": user.sid, "name_key": user.name_key, "sam": user.sam, "upn": user.upn,
        "display_name": user.display_name, "domain": user.domain, "local": user.local, "enabled": user.enabled,
        "privileged": user.privileged, "first_seen": _iso(user.first_seen), "last_seen": _iso(user.last_seen),
        "merged_into": user.merged_into, "note": user.note, "tags": list(user.tags or []),
        "created_at": _iso(user.created_at), "updated_at": _iso(user.updated_at),
        "sources": _sources([(r.source, r.seen_at, r.gone_at) for r in rows], now, stale_days),
        "hosts_active": hosts_active, "hosts_total": hosts_total, "codes": _codes(found),
        "observations": [
            {"id": r.id, "source": r.source, "source_key": r.source_key, "seen_at": _iso(r.seen_at), "gone_at": _iso(r.gone_at),
             "data": dict(r.data or {})}
            for r in rows
        ],
        "groups": [{"sid": g.group_sid, "name": g.group_name, "direct": g.direct, "source": g.source} for g in groups],
        "group_notes": notes,
        "devices": [
            {"asset_id": lk.asset_id, "name": lk.name, "ip": lk.ip, "os": lk.os, "kind": lk.kind, "active": lk.active,
             "seen_at": _iso(lk.seen_at), "gone_at": _iso(lk.gone_at), "users_collected": lk.collected, "stale": lk.stale}
            for lk in devices
        ],
        "discrepancies": [{"code": d.code, "host_asset_id": d.host_asset_id, "text": d.text} for d in found],
    }


def update_user(db: Session, user_id: int, values: dict[str, Any]) -> AssetUser:
    """Ручные поля: note, tags — синхронизация их не трогает."""
    user = _user_or_404(db, user_id)
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
    collected = [r for r in ksc if (r.extra or {}).get("users_collected")]
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
        "session_groups": [g for r in collected for g in (r.extra or {}).get("session_groups") or []],
        "owner_unresolved": owner_unresolved,
    }
