"""Группы как активы — список, карточка, полный состав (спека «Группы как активы» §4–§6, план, задача 5).

Читаются только таблицы `asset_group*` и активы: ни AD, ни VM при просмотре не спрашиваются.

- Список: все оси — столбцы группы, поэтому отбор, фасеты и страница считаются в базе. Фасет оси — по группам
  под всеми фильтрами, кроме фильтра этой оси; `q`, `domain` и `host_id` сужают и фасеты.
- Карточка: прямой состав (до `MEMBERS_MAX` строк), предки — подъёмом по `member_group_id` (родители фронта
  одним запросом на шаг) только через доменные группы: доменные предки — «Куда входит», локальные группы, где
  прямо состоит сама группа или её доменный предок, — «права по факту» (спека §5). Выше локальной группы подъём
  не идёт: локальная группа Windows не вкладывается в локальную. По хостам — до `LOCAL_OF_MAX` строк по имени
  хоста; свод по факту — строка на (локальная группа: SID, без SID — имя; цепочка) с `FACT_HOSTS_MAX` хостами
  (у Domain Users и Domain Admins — локальные группы почти каждого хоста). По политике — строки `asset_group_gpo`: у доменной — с SID группы или её
  доменного предка (SID `S-1-5-21-*` — по одному SID, прочие — ещё и по домену GPO), у локальной — с её SID
  (у строки без SID цели — по имени) и её хостом в списке хостов GPO.
- Полный состав: спуск от группы по `asset_group_member` (участники фронта одним запросом на шаг), только
  достижимая часть, затем `core.groups.expand`.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Collection, Iterable
from typing import Any

from sqlalchemy import and_, case, exists, func, literal, or_, select, type_coerce
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

from api.modules.assets.core.groups import (
    Edge,
    Leaf,
    ancestors,
    expand,
    normalize_sid,
    well_known_text,
)
from api.modules.assets.models import Asset, AssetGroup, AssetGroupGpo, AssetGroupMember
from api.modules.assets.services.groups import gpo_notes
from api.modules.assets.services.users import ad_group_notes

GROUP_SOURCES = ("ad", "vm")
KINDS = ("local", "domain")
STATES = ("live", "gone")
MEMBERS = ("some", "none")
#: Оси фильтров с фасетами; `q`, `domain` и `host_id` сужают выборку до фасетов.
AXES = ("kind", "source", "state", "members")
#: Прямой состав в карточке: у Domain Users через primaryGroupID — все учётки домена; полный счёт — `members_total`.
MEMBERS_MAX = 1000
#: Локальных групп «по хостам» в карточке; полный счёт — `local_member_of_total`.
LOCAL_OF_MAX = 1000
#: Хостов в строке свода «по факту»; полный счёт — `hosts_total`.
FACT_HOSTS_MAX = 50
#: Тупиков полного состава в ответе; полный счёт — `dead_ends_total`.
DEAD_ENDS_MAX = 500
#: Столько id в одном `IN` при обходе.
IN_CHUNK = 5000
KIND_ORDER = ("group", "user", "computer", "well_known", "unknown")
DOMAIN_SID = "S-1-5-21-"


class GroupNotFound(LookupError):
    pass


def _chunks(ids: Collection[int]) -> Iterable[list[int]]:
    items = sorted(ids)
    for i in range(0, len(items), IN_CHUNK):
        yield items[i : i + IN_CHUNK]


def _members_exist() -> Any:
    return exists().where(AssetGroupMember.group_id == AssetGroup.id)


def _axis_condition(axis: str, value: str) -> Any:
    if axis == "kind":
        return AssetGroup.local.is_(value == "local")
    if axis == "source":
        return type_coerce(AssetGroup.sources, JSONB).contains([value])
    if axis == "state":
        return AssetGroup.gone_at.is_(None) if value == "live" else AssetGroup.gone_at.is_not(None)
    return _members_exist() if value == "some" else ~_members_exist()


def _base_conditions(q: str | None, domain: frozenset[str] | None, host_id: frozenset[int] | None) -> list[Any]:
    """`q` — подстрока имени или SID без учёта регистра (`%` и `_` — буквально); `domain` — DNS-домен доменной
    или имя (короткое или FQDN) хоста локальной; `host_id` — локальные группы этих активов."""
    conds: list[Any] = []
    needle = (q or "").strip().lower()
    if needle:
        conds.append(or_(AssetGroup.name.icontains(needle, autoescape=True), AssetGroup.sid.icontains(needle, autoescape=True)))
    if domain is not None:
        values = sorted({d.strip().lower() for d in domain})
        hosts = select(Asset.id).where(or_(func.lower(Asset.name).in_(values), func.lower(Asset.fqdn).in_(values)))
        conds.append(or_(
            and_(AssetGroup.local.is_(False), func.lower(AssetGroup.domain).in_(values)),
            and_(AssetGroup.local.is_(True), AssetGroup.host_asset_id.in_(hosts)),
        ))
    if host_id is not None:
        conds.append(AssetGroup.host_asset_id.in_(sorted(host_id)))
    return conds


def _chosen_conditions(chosen: dict[str, frozenset[str] | None], skip: str | None = None) -> list[Any]:
    return [or_(*(_axis_condition(axis, v) for v in sorted(values)))
            for axis, values in chosen.items() if values is not None and axis != skip]


def _sources(value: Any) -> list[str]:
    got = set(value or ())
    return [s for s in GROUP_SOURCES if s in got] + sorted(got - set(GROUP_SOURCES))


def _members_count() -> Any:
    return select(func.count()).where(AssetGroupMember.group_id == AssetGroup.id).correlate(AssetGroup).scalar_subquery()


def _item(row: Any) -> dict[str, Any]:
    gid, name, domain, local, host_id, sid, description, sources, in_ad, gone_at, host_name, members, os_family = row
    return {"id": gid, "name": name, "domain_label": (host_name or "") if local else domain, "host_asset_id": host_id,
            "local": local, "os_family": os_family, "sid": sid, "description": description, "sources": _sources(sources),
            "members_direct": int(members), "in_ad": in_ad, "gone": gone_at is not None}


def _item_columns() -> tuple[Any, ...]:
    g = AssetGroup
    return (g.id, g.name, g.domain, g.local, g.host_asset_id, g.sid, g.description, g.sources, g.in_ad, g.gone_at, Asset.name,
            _members_count(), g.os_family)


def _iso(value: Any) -> str | None:
    return value.isoformat() if value else None


def _dates(conn: Connection, group_id: int, os_family: str) -> dict[str, str | None]:
    """Даты шапки карточки; у локальной — ещё время снимка VM, которым семейство её хоста записано полностью
    последний раз (`VmGroupImport.<семейство>_ok`)."""
    from api.modules.vm.models import VmGroupImport

    first, last, gone = conn.execute(
        select(AssetGroup.first_seen, AssetGroup.last_seen, AssetGroup.gone_at).where(AssetGroup.id == group_id)
    ).one()
    flag = {"windows": VmGroupImport.windows_ok, "linux": VmGroupImport.linux_ok}.get(os_family)
    snapshot = conn.execute(select(func.max(VmGroupImport.finished_at)).where(flag.is_(True))).scalar() if flag is not None else None
    return {"first_seen": _iso(first), "last_seen": _iso(last), "gone_at": _iso(gone), "vm_snapshot_at": _iso(snapshot)}


def list_groups(
    db: Session,
    *,
    q: str | None = None,
    kind: frozenset[str] | None = None,
    source: frozenset[str] | None = None,
    state: frozenset[str] | None = None,
    members: frozenset[str] | None = None,
    domain: frozenset[str] | None = None,
    host_id: frozenset[int] | None = None,
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int, dict[str, dict[str, int]]]:
    """items, total, facets. Порядок — по имени, затем по домену или хосту, затем по id."""
    conn = db.connection()
    base = _base_conditions(q, domain, host_id)
    chosen = {"kind": kind, "source": source, "state": state, "members": members}
    values = {"kind": KINDS, "source": GROUP_SOURCES, "state": STATES, "members": MEMBERS}
    facets: dict[str, dict[str, int]] = {}
    for axis in AXES:
        counts = conn.execute(
            select(*(func.count().filter(_axis_condition(axis, v)) for v in values[axis]))
            .select_from(AssetGroup).where(*base, *_chosen_conditions(chosen, skip=axis))
        ).one()
        facets[axis] = {v: int(n) for v, n in zip(values[axis], counts, strict=True)}
    where = [*base, *_chosen_conditions(chosen)]
    total = int(conn.execute(select(func.count()).select_from(AssetGroup).where(*where)).scalar_one())
    label = func.lower(func.coalesce(func.nullif(AssetGroup.domain, ""), Asset.name, literal("")))
    rows = conn.execute(
        select(*_item_columns())
        .select_from(AssetGroup).outerjoin(Asset, Asset.id == AssetGroup.host_asset_id)
        .where(*where)
        .order_by(func.lower(AssetGroup.name), label, AssetGroup.id)
        .offset(offset).limit(limit)
    ).tuples().all()
    return [_item(r) for r in rows], total, facets


# ---- карточка ------------------------------------------------------------------------------------------


def _group_row(conn: Connection, group_id: int) -> Any:
    row = conn.execute(
        select(*_item_columns()).select_from(AssetGroup).outerjoin(Asset, Asset.id == AssetGroup.host_asset_id)
        .where(AssetGroup.id == group_id)
    ).tuples().first()
    if row is None:
        raise GroupNotFound("группа не найдена")
    return row


def _parents(conn: Connection, start: int) -> dict[int, list[int]]:
    """Группа → группы, куда она прямо входит: `start` и его доменные предки (подъём фронтом); родители-локальные
    группы попадают в ответ, но сами не раскрываются."""
    parents: dict[int, list[int]] = defaultdict(list)
    loaded: set[int] = set()
    frontier = {start}
    while frontier:
        loaded |= frontier
        found: set[int] = set()
        for chunk in _chunks(frontier):
            for child, parent, local in conn.execute(
                select(AssetGroupMember.member_group_id, AssetGroupMember.group_id, AssetGroup.local)
                .join(AssetGroup, AssetGroup.id == AssetGroupMember.group_id)
                .where(AssetGroupMember.member_group_id.in_(chunk)).distinct()
            ).tuples():
                if child is not None:
                    parents[child].append(parent)
                    if not local:
                        found.add(parent)
        frontier = found - loaded
    for v in parents.values():
        v.sort()
    return parents


#: Сведения о группе для ссылок: (имя, домен, локальная, хост, SID, есть в AD).
GroupMeta = tuple[str, str, bool, int | None, str, bool]


def _meta(conn: Connection, ids: Collection[int]) -> dict[int, GroupMeta]:
    out: dict[int, GroupMeta] = {}
    for chunk in _chunks(ids):
        for gid, name, domain, local, host, sid, in_ad in conn.execute(
            select(AssetGroup.id, AssetGroup.name, AssetGroup.domain, AssetGroup.local, AssetGroup.host_asset_id, AssetGroup.sid,
                   AssetGroup.in_ad).where(AssetGroup.id.in_(chunk))
        ).tuples():
            out[gid] = (name, domain, local, host, sid, in_ad)
    return out


def _host_names(conn: Connection, ids: Collection[int]) -> dict[int, str]:
    out: dict[int, str] = {}
    for chunk in _chunks(ids):
        out.update(conn.execute(select(Asset.id, Asset.name).where(Asset.id.in_(chunk))).tuples().all())
    return out


def _ref(meta: dict[int, GroupMeta], gid: int) -> dict[str, Any]:
    return {"id": gid, "name": meta[gid][0] if gid in meta else ""}


def _member_id(kind: str, user_id: int | None, group_id: int | None, asset_id: int | None) -> int | None:
    return {"user": user_id, "group": group_id, "computer": asset_id}.get(kind)


def _direct_members(conn: Connection, group_id: int) -> tuple[list[dict[str, Any]], int]:
    m = AssetGroupMember
    total = int(conn.execute(select(func.count()).where(m.group_id == group_id)).scalar_one())
    order = case({k: i for i, k in enumerate(KIND_ORDER)}, value=m.member_kind, else_=len(KIND_ORDER))
    rows = conn.execute(
        select(m.member_kind, m.user_id, m.member_group_id, m.asset_id, m.member_name, m.member_domain, m.member_sid, m.primary, m.source)
        .where(m.group_id == group_id).order_by(order, func.lower(m.member_name), m.id).limit(MEMBERS_MAX)
    ).tuples().all()
    items = [
        {"kind": kind, "id": _member_id(kind, uid, gid, aid), "name": name, "domain": domain, "sid": sid, "primary": primary,
         "source": source, "text": well_known_text(sid) if kind == "well_known" else ""}
        for kind, uid, gid, aid, name, domain, sid, primary, source in rows
    ]
    return items, total


def _short(name: str) -> str:
    return name.split(".", 1)[0]


def _host_assets(conn: Connection, names: Collection[str]) -> dict[str, int | None]:
    """Имя хоста GPO → живой актив: FQDN — по FQDN актива (без FQDN у актива — по короткому имени), короткое — по
    короткому имени; только однозначное совпадение, иначе None."""
    keys = {n: n.strip().lower().rstrip(".") for n in names}
    fqdns = sorted({k for k in keys.values() if "." in k})
    shorts = sorted({_short(k) for k in keys.values() if k})
    by_fqdn: dict[str, list[int]] = defaultdict(list)
    by_short: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for i in range(0, max(len(fqdns), len(shorts)), IN_CHUNK):
        f, s = fqdns[i : i + IN_CHUNK], shorts[i : i + IN_CHUNK]
        conds = [c for c in (func.lower(Asset.fqdn).in_(f) if f else None, Asset.name_key.in_(s) if s else None) if c is not None]
        for aid, fqdn, key in conn.execute(
            select(Asset.id, Asset.fqdn, Asset.name_key).where(Asset.merged_into.is_(None), or_(*conds))
        ).tuples():
            if fqdn:
                by_fqdn[fqdn.lower().rstrip(".")].append(aid)
            by_short[key].append((aid, (fqdn or "").lower()))
    out: dict[str, int | None] = {}
    for name, key in keys.items():
        if "." in key:
            found = by_fqdn.get(key) or [aid for aid, fqdn in by_short.get(_short(key), []) if not fqdn]
        else:
            found = [aid for aid, _fqdn in by_short.get(key, [])]
        out[name] = found[0] if len(set(found)) == 1 else None
    return out


def _host_matches(name: str, asset_fqdn: str, asset_key: str) -> bool:
    n = name.strip().lower().rstrip(".")
    fqdn = asset_fqdn.lower().rstrip(".")
    if "." in n:
        return n == fqdn or (not fqdn and _short(n) == asset_key)
    return n == asset_key


GPO_COLUMNS = (AssetGroupGpo.id, AssetGroupGpo.domain, AssetGroupGpo.group_sid, AssetGroupGpo.local_group,
               AssetGroupGpo.local_group_sid, AssetGroupGpo.via, AssetGroupGpo.action, AssetGroupGpo.gpo_name,
               AssetGroupGpo.filtered, AssetGroupGpo.hosts, AssetGroupGpo.hosts_total)


def _policy_domain(conn: Connection, group_id: int, chains: dict[int, list[int]], meta: dict[int, GroupMeta]) -> list[tuple[Any, int]]:
    """Строки GPO доменной группы: (строка, через какую группу) — сама группа или ближайший доменный предок."""
    candidates = [group_id, *sorted((a for a in chains if not meta[a][2]), key=lambda a: (len(chains[a]), a))]
    by_sid: dict[str, list[int]] = defaultdict(list)
    for gid in candidates:
        if meta[gid][4]:
            by_sid[normalize_sid(meta[gid][4])].append(gid)
    if not by_sid:
        return []
    out: list[tuple[Any, int]] = []
    for row in conn.execute(select(*GPO_COLUMNS).where(AssetGroupGpo.group_sid.in_(sorted(by_sid)))).tuples():
        sid, gpo_domain = normalize_sid(row[2]), row[1].lower()
        through = next((gid for gid in by_sid.get(sid, [])
                        if sid.startswith(DOMAIN_SID) or meta[gid][1].lower() == gpo_domain), None)
        if through is not None:
            out.append((row, through))
    return out


def _policy_local(conn: Connection, sid: str, name: str, host_id: int | None) -> list[tuple[Any, int]]:
    """Строки GPO локальной группы на её хосте: цель — её SID (у строки без SID цели — её имя)."""
    if host_id is None:
        return []
    host = conn.execute(select(Asset.fqdn, Asset.name_key).where(Asset.id == host_id)).tuples().first()
    if host is None:
        return []
    sid = normalize_sid(sid)
    by_name = func.lower(AssetGroupGpo.local_group) == name.strip().lower()
    target = or_(AssetGroupGpo.local_group_sid == sid, and_(AssetGroupGpo.local_group_sid == "", by_name)) if sid else by_name
    rows = conn.execute(select(*GPO_COLUMNS).where(target)).tuples().all()
    return [(r, 0) for r in rows if any(_host_matches(h, host[0], host[1]) for h in r[9] or [])]


def _policy_items(conn: Connection, rows: list[tuple[Any, int]], group_id: int, meta: dict[int, GroupMeta]) -> list[dict[str, Any]]:
    assets = _host_assets(conn, {h for r, _ in rows for h in r[9] or []})
    items: list[tuple[tuple[str, str, bool, str], dict[str, Any]]] = []
    for row, through in rows:
        _id, _domain, _sid, local_group, _lsid, via, action, gpo_name, filtered, hosts, hosts_total = row
        ref = None if through in (0, group_id) else _ref(meta, through)
        key = (gpo_name.lower(), local_group.lower(), ref is not None, ref["name"].lower() if ref else "")
        items.append((key, {
            "local_group": local_group, "via": via, "action": action, "gpo_name": gpo_name, "filtered": filtered,
            "hosts_total": hosts_total, "hosts": [{"name": h, "asset_id": assets.get(h)} for h in hosts or []],
            "through": ref,
        }))
    items.sort(key=lambda t: t[0])
    return [item for _key, item in items]


def _gpo_notes(db: Session, domains: Iterable[str]) -> list[dict[str, Any]]:
    notes = gpo_notes(db)
    return [{"domain": d, **notes[d]} for d in sorted({x.lower() for x in domains if x}) if d in notes]


def _fact(local_of: list[dict[str, Any]], meta: dict[int, GroupMeta]) -> list[dict[str, Any]]:
    """Свод «по факту»: строка на (локальная группа — SID, без SID — имя в нижнем регистре; цепочка). `local_of`
    уже по имени хоста — первые хосты строки тоже по нему."""
    rows: dict[tuple[str, tuple[int, ...]], dict[str, Any]] = {}
    for x in local_of:
        sid = meta[x["group_id"]][4]
        key = (sid or x["name"].lower(), tuple(v["id"] for v in x["via"]))
        row = rows.get(key)
        if row is None:
            row = rows[key] = {"local_group": x["name"], "local_group_sid": sid, "via": x["via"], "hosts_total": 0, "hosts": []}
        row["hosts_total"] += 1
        if len(row["hosts"]) < FACT_HOSTS_MAX:
            row["hosts"].append({"group_id": x["group_id"], "host_asset_id": x["host_asset_id"], "host_name": x["host_name"]})
    return sorted(rows.values(), key=lambda r: (-r["hosts_total"], r["local_group"].lower(), len(r["via"]),
                                                [v["name"].lower() for v in r["via"]]))


def group_detail(db: Session, group_id: int) -> dict[str, Any]:
    """Карточка: поля списка, `host_name`, даты (`first_seen`, `last_seen`, `gone_at`, у локальной — `vm_snapshot_at`),
    прямой состав, куда входит, права по факту и по политике (см. модуль)."""
    conn = db.connection()
    row = _group_row(conn, group_id)
    card = _item(row)
    card["host_name"] = row[10] or ""
    card.update(_dates(conn, group_id, card["os_family"]))
    members, members_total = _direct_members(conn, group_id)
    parents = _parents(conn, group_id)
    chains = ancestors({group_id}, lambda gid: parents.get(gid, []))
    meta = _meta(conn, {group_id, *chains})
    hosts = _host_names(conn, {h for a in chains if meta[a][2] and (h := meta[a][3]) is not None})
    by_chain = sorted(chains, key=lambda a: (len(chains[a]), meta[a][0].lower(), a))
    member_of = [{"id": a, "name": meta[a][0], "domain": meta[a][1], "direct": len(chains[a]) == 1}
                 for a in by_chain if not meta[a][2]]
    local_ids = sorted((a for a in chains if meta[a][2]),
                       key=lambda a: (hosts.get(meta[a][3] or 0, "").lower(), meta[a][0].lower(), a))
    local_of = [{"group_id": a, "name": meta[a][0], "host_asset_id": meta[a][3], "host_name": hosts.get(meta[a][3] or 0, ""),
                 "via": [_ref(meta, x) for x in chains[a][1:]]} for a in local_ids]
    if card["local"]:
        policy_rows = _policy_local(conn, card["sid"], card["name"], card["host_asset_id"])
        host_domain = conn.execute(select(Asset.domain).where(Asset.id == card["host_asset_id"])).scalar() or ""
        domains = [host_domain, *(r[1] for r, _ in policy_rows)]
    else:
        policy_rows = _policy_domain(conn, group_id, chains, meta)
        domains = [meta[group_id][1], *(meta[a][1] for a in chains if not meta[a][2]), *(r[1] for r, _ in policy_rows)]
    return {
        **card,
        "members": members, "members_total": members_total,
        "member_of": member_of,
        "local_member_of": local_of[:LOCAL_OF_MAX], "local_member_of_total": len(local_of),
        "rights": {"fact": _fact(local_of, meta), "policy": _policy_items(conn, policy_rows, group_id, meta), "notes": _gpo_notes(db, domains)},
    }


# ---- полный состав ---------------------------------------------------------------------------------------


def _reachable(conn: Connection, root: int) -> tuple[dict[int, list[Edge]], dict[tuple[Any, ...], str]]:
    """Прямой состав всех групп, достижимых от `root` (спуск фронтом), и домен участника по его рёбру."""
    m = AssetGroupMember
    edges: dict[int, list[Edge]] = defaultdict(list)
    domains: dict[tuple[Any, ...], str] = {}
    loaded: set[int] = set()
    frontier = {root}
    while frontier:
        loaded |= frontier
        found: set[int] = set()
        for chunk in _chunks(frontier):
            for gid, kind, uid, mgid, aid, sid, name, domain, primary in conn.execute(
                select(m.group_id, m.member_kind, m.user_id, m.member_group_id, m.asset_id, m.member_sid, m.member_name,
                       m.member_domain, m.primary).where(m.group_id.in_(chunk)).order_by(m.group_id, m.id)
            ).tuples():
                edges[gid].append(Edge(kind, uid, mgid, aid, sid, name, primary))
                domains.setdefault((kind, uid, aid, sid, name), domain)
                if kind == "group" and mgid is not None:
                    found.add(mgid)
        frontier = found - loaded
    return edges, domains


def _dead_reason(leaf: Leaf, meta: dict[int, GroupMeta]) -> str:
    if leaf.kind != "group":
        return "неизвестный участник"
    if leaf.group_id is None:
        return "группа без записи"
    got = meta.get(leaf.group_id)
    return "нет в AD" if got is not None and not got[2] and not got[5] else "пустая"


def group_expanded(db: Session, group_id: int, limit: int = 200, offset: int = 0) -> dict[str, Any]:
    """Полный состав (спека §6): `items` — пользователи и компьютеры постранично, `well_known` целиком, `dead_ends` —
    до `DEAD_ENDS_MAX`; `notes` — оговорки AD «список участников мог быть обрезан» доменов пройденных групп."""
    from api.modules.ad.models import AdDomain

    conn = db.connection()
    _group_row(conn, group_id)
    edges, domains = _reachable(conn, group_id)
    res = expand(group_id, lambda gid: edges.get(gid, []))
    meta = _meta(conn, res.groups_seen)

    def via(leaf: Leaf) -> list[dict[str, Any]]:
        return [_ref(meta, g) for g in leaf.via]

    def domain(leaf: Leaf) -> str:
        if leaf.group_id is not None and leaf.group_id in meta:
            return meta[leaf.group_id][1]
        return domains.get((leaf.kind, leaf.user_id, leaf.asset_id, leaf.sid, leaf.name), "")

    items = [
        {"kind": x.kind, "id": x.user_id if x.kind == "user" else x.asset_id, "name": x.name, "domain": domain(x), "sid": x.sid,
         "via": via(x), "paths": x.paths}
        for x in res.leaves[offset : offset + limit]
    ]
    seen_domains = {meta[g][1].lower() for g in res.groups_seen if g in meta and not meta[g][2] and meta[g][1]}
    ids = [int(i) for i in conn.execute(
        select(AdDomain.id).where(func.lower(AdDomain.dns_root).in_(sorted(seen_domains))).order_by(AdDomain.id)
    ).scalars()] if seen_domains else []
    notes_of = ad_group_notes(db)
    return {
        "total": len(res.leaves),
        "items": items,
        "well_known": [{"sid": x.sid, "name": x.name, "text": well_known_text(x.sid), "via": via(x), "paths": x.paths}
                       for x in res.well_known],
        "dead_ends": [{"kind": x.kind, "id": x.group_id, "name": x.name, "domain": domain(x), "sid": x.sid, "via": via(x),
                       "paths": x.paths, "reason": _dead_reason(x, meta)} for x in res.dead_ends[:DEAD_ENDS_MAX]],
        "dead_ends_total": len(res.dead_ends),
        "notes": list(dict.fromkeys(n for d in ids for n in notes_of.get(d, []))),
    }


def user_group_ids(db: Session, user_domain: str, sids: Collection[str]) -> dict[str, int]:
    """SID группы карточки пользователя → доменная группа (план): тот же SID и домен пользователя; SID
    `S-1-5-21-*` уникален между доменами — по одному SID. Живая группа предпочтительнее пропавшей."""
    wanted = sorted({normalize_sid(s) for s in sids if s})
    if not wanted:
        return {}
    domain = user_domain.strip().lower()
    out: dict[str, tuple[tuple[int, int, int], int]] = {}
    for gid, sid, gdomain, gone_at in db.execute(
        select(AssetGroup.id, AssetGroup.sid, AssetGroup.domain, AssetGroup.gone_at)
        .where(AssetGroup.local.is_(False), AssetGroup.sid.in_(wanted))
    ).tuples():
        same = gdomain.lower() == domain
        if not same and not sid.startswith(DOMAIN_SID):
            continue
        rank = (0 if same else 1, 0 if gone_at is None else 1, gid)
        if sid not in out or rank < out[sid][0]:
            out[sid] = (rank, gid)
    return {sid: gid for sid, (_rank, gid) in out.items()}
