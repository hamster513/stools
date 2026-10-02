"""Выборка пар хост–CVE: фильтры, фасеты, сортировки (спека §8).

Один запрос собирает и страницу, и фасеты; фасеты считаются по всей
выборке с теми же фильтрами, а не по загруженной странице — иначе
счётчики менялись бы при прокрутке.

Статус пары — строка `platform_finding_state` с ключом `hostname|ip|cve`
(статусы находок, спека §3). Пар — десятки тысяч и больше, строк состояния —
только те, о которых решали люди. Поэтому ключ не собирается по каждой паре:
строки состояния разбираются обратно в (host_id, cve_id) — CVE и IP символа
`|` не содержат, их отрезают справа, а хост находится по уникальному
(hostname, ip), — и присоединяются к парам по первичному ключу (`ST`).
Пара без строки — «новая», без исполнителя и сроков.
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from dataclasses import dataclass, field, fields
from typing import Any

from sqlalchemy import Select, and_, case, func, literal, not_, or_, select, tuple_
from sqlalchemy.orm import Session
from sqlalchemy.sql import ColumnElement, Subquery

from api.modules.vm.models import VmCve, VmHost, VmHostCve
from api.platform.findings import service as finding_svc
from api.platform.findings.core import OPEN, STATUS_TITLES, STATUSES, is_overdue
from api.platform.findings.models import FindingState

#: Статусы находок VM: одна область, ключ пары — `pair_key`.
MODULE = "vm"
SCOPE = 0


def pair_key(hostname: str, ip: str, cve_id: str) -> str:
    """Ключ пары — имя хоста и IP как хранятся в `vm_host`, без приведения регистра:
    у той же пары в следующем импорте тот же ключ. Хост с новым IP — новая пара."""
    return f"{hostname}|{ip}|{cve_id}"

LEVELS = ("low", "medium", "high", "critical")
LEVEL_BOUNDS = {"low": (0, 19), "medium": (20, 39), "high": (40, 69), "critical": (70, 100)}

SORTS: dict[str, list[Any]] = {
    # При равном балле (после отсечения на 100 их много) выше — пара с
    # большим сырым риском: она дальше от порога, а не просто первая по имени.
    "risk_desc": [VmHostCve.risk.desc(), VmHostCve.risk_raw.desc(), VmHost.hostname, VmHostCve.cve_id],
    "risk_asc": [VmHostCve.risk.asc(), VmHostCve.risk_raw.asc(), VmHost.hostname, VmHostCve.cve_id],
    "cvss_desc": [VmCve.cvss.desc().nulls_last(), VmHostCve.risk.desc()],
    "epss_desc": [VmCve.epss.desc().nulls_last(), VmHostCve.risk.desc()],
    "exploits_desc": [VmCve.exploits_count.desc(), VmHostCve.risk.desc()],
    "host_asc": [VmHost.hostname, VmHost.ip, VmHostCve.risk.desc()],
    "cve_asc": [VmHostCve.cve_id, VmHostCve.risk.desc()],
}


def _state_subquery() -> Subquery:
    """Строки состояния VM как (host_id, cve_id, …): см. описание модуля. Строка, хоста
    которой в текущих данных нет, сюда не попадает — и к парам не присоединится."""
    s = FindingState
    rev = func.reverse(s.key)
    cve_r, ip_r = func.split_part(rev, "|", 1), func.split_part(rev, "|", 2)
    hostname = func.left(s.key, func.length(s.key) - func.length(cve_r) - func.length(ip_r) - 2)
    return (
        select(
            VmHost.id.label("host_id"),
            func.reverse(cve_r).label("cve_id"),
            s.status,
            s.assignee,
            s.due_date,
            s.risk_until,
            s.first_seen_at,
        )
        .select_from(s)
        .join(VmHost, and_(VmHost.hostname == hostname, VmHost.ip == func.reverse(ip_r)))
        .where(s.module == MODULE, s.scope_id == SCOPE)
        .subquery("st")
    )


ST = _state_subquery()


@dataclass(frozen=True)
class StatusFilter:
    """Отбор по статусу пары (спека §5). `statuses=None` — все; `assignee` — логин или `none`."""

    statuses: frozenset[str] | None = None
    assignee: str | None = None
    overdue: bool = False
    risk_expiring: bool = False
    #: «Сегодня» для сроков; None — `finding_svc.today()` на момент запроса.
    today: dt.date | None = None

    def is_noop(self) -> bool:
        return self.statuses is None and self.assignee is None and not self.overdue and not self.risk_expiring

    def keeps_undecided(self) -> bool:
        """Пара без строки состояния — «новая», без исполнителя и сроков — проходит фильтр."""
        return ((self.statuses is None or "new" in self.statuses) and self.assignee in (None, "none")
                and not self.overdue and not self.risk_expiring)

    def day(self) -> dt.date:
        return self.today or finding_svc.today()


def status_filter(status: str | None, assignee: str | None, overdue: bool | None, risk_expiring: bool | None,
                  *, login: str) -> StatusFilter:
    """Параметры списка, как у других модулей: `status` — коды через запятую или `all`; не задан —
    открытые, а с «риск истекает» — принятые. `assignee`: `me`, `none` или логин."""
    statuses: frozenset[str] | None
    if not status:
        statuses = frozenset({"risk_accepted"}) if risk_expiring else OPEN
    elif status == "all":
        statuses = None
    else:
        statuses = frozenset(s for s in status.split(",") if s)
        unknown = statuses - set(STATUSES)
        if unknown or not statuses:
            raise ValueError(f"неизвестный статус: {', '.join(sorted(unknown)) or status}")
    return StatusFilter(statuses, login if assignee == "me" else (assignee or None), bool(overdue), bool(risk_expiring),
                        today=finding_svc.today())


@dataclass
class VulnFilters:
    q: str | None = None
    host: str | None = None
    cve: str | None = None
    criticality: str | None = None
    zone: str | None = None
    os: str | None = None
    level: str | None = None
    exploits: bool | None = None
    msf: bool | None = None
    cvss_source: str | None = None
    host_id: int | None = None
    #: По умолчанию — все статусы: обзор и карточка хоста считают все пары.
    status: StatusFilter = field(default_factory=StatusFilter)

    def data_empty(self) -> bool:
        """Нет фильтров по данным пары (статус не в счёт)."""
        return all(getattr(self, f.name) is None for f in fields(self) if f.name != "status")


def level_expr() -> ColumnElement[str]:
    return case(
        (VmHostCve.risk >= 70, "critical"),
        (VmHostCve.risk >= 40, "high"),
        (VmHostCve.risk >= 20, "medium"),
        else_="low",
    )


def _overdue(today: dt.date) -> ColumnElement[bool]:
    return and_(ST.c.status.in_(sorted(OPEN)), ST.c.due_date < today)


def _expiring(today: dt.date) -> ColumnElement[bool]:
    return and_(ST.c.status == "risk_accepted",
                ST.c.risk_until <= today + dt.timedelta(days=finding_svc.RISK_EXPIRING_DAYS))


def status_conditions(sf: StatusFilter) -> list[ColumnElement[bool]]:
    """Условия на присоединённые строки состояния (`base_select(state=True)`)."""
    conds: list[ColumnElement[bool]] = []
    if sf.statuses is not None:
        listed = ST.c.status.in_(sorted(sf.statuses))
        conds.append(or_(ST.c.status.is_(None), listed) if "new" in sf.statuses else listed)
    if sf.assignee == "none":
        conds.append(ST.c.assignee.is_(None))
    elif sf.assignee:
        conds.append(ST.c.assignee == sf.assignee)
    if sf.overdue:
        conds.append(_overdue(sf.day()))
    if sf.risk_expiring:
        conds.append(_expiring(sf.day()))
    return conds


def conditions(f: VulnFilters, *, with_status: bool = True) -> list[ColumnElement[bool]]:
    conds: list[ColumnElement[bool]] = status_conditions(f.status) if with_status else []
    if f.q:
        # Подстрока по хосту ищется среди хостов (их тысячи), а не по
        # миллионам пар; CVE — по префиксу, чтобы работал индекс. OR по двум
        # индексированным колонкам пар Postgres собирает через BitmapOr.
        needle = f"%{f.q.strip()}%"
        hosts = select(VmHost.id).where(or_(VmHost.hostname.ilike(needle), VmHost.ip.ilike(needle)))
        conds.append(or_(VmHostCve.host_id.in_(hosts), VmHostCve.cve_id.like(f"{f.q.strip().upper()}%")))
    if f.host:
        conds.append(or_(VmHost.hostname.ilike(f"%{f.host}%"), VmHost.ip.ilike(f"%{f.host}%")))
    if f.cve:
        conds.append(VmHostCve.cve_id == f.cve.strip().upper())
    if f.criticality is not None:
        conds.append(VmHost.criticality == f.criticality)
    if f.zone is not None:
        conds.append(VmHost.zone == f.zone)
    if f.os:
        conds.append(VmHost.os_name == f.os)
    if f.level in LEVEL_BOUNDS:
        lo, hi = LEVEL_BOUNDS[f.level]
        conds.append(VmHostCve.risk.between(lo, hi))
    if f.exploits is not None:
        conds.append(VmCve.exploits_count > 0 if f.exploits else VmCve.exploits_count == 0)
    if f.msf is not None:
        conds.append(VmCve.msf_modules > 0 if f.msf else VmCve.msf_modules == 0)
    if f.cvss_source:
        conds.append(VmCve.cvss_source == f.cvss_source)
    if f.host_id is not None:
        conds.append(VmHostCve.host_id == f.host_id)
    return conds


def base_select(columns: list[Any], *, state: bool = False) -> Select[Any]:
    """`state` — присоединить строки состояния (`ST`): нужны условиям статуса и полям строки списка."""
    stmt = (
        select(*columns)
        .select_from(VmHostCve)
        .join(VmHost, VmHost.id == VmHostCve.host_id)
        .join(VmCve, VmCve.cve_id == VmHostCve.cve_id)
    )
    if state:
        stmt = stmt.outerjoin(ST, and_(ST.c.host_id == VmHostCve.host_id, ST.c.cve_id == VmHostCve.cve_id))
    return stmt


ROW_COLUMNS = [
    VmHostCve.host_id,
    VmHost.hostname,
    VmHost.ip,
    VmHost.os_name,
    VmHost.criticality,
    VmHost.zone,
    VmHostCve.cve_id,
    VmHostCve.risk,
    VmHostCve.risk_raw,
    VmCve.cvss,
    VmCve.cvss_source,
    VmCve.epss,
    VmCve.exploitdb_type,
    VmCve.exploits_count,
    VmCve.msf_rank,
    VmCve.msf_modules,
]


STATE_COLUMNS = [
    ST.c.status.label("st_status"),
    ST.c.assignee.label("st_assignee"),
    ST.c.due_date.label("st_due_date"),
    ST.c.risk_until.label("st_risk_until"),
    ST.c.first_seen_at.label("st_first_seen_at"),
]


def level_of(risk: int) -> str:
    return next(k for k, (lo, hi) in LEVEL_BOUNDS.items() if lo <= risk <= hi)


def row_to_item(row: Any) -> dict[str, Any]:
    risk = int(row.risk)
    return {
        "key": pair_key(row.hostname, row.ip, row.cve_id),
        "host_id": row.host_id,
        "hostname": row.hostname,
        "ip": row.ip,
        "os_name": row.os_name,
        "criticality": row.criticality,
        "zone": row.zone,
        "cve_id": row.cve_id,
        "risk": risk,
        "risk_raw": float(row.risk_raw),
        "level": level_of(risk),
        "cvss": row.cvss,
        "cvss_source": row.cvss_source,
        "epss": row.epss,
        "exploitdb_type": row.exploitdb_type,
        "exploits_count": row.exploits_count,
        "msf_rank": row.msf_rank,
        "msf_modules": row.msf_modules,
    }


def item_with_state(row: Any, today: dt.date) -> dict[str, Any]:
    """Строка списка и экспорта: пара и поля её статуса (спека §5). Возраста у пар VM нет —
    модуль не хранит истории импортов по парам; `first_seen_at` — из строки состояния, если есть."""
    status = row.st_status or "new"
    return {
        **row_to_item(row),
        "status": status,
        "status_title": STATUS_TITLES[status],
        "assignee": row.st_assignee,
        "due_date": row.st_due_date.isoformat() if row.st_due_date else None,
        "overdue": is_overdue(status, row.st_due_date, today),
        "risk_until": row.st_risk_until.isoformat() if row.st_risk_until else None,
        "first_seen_at": row.st_first_seen_at.isoformat() if row.st_first_seen_at else None,
    }


def page_items(db: Session, f: VulnFilters, sort: str, limit: int, offset: int) -> list[dict[str, Any]]:
    order = SORTS.get(sort, SORTS["risk_desc"])
    rows = db.execute(
        base_select(ROW_COLUMNS + STATE_COLUMNS, state=True).where(*conditions(f)).order_by(*order).limit(limit).offset(offset)
    ).all()
    today = f.status.day()
    return [item_with_state(r, today) for r in rows]


def count(db: Session, f: VulnFilters) -> int:
    return int(db.execute(base_select([func.count()], state=not f.status.is_noop()).where(*conditions(f))).scalar() or 0)


def page(db: Session, f: VulnFilters, sort: str, limit: int, offset: int) -> tuple[int, list[dict[str, Any]]]:
    return count(db, f), page_items(db, f, sort, limit, offset)


def _counts(db: Session, expr: Any, conds: list[ColumnElement[bool]], state: bool, limit: int | None = None) -> dict[str, int]:
    stmt = base_select([expr, func.count()], state=state).where(*conds).group_by(expr).order_by(func.count().desc())
    if limit:
        stmt = stmt.limit(limit)
    return {str(k if k is not None else ""): int(n) for k, n in db.execute(stmt).all()}


FACET_EXPRS: dict[str, Any] = {
    "level": level_expr(),
    "criticality": VmHost.criticality,
    "zone": VmHost.zone,
    "os": VmHost.os_name,
    "exploits": case((VmCve.exploits_count > 0, "yes"), else_="no"),
    "msf": case((VmCve.msf_modules > 0, "yes"), else_="no"),
    "cvss_source": VmCve.cvss_source,
}


def _facets_one_pass(db: Session, conds: list[ColumnElement[bool]], state: bool) -> dict[str, dict[str, int]]:
    """Postgres: все фасеты одним GROUPING SETS — один проход по парам
    вместо семи. Какой набор дал строку, говорит GROUPING()."""
    names = list(FACET_EXPRS)
    cols = [FACET_EXPRS[n].label(f"f_{n}") for n in names]
    grouping = func.grouping(*cols).label("g")
    stmt = (
        base_select([*cols, grouping, func.count().label("n")], state=state)
        .where(*conds)
        .group_by(func.grouping_sets(*[tuple_(c) for c in cols]))
    )
    out: dict[str, dict[str, int]] = {n: {} for n in names}
    width = len(names)
    for row in db.execute(stmt).all():
        mask = int(row.g)
        for i, name in enumerate(names):
            if not (mask >> (width - 1 - i)) & 1:
                key = getattr(row, f"f_{name}")
                out[name][str(key if key is not None else "")] = int(row.n)
                break
    return out


def facets_where(db: Session, conds: list[ColumnElement[bool]], *, state: bool) -> dict[str, dict[str, int]]:
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        raw = _facets_one_pass(db, conds, state)
        top_os = dict(sorted(raw["os"].items(), key=lambda kv: kv[1], reverse=True)[:20])
        levels = raw["level"]
        return {**raw, "level": {lvl: levels.get(lvl, 0) for lvl in LEVELS}, "os": top_os}
    levels = _counts(db, FACET_EXPRS["level"], conds, state)
    return {
        "level": {lvl: levels.get(lvl, 0) for lvl in LEVELS},
        "criticality": _counts(db, FACET_EXPRS["criticality"], conds, state),
        "zone": _counts(db, FACET_EXPRS["zone"], conds, state),
        "os": _counts(db, FACET_EXPRS["os"], conds, state, limit=20),
        "exploits": _counts(db, FACET_EXPRS["exploits"], conds, state),
        "msf": _counts(db, FACET_EXPRS["msf"], conds, state),
        "cvss_source": _counts(db, FACET_EXPRS["cvss_source"], conds, state),
    }


def facets(db: Session, f: VulnFilters) -> dict[str, dict[str, int]]:
    return facets_where(db, conditions(f), state=not f.status.is_noop())


def _minus(whole: dict[str, dict[str, int]], part: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for name, counts in whole.items():
        sub = part.get(name, {})
        left = {k: n - sub.get(k, 0) for k, n in counts.items()}
        out[name] = left if name == "level" else {k: n for k, n in left.items() if n > 0}
    return out


def data_facets(db: Session, f: VulnFilters, cached: dict[str, Any] | None) -> dict[str, dict[str, int]]:
    """Фасеты по данным пар. Без фильтров по данным и при статусном фильтре, который пропускает
    пары без решений (по умолчанию — открытые), — из кэша пересчёта (`vm.stats`, все пары) за
    вычетом пар с решением, не прошедших фильтр: их единицы, и проход по всем парам не нужен."""
    if not (cached and "criticality" in cached and f.data_empty() and f.status.keeps_undecided()):
        return facets(db, f)
    sc = status_conditions(f.status)
    if not sc:
        return {name: dict(counts) for name, counts in cached.items()}
    excluded = facets_where(db, [ST.c.host_id.is_not(None), not_(and_(*sc))], state=True)
    return _minus(cached, excluded)


def _passes(sf: StatusFilter, status: str, assignee: str | None, overdue: bool, expiring: bool, *skip: str) -> bool:
    if "status" not in skip and sf.statuses is not None and status not in sf.statuses:
        return False
    if "assignee" not in skip and sf.assignee and assignee != (None if sf.assignee == "none" else sf.assignee):
        return False
    if "overdue" not in skip and sf.overdue and not overdue:
        return False
    return not ("risk_expiring" not in skip and sf.risk_expiring and not expiring)


def status_facets(db: Session, f: VulnFilters, total_all: int | None) -> dict[str, dict[str, int]]:
    """Фасеты статуса, исполнителя и сроков — каждый без своего фильтра, с остальными (как у
    AD/KSC); флаги сроков — ещё и без фильтра статуса: «риск истекает» бывает только у
    принятых, «просроченные» — только у открытых, и по умолчанию (открытые) первый был бы 0. Пары сгруппированы по (статус, исполнитель, просрочка, риск истекает): групп
    немного, фильтры применяются к группам. Без фильтров по данным и при известном числе всех
    пар (`total_all`) группы берутся по строкам состояния, а пары без строки — разностью."""
    today = f.status.day()
    flags = [
        ST.c.status.label("status"),
        ST.c.assignee.label("assignee"),
        case((_overdue(today), True), else_=False).label("overdue"),
        case((_expiring(today), True), else_=False).label("expiring"),
    ]
    by_rows = f.data_empty() and total_all is not None
    where = [ST.c.host_id.is_not(None)] if by_rows else conditions(f, with_status=False)
    inner = base_select(flags, state=True).where(*where).subquery("groups")
    cols = [inner.c.status, inner.c.assignee, inner.c.overdue, inner.c.expiring]
    groups = [(r[0] or "new", r[1], bool(r[2]), bool(r[3]), int(r[4]))
              for r in db.execute(select(*cols, func.count()).group_by(*cols))]
    if by_rows:
        assert total_all is not None
        groups.append(("new", None, False, False, max(total_all - sum(g[4] for g in groups), 0)))
    out: dict[str, dict[str, int]] = {
        "status": dict.fromkeys(STATUSES, 0), "assignee": {"none": 0}, "flags": {"overdue": 0, "risk_expiring": 0},
    }
    sf = f.status
    for status, assignee, overdue, expiring, n in groups:
        if _passes(sf, status, assignee, overdue, expiring, "status"):
            out["status"][status] += n
        if _passes(sf, status, assignee, overdue, expiring, "assignee"):
            who = assignee or "none"
            out["assignee"][who] = out["assignee"].get(who, 0) + n
        if overdue and _passes(sf, status, assignee, overdue, expiring, "overdue", "status"):
            out["flags"]["overdue"] += n
        if expiring and _passes(sf, status, assignee, overdue, expiring, "risk_expiring", "status"):
            out["flags"]["risk_expiring"] += n
    out["assignee"] = {k: n for k, n in out["assignee"].items() if n or k == "none"}
    return out


def iter_rows(db: Session, f: VulnFilters, sort: str, chunk: int = 5000) -> Any:
    """Для экспорта: серверный курсор, а не страницы по offset — иначе
    каждая страница заново сортирует миллионы строк."""
    conds = conditions(f)
    order = SORTS.get(sort, SORTS["risk_desc"])
    stmt = base_select(ROW_COLUMNS + STATE_COLUMNS, state=True).where(*conds).order_by(*order).execution_options(yield_per=chunk)
    yield from db.execute(stmt)


def iter_keys(db: Session, f: VulnFilters, chunk: int) -> Iterator[str]:
    """Ключи пар по фильтру — кусками по `chunk` с продолжением по первичному ключу пары, а не
    по offset и не курсором: между кусками вызывающий фиксирует транзакцию (массовая смена
    статусов), и пары, ушедшие из фильтра после смены, не сдвигают следующие."""
    conds = conditions(f)
    state = not f.status.is_noop()
    cols = [VmHostCve.host_id, VmHostCve.cve_id, VmHost.hostname, VmHost.ip]
    last: tuple[int, str] | None = None
    while True:
        stmt = base_select(cols, state=state).where(*conds)
        if last is not None:
            stmt = stmt.where(tuple_(VmHostCve.host_id, VmHostCve.cve_id) > tuple_(literal(last[0]), literal(last[1])))
        rows = db.execute(stmt.order_by(VmHostCve.host_id, VmHostCve.cve_id).limit(chunk)).all()
        if not rows:
            return
        yield from (pair_key(r.hostname, r.ip, r.cve_id) for r in rows)
        last = (rows[-1].host_id, rows[-1].cve_id)
