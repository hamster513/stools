"""Выборка пар хост–CVE: фильтры, фасеты, сортировки (спека §8).

Один запрос собирает и страницу, и фасеты; фасеты считаются по всей
выборке с теми же фильтрами, а не по загруженной странице — иначе
счётчики менялись бы при прокрутке.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import Select, case, func, or_, select, tuple_
from sqlalchemy.orm import Session
from sqlalchemy.sql import ColumnElement

from api.modules.vm.models import VmCve, VmHost, VmHostCve

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

    def is_empty(self) -> bool:
        return all(v is None for v in self.__dict__.values())


def level_expr() -> ColumnElement[str]:
    return case(
        (VmHostCve.risk >= 70, "critical"),
        (VmHostCve.risk >= 40, "high"),
        (VmHostCve.risk >= 20, "medium"),
        else_="low",
    )


def conditions(f: VulnFilters) -> list[ColumnElement[bool]]:
    conds: list[ColumnElement[bool]] = []
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


def base_select(columns: list[Any]) -> Select[Any]:
    return (
        select(*columns)
        .select_from(VmHostCve)
        .join(VmHost, VmHost.id == VmHostCve.host_id)
        .join(VmCve, VmCve.cve_id == VmHostCve.cve_id)
    )


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


def row_to_item(row: Any) -> dict[str, Any]:
    risk = int(row.risk)
    return {
        "host_id": row.host_id,
        "hostname": row.hostname,
        "ip": row.ip,
        "os_name": row.os_name,
        "criticality": row.criticality,
        "zone": row.zone,
        "cve_id": row.cve_id,
        "risk": risk,
        "risk_raw": float(row.risk_raw),
        "level": next(k for k, (lo, hi) in LEVEL_BOUNDS.items() if lo <= risk <= hi),
        "cvss": row.cvss,
        "cvss_source": row.cvss_source,
        "epss": row.epss,
        "exploitdb_type": row.exploitdb_type,
        "exploits_count": row.exploits_count,
        "msf_rank": row.msf_rank,
        "msf_modules": row.msf_modules,
    }


def page_items(db: Session, f: VulnFilters, sort: str, limit: int, offset: int) -> list[dict[str, Any]]:
    order = SORTS.get(sort, SORTS["risk_desc"])
    rows = db.execute(base_select(ROW_COLUMNS).where(*conditions(f)).order_by(*order).limit(limit).offset(offset)).all()
    return [row_to_item(r) for r in rows]


def count(db: Session, f: VulnFilters) -> int:
    return int(db.execute(base_select([func.count()]).where(*conditions(f))).scalar() or 0)


def page(db: Session, f: VulnFilters, sort: str, limit: int, offset: int) -> tuple[int, list[dict[str, Any]]]:
    return count(db, f), page_items(db, f, sort, limit, offset)


def _counts(db: Session, expr: Any, conds: list[ColumnElement[bool]], limit: int | None = None) -> dict[str, int]:
    stmt = base_select([expr, func.count()]).where(*conds).group_by(expr).order_by(func.count().desc())
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


def _facets_one_pass(db: Session, conds: list[ColumnElement[bool]]) -> dict[str, dict[str, int]]:
    """Postgres: все фасеты одним GROUPING SETS — один проход по парам
    вместо семи. Какой набор дал строку, говорит GROUPING()."""
    names = list(FACET_EXPRS)
    cols = [FACET_EXPRS[n].label(f"f_{n}") for n in names]
    grouping = func.grouping(*cols).label("g")
    stmt = (
        base_select([*cols, grouping, func.count().label("n")])
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


def facets(db: Session, f: VulnFilters) -> dict[str, dict[str, int]]:
    conds = conditions(f)
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        raw = _facets_one_pass(db, conds)
        top_os = dict(sorted(raw["os"].items(), key=lambda kv: kv[1], reverse=True)[:20])
        levels = raw["level"]
        return {**raw, "level": {lvl: levels.get(lvl, 0) for lvl in LEVELS}, "os": top_os}
    levels = _counts(db, FACET_EXPRS["level"], conds)
    return {
        "level": {lvl: levels.get(lvl, 0) for lvl in LEVELS},
        "criticality": _counts(db, FACET_EXPRS["criticality"], conds),
        "zone": _counts(db, FACET_EXPRS["zone"], conds),
        "os": _counts(db, FACET_EXPRS["os"], conds, limit=20),
        "exploits": _counts(db, FACET_EXPRS["exploits"], conds),
        "msf": _counts(db, FACET_EXPRS["msf"], conds),
        "cvss_source": _counts(db, FACET_EXPRS["cvss_source"], conds),
    }


def iter_rows(db: Session, f: VulnFilters, sort: str, chunk: int = 5000) -> Any:
    """Для экспорта: серверный курсор, а не страницы по offset — иначе
    каждая страница заново сортирует миллионы строк."""
    conds = conditions(f)
    order = SORTS.get(sort, SORTS["risk_desc"])
    stmt = base_select(ROW_COLUMNS).where(*conds).order_by(*order).execution_options(yield_per=chunk)
    yield from db.execute(stmt)
