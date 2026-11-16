"""Таблица пар, карточка расчёта, хост, экспорт."""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.vm.core.priority import AssetContext, priority_score
from api.modules.vm.core.refs import REF_NAMES
from api.modules.vm.models import (
    VmCve,
    VmHost,
    VmHostCve,
    VmRefExploitdb,
    VmRefExploitdbCve,
    VmRefMsf,
    VmRefMsfCve,
    VmRefState,
    VmZone,
)
from api.modules.vm.services.query import (
    ROW_COLUMNS,
    SORTS,
    VulnFilters,
    base_select,
    data_facets,
    item_with_state,
    iter_rows,
    page_items,
    row_to_item,
    status_facets,
    status_filter,
)
from api.modules.vm.services.risk_view import cve_inputs, risk_view
from api.modules.vm.services.settings import load_settings
from api.modules.vm.services.stats import load_stats
from api.platform.export import Column, export_response
from api.platform.filters import QueryList, QueryStatus, multi

router = APIRouter(tags=["vm"])

MAX_LIMIT = 1000


def _filters(
    q: str | None = None,
    host: str | None = None,
    cve: str | None = None,
    criticality: QueryList = None,
    zone: QueryList = None,
    os: QueryList = None,
    level: QueryList = None,
    exploits: bool | None = None,
    msf: bool | None = None,
    kev: bool | None = None,
    cvss_source: QueryList = None,
    host_id: int | None = None,
    status_: QueryStatus = None,
    assignee: QueryList = None,
    overdue: bool = False,
    risk_expiring: bool = False,
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> VulnFilters:
    """Статус пары: `status` — коды повтором ключа (только он — ещё и через запятую) или `all`, по умолчанию — открытые;
    `assignee` — `me`, `none` или логин; `overdue`, `risk_expiring` (спека статусов §5).
    Фасеты `level, criticality, zone, cvss_source, os, assignee` — повтором ключа."""
    try:
        sf = status_filter(status_, assignee, overdue, risk_expiring, login=user.login)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from None
    # Пороги уровней — из настроек, один раз на запрос: `level` в фильтре и в строках по ним.
    return VulnFilters(q, host, cve, multi(criticality), multi(zone), multi(os), multi(level), exploits, msf, kev,
                       multi(cvss_source), host_id, sf, load_settings(db).weights.levels)


def _with_names(db: Session, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Имя исполнителя — одним запросом на страницу."""
    logins = {i["assignee"] for i in items if i["assignee"]}
    names = {u.login: u.display_name or u.login for u in db.scalars(select(AppUser).where(AppUser.login.in_(logins)))} if logins else {}
    for i in items:
        i["assignee_name"] = names.get(i["assignee"], i["assignee"]) if i["assignee"] else None
    return items


class VulnsResponse(BaseModel):
    #: Только у первой страницы (`offset=0`), как и фасеты.
    total: int | None
    items: list[dict[str, Any]]
    facets: dict[str, dict[str, int]] | None = None


@router.get("/vulns", response_model=VulnsResponse)
def list_vulns(
    f: VulnFilters = Depends(_filters),
    sort: str = Query(default="risk_desc"),
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> VulnsResponse:
    if sort not in SORTS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="неизвестная сортировка")
    # Фасеты и total только с первой страницей: при прокрутке они не меняются,
    # а считать их на каждую догрузку — лишняя работа на миллионах строк
    # (count по миллионам пар — секунда на каждой следующей странице).
    # Без фильтров они берутся из кэша пересчёта, total — сумма по шкале:
    # отдельный count по миллионам пар не нужен.
    if offset > 0:
        return VulnsResponse(total=None, items=_with_names(db, page_items(db, f, sort, limit, offset)), facets=None)
    # Статусы: по умолчанию показываются открытые; кэш годится, пока фильтр статуса пропускает
    # пары без решений, — из него вычитаются пары с решением, не прошедшие фильтр (`data_facets`).
    cached = load_stats(db).get("facets") if f.data_empty() else None
    fac = data_facets(db, f, cached)
    total_all = sum(cached["risk"].values()) if cached and "risk" in cached else None
    fac.update(status_facets(db, f, total_all))
    return VulnsResponse(total=sum(fac["level"].values()), items=_with_names(db, page_items(db, f, sort, limit, 0)), facets=fac)


@router.get("/vulns/{host_id}/{cve_id}")
def risk_card(
    host_id: int,
    cve_id: str,
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    pair = db.get(VmHostCve, (host_id, cve_id.upper()))
    if pair is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="пара хост–CVE не найдена")
    host = db.get(VmHost, host_id)
    cve = db.get(VmCve, pair.cve_id)
    assert host is not None and cve is not None
    zone = db.get(VmZone, host.zone) if host.zone else None
    settings = load_settings(db)
    refs = {s.name: s.loaded_at for s in db.execute(select(VmRefState)).scalars()}
    inputs = cve_inputs(cve, kev_loaded="kev" in refs)
    marked = bool(zone and zone.marked)
    e = priority_score(inputs, AssetContext(host.criticality or None,
                       zone.internet_access if marked else None,
                       zone.confidential_data if marked else None))
    exploits = db.execute(
        select(VmRefExploitdb.exploit_id, VmRefExploitdb.type, VmRefExploitdb.verified, VmRefExploitdb.published)
        .join(VmRefExploitdbCve, VmRefExploitdbCve.exploit_id == VmRefExploitdb.exploit_id)
        .where(VmRefExploitdbCve.cve_id == pair.cve_id)
        .order_by(VmRefExploitdb.published.desc().nulls_last())
        .limit(20)
    ).all()
    modules = db.execute(
        select(VmRefMsf.fullname, VmRefMsf.name, VmRefMsf.rank)
        .join(VmRefMsfCve, VmRefMsfCve.fullname == VmRefMsf.fullname)
        .where(VmRefMsfCve.cve_id == pair.cve_id)
        .order_by(VmRefMsf.rank.desc())
        .limit(20)
    ).all()
    return {
        "host": {
            "id": host.id,
            "hostname": host.hostname,
            "ip": host.ip,
            "os_name": host.os_name,
            "groups": host.groups,
            "criticality": host.criticality,
            "zone": host.zone,
            "zone_marked": bool(zone and zone.marked),
            "internet_access": bool(zone and zone.internet_access),
            "confidential_data": bool(zone and zone.confidential_data),
        },
        "cve": {
            "cve_id": cve.cve_id,
            "description": cve.description,
            "published": cve.published.isoformat() if cve.published else None,
            "cvss": cve.cvss,
            "cvss_source": cve.cvss_source,
            "epss": cve.epss,
            "epss_percentile": cve.epss_percentile,
            # KEV: факт эксплуатации; дата, вымогатели и срок CISA — для человека, в балл не входят.
            "kev": cve.kev,
            "kev_added": cve.kev_added.isoformat() if cve.kev_added else None,
            "kev_ransomware": cve.kev_ransomware,
            "kev_due": cve.kev_due.isoformat() if cve.kev_due else None,
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}",
            "exploits": [
                {"exploit_id": r.exploit_id, "type": r.type, "verified": r.verified, "published": r.published.isoformat() if r.published else None}
                for r in exploits
            ],
            "msf_modules": [{"fullname": r.fullname, "name": r.name, "rank": r.rank} for r in modules],
        },
        "risk": risk_view(e, settings, pair.risk, pair.risk_raw),
        # Все справочники, в том числе незагруженные (null): карточка показывает и KEV.
        "refs_loaded_at": {n: (refs[n].isoformat() if refs.get(n) else None) for n in REF_NAMES},
    }


@router.get("/hosts/{host_id}")
def host_detail(host_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    host = db.get(VmHost, host_id)
    if host is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="хост не найден")
    levels = load_settings(db).weights.levels
    rows = db.execute(
        base_select(ROW_COLUMNS).where(VmHostCve.host_id == host_id).order_by(VmHostCve.risk.desc(), VmHostCve.cve_id).limit(500)
    ).all()
    return {
        "host": {
            "id": host.id,
            "hostname": host.hostname,
            "ip": host.ip,
            "os_name": host.os_name,
            "groups": host.groups,
            "criticality": host.criticality,
            "zone": host.zone,
        },
        "items": [row_to_item(r, levels) for r in rows],
    }


EXPORT_COLUMNS = [
    Column("risk", "Риск"),
    Column("level", "Уровень"),
    Column("hostname", "Хост"),
    Column("ip", "IP"),
    Column("cve_id", "CVE"),
    Column("cvss", "CVSS"),
    Column("cvss_source", "Источник CVSS"),
    Column("epss", "EPSS"),
    Column("exploitdb_type", "Эксплойт"),
    Column("exploits_count", "Эксплойтов"),
    Column("msf_rank", "Metasploit"),
    Column("criticality", "Критичность"),
    Column("zone", "Зона"),
    Column("os_name", "ОС"),
    Column("risk_raw", "Риск (сырой)"),
    Column("kev", "KEV"),
    Column("status_title", "Статус"),
    Column("assignee", "Исполнитель"),
    Column("due_date", "Срок"),
]


@router.get("/export")
def export_csv(
    f: VulnFilters = Depends(_filters),
    sort: str = Query(default="risk_desc"),
    fmt: str = Query(default="csv", alias="format"),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """CSV (по умолчанию) или XLSX — api/platform/export.py. Фильтры — как у списка, по умолчанию
    открытые пары; последние колонки — статус, исполнитель, срок. Строки (имя хоста, ОС, зона — из
    выгрузки MaxPatrol) в CSV проходят `csv_safe` (аудит L2)."""

    def rows() -> Iterator[dict[str, Any]]:
        today = f.status.day()
        for row in iter_rows(db, f, sort):
            item = item_with_state(row, today, f.levels)
            # Признак в таблице читают глазами: «да» у KEV и пустая ячейка у остальных, а не True/False.
            item["kev"] = "да" if item["kev"] else ""
            yield item

    return export_response(fmt, EXPORT_COLUMNS, rows(), module="vm", name="vulns")
