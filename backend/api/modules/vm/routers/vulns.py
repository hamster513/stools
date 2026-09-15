"""Таблица пар, карточка расчёта, хост, экспорт."""
from __future__ import annotations

import csv
import io
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
from api.modules.vm.core.risk import LEVEL_WORD, CveInputs, explain
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
    facets,
    iter_rows,
    page,
    page_items,
    row_to_item,
)
from api.modules.vm.services.settings import load_settings
from api.modules.vm.services.stats import load_stats

router = APIRouter(tags=["vm"])

MAX_LIMIT = 1000


def _filters(
    q: str | None = None,
    host: str | None = None,
    cve: str | None = None,
    criticality: str | None = None,
    zone: str | None = None,
    os: str | None = None,
    level: str | None = None,
    exploits: bool | None = None,
    msf: bool | None = None,
    cvss_source: str | None = None,
    host_id: int | None = None,
) -> VulnFilters:
    return VulnFilters(q, host, cve, criticality, zone, os, level, exploits, msf, cvss_source, host_id)


class VulnsResponse(BaseModel):
    total: int
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
    # Фасеты только с первой страницей: при прокрутке они не меняются,
    # а считать их на каждую догрузку — лишняя работа на миллионах строк.
    # Без фильтров они берутся из кэша пересчёта, total — сумма по шкале:
    # отдельный count по миллионам пар не нужен.
    if offset > 0:
        total, items = page(db, f, sort, limit, offset)
        return VulnsResponse(total=total, items=items, facets=None)
    cached = load_stats(db).get("facets") if f.is_empty() else None
    fac = cached if cached and "criticality" in cached else facets(db, f)
    return VulnsResponse(total=sum(fac["level"].values()), items=page_items(db, f, sort, limit, 0), facets=fac)


def _factor(fac: Any) -> dict[str, Any]:
    return {"value": fac.value, "source": fac.source, "substituted": fac.substituted}


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
    inputs = CveInputs(
        epss=cve.epss,
        cvss=cve.cvss,
        v3_av=cve.v3_av,
        v3_pr=cve.v3_pr,
        v3_ui=cve.v3_ui,
        v2_av=cve.v2_av,
        v2_ac=cve.v2_ac,
        v2_au=cve.v2_au,
        exploitdb_type=cve.exploitdb_type,
        msf_rank=cve.msf_rank,
    )
    e = explain(
        inputs,
        host.criticality or None,
        internet=bool(zone and zone.internet_access),
        confidential=bool(zone and zone.confidential_data),
        zone_marked=bool(zone and zone.marked),
        w=settings.weights,
    )
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
    refs = {s.name: s.loaded_at for s in db.execute(select(VmRefState)).scalars()}
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
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}",
            "exploits": [
                {"exploit_id": r.exploit_id, "type": r.type, "verified": r.verified, "published": r.published.isoformat() if r.published else None}
                for r in exploits
            ],
            "msf_modules": [{"fullname": r.fullname, "name": r.name, "rank": r.rank} for r in modules],
        },
        "risk": {
            "score": pair.risk,
            "raw": pair.risk_raw,
            "level": e.level,
            "level_word": LEVEL_WORD[e.level],
            "threshold": settings.threshold,
            "epss": _factor(e.epss),
            "cvss": _factor(e.cvss),
            "cve_param": _factor(e.cve_param),
            "exdb_param": _factor(e.exdb_param),
            "msf_param": _factor(e.msf_param),
            "impact": _factor(e.impact),
            "impact_parts": {k: _factor(v) for k, v in e.impact_parts.items()},
        },
        "refs_loaded_at": {k: (v.isoformat() if v else None) for k, v in refs.items()},
    }


@router.get("/hosts/{host_id}")
def host_detail(host_id: int, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    host = db.get(VmHost, host_id)
    if host is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="хост не найден")
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
        "items": [row_to_item(r) for r in rows],
    }


EXPORT_COLUMNS = [
    ("risk", "Риск"),
    ("level", "Уровень"),
    ("hostname", "Хост"),
    ("ip", "IP"),
    ("cve_id", "CVE"),
    ("cvss", "CVSS"),
    ("cvss_source", "Источник CVSS"),
    ("epss", "EPSS"),
    ("exploitdb_type", "Эксплойт"),
    ("exploits_count", "Эксплойтов"),
    ("msf_rank", "Metasploit"),
    ("criticality", "Критичность"),
    ("zone", "Зона"),
    ("os_name", "ОС"),
    ("risk_raw", "Риск (сырой)"),
]


@router.get("/export")
def export_csv(
    f: VulnFilters = Depends(_filters),
    sort: str = Query(default="risk_desc"),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """CSV с BOM и `;` — так его открывает Excel в русской локали без вопросов."""

    def gen() -> Iterator[bytes]:
        buf = io.StringIO()
        writer = csv.writer(buf, delimiter=";", lineterminator="\r\n")
        writer.writerow([title for _, title in EXPORT_COLUMNS])
        yield ("﻿" + buf.getvalue()).encode("utf-8")
        for row in iter_rows(db, f, sort):
            item = row_to_item(row)
            buf.seek(0)
            buf.truncate()
            writer.writerow([item.get(key, "") if item.get(key) is not None else "" for key, _ in EXPORT_COLUMNS])
            yield buf.getvalue().encode("utf-8")

    return StreamingResponse(
        gen(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="stools-vm-export.csv"'},
    )
