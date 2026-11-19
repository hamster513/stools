"""Обзор: числа, распределение, топы и проблемные области данных."""
from __future__ import annotations

import datetime as dt
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.vm.core.refs import REF_NAMES
from api.modules.vm.models import VmCve, VmHost, VmHostCve, VmImport, VmRefState, VmZone
from api.modules.vm.services.query import (
    MODULE,
    SCOPE,
    StatusFilter,
    VulnFilters,
    base_select,
    data_facets,
    status_conditions,
    status_facets,
)
from api.modules.vm.services.settings import load_settings
from api.modules.vm.services.stats import high_risk_stats, load_stats
from api.platform.findings import service as finding_svc
from api.platform.findings.core import OPEN

router = APIRouter(prefix="/overview", tags=["vm"])


@router.get("")
def overview(hide_medium_low: bool = False, db: Session = Depends(get_db),
             _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    settings = load_settings(db)
    levels = settings.weights.levels
    counted_statuses = finding_svc.counted_statuses(db)
    counted = StatusFilter(statuses=counted_statuses)
    stats = load_stats(db)
    if hide_medium_low:
        scoped = stats.get("high_risk")
        if scoped is None or scoped.get("minimum") != levels.high:
            # Старый кэш используется до очередного пересчёта; выборку читаем из текущих пар.
            scoped = high_risk_stats(db, levels.high)
        hosts, pairs_all, cves = scoped["hosts"], scoped["pairs_all"], scoped["cves"]
        no_epss, no_nvd, unmarked = scoped["cves_without_epss"], scoped["cves_without_nvd"], scoped["unmarked_zones"]
        counted_pairs, critical, above, kev = db.execute(base_select([
            func.count(), func.count().filter(VmHostCve.risk >= levels.critical),
            func.count().filter(VmHostCve.risk >= settings.threshold), func.count().filter(VmCve.kev.is_(True)),
        ], state=True).where(VmHostCve.risk >= levels.high, *status_conditions(counted))).one()
        distribution = {"low": 0, "medium": 0, "high": counted_pairs - critical, "critical": critical}
        # Фасет статуса считает все статусы, а «без исполнителя» — только открытые пары.
        facets = status_facets(db, VulnFilters(min_risk=levels.high, status=StatusFilter(statuses=OPEN)), None)
        findings = {"by_status": facets["status"], "unassigned": facets["assignee"]["none"], **facets["flags"]}
    else:
        scoped = stats
        hosts = db.scalar(select(func.count()).select_from(VmHost))
        pairs_all = db.scalar(select(func.count()).select_from(VmHostCve))
        cves, no_epss, no_nvd = db.execute(select(
            func.count(), func.count().filter(VmCve.epss.is_(None)), func.count().filter(VmCve.cvss_source == "none")
        ).select_from(VmCve)).one()
        unmarked = db.scalar(select(func.count()).select_from(VmZone).where(VmZone.marked.is_(False)))
        counted_facets = data_facets(db, VulnFilters(status=counted, levels=levels), stats.get("facets"))
        distribution = counted_facets["level"]
        kev = counted_facets["kev"].get("yes", 0)
        above = db.scalar(base_select([func.count()], state=True).where(
            VmHostCve.risk >= settings.threshold, *status_conditions(counted)))
        findings = finding_svc.summary(db, MODULE, SCOPE, keys_present=pairs_all, present_only=True)

    last_import = db.execute(select(VmImport).order_by(VmImport.id.desc())).scalars().first()
    states = {s.name: s for s in db.execute(select(VmRefState)).scalars()}
    now = dt.datetime.now(dt.UTC)
    refs = []
    for name in REF_NAMES:
        s = states.get(name)
        loaded = s.loaded_at if s else None
        if loaded is not None and loaded.tzinfo is None:
            loaded = loaded.replace(tzinfo=dt.UTC)
        refs.append(
            {
                "name": name,
                "loaded_at": loaded.isoformat() if loaded else None,
                "records": s.records if s else 0,
                "stale": loaded is None or (now - loaded) > dt.timedelta(days=30),
            }
        )
    return {
        "hosts": hosts,
        "pairs": sum(distribution.values()),
        "pairs_all": pairs_all,
        "cves": cves,
        "above_threshold": above,
        "threshold": settings.threshold,
        "levels": levels.model_dump(),
        "counted_statuses": sorted(counted_statuses),
        "distribution": distribution,
        "kev_pairs": kev,
        "findings": findings,
        "top_cves": scoped["top_cves"],
        "top_hosts": scoped["top_hosts"],
        "data": {
            "last_import": {
                "finished_at": last_import.finished_at.isoformat(),
                "source": last_import.source,
                "filename": last_import.filename,
                "hosts": last_import.hosts,
                "pairs": last_import.pairs,
                "cves": last_import.cves,
            }
            if last_import
            else None,
            "refs": refs,
            "unmarked_zones": unmarked,
            "cves_without_epss": no_epss,
            "cves_without_nvd": no_nvd,
        },
    }
