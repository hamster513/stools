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
)
from api.modules.vm.services.settings import load_settings
from api.modules.vm.services.stats import load_stats
from api.platform.findings import service as finding_svc

router = APIRouter(prefix="/overview", tags=["vm"])


@router.get("")
def overview(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    settings = load_settings(db)
    hosts = int(db.execute(select(func.count()).select_from(VmHost)).scalar() or 0)
    pairs_all = int(db.execute(select(func.count()).select_from(VmHostCve)).scalar() or 0)
    cves = int(db.execute(select(func.count()).select_from(VmCve)).scalar() or 0)
    # Распределение и топы — из кэша, обновляемого после каждого пересчёта.
    stats = load_stats(db)
    # Пары, распределение и «выше порога» — по учитываемым статусам (настройка платформы
    # `counted`): принятый риск по умолчанию не считается. Топы — по всем парам, из кэша.
    counted = VulnFilters(status=StatusFilter(statuses=finding_svc.counted_statuses(db)))
    distribution = data_facets(db, counted, stats.get("facets"))["level"]
    above = int(
        db.execute(
            base_select([func.count()], state=True).where(VmHostCve.risk >= settings.threshold, *status_conditions(counted.status))
        ).scalar() or 0
    )

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
    unmarked = int(db.execute(select(func.count()).select_from(VmZone).where(VmZone.marked.is_(False))).scalar() or 0)
    no_epss = int(db.execute(select(func.count()).select_from(VmCve).where(VmCve.epss.is_(None))).scalar() or 0)
    no_nvd = int(db.execute(select(func.count()).select_from(VmCve).where(VmCve.cvss_source == "none")).scalar() or 0)

    return {
        "hosts": hosts,
        "pairs": sum(distribution.values()),
        "pairs_all": pairs_all,
        "cves": cves,
        "above_threshold": above,
        "threshold": settings.threshold,
        "distribution": distribution,
        # Плитки ведут в список, а он показывает только пары текущих данных.
        "findings": finding_svc.summary(db, MODULE, SCOPE, keys_present=pairs_all, present_only=True),
        "top_cves": stats["top_cves"],
        "top_hosts": stats["top_hosts"],
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
