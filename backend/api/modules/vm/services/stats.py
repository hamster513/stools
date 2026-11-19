"""Кэш обзора: распределение и топы считаются после каждого пересчёта,
а не на каждый заход на экран — на 4,7 млн пар это шесть секунд.

Лежит в app_setting['vm.stats']; поменяться данные могут только через
rescore_pairs, который его и обновляет.
"""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.orm import Session

from api.db.models import AppSetting
from api.modules.vm.models import VmCve, VmHost, VmHostCve, VmZone
from api.modules.vm.services.query import VulnFilters, base_select, raw_facets
from api.modules.vm.services.settings import load_settings

STATS_KEY = "vm.stats"


def _rankings(db: Session, *scope: ColumnElement[bool]) -> dict[str, Any]:
    top_cves = db.execute(
        select(
            VmHostCve.cve_id,
            func.count().label("hosts"),
            func.sum(VmHostCve.risk).label("risk_sum"),
            func.max(VmHostCve.risk).label("risk_max"),
            VmCve.cvss,
            VmCve.epss,
            VmCve.exploitdb_type,
        )
        .join(VmCve, VmCve.cve_id == VmHostCve.cve_id)
        .where(*scope)
        .group_by(VmHostCve.cve_id, VmCve.cvss, VmCve.epss, VmCve.exploitdb_type)
        .order_by(func.sum(VmHostCve.risk).desc(), func.sum(VmHostCve.risk_raw).desc(), func.count().desc())
        .limit(10)
    ).all()
    top_hosts = db.execute(
        base_select(
            [
                VmHost.id,
                VmHost.hostname,
                VmHost.ip,
                VmHost.zone,
                VmHost.criticality,
                func.count().label("pairs"),
                func.sum(VmHostCve.risk).label("risk_sum"),
                func.max(VmHostCve.risk).label("risk_max"),
            ]
        )
        .where(*scope)
        .group_by(VmHost.id, VmHost.hostname, VmHost.ip, VmHost.zone, VmHost.criticality)
        .order_by(func.sum(VmHostCve.risk).desc())
        .limit(10)
    ).all()
    return {
        "top_cves": [
            {
                "cve_id": r.cve_id,
                "hosts": int(r.hosts),
                "risk_sum": int(r.risk_sum or 0),
                "risk_max": int(r.risk_max or 0),
                "cvss": r.cvss,
                "epss": r.epss,
                "exploitdb_type": r.exploitdb_type,
            }
            for r in top_cves
        ],
        "top_hosts": [
            {
                "host_id": r.id,
                "hostname": r.hostname,
                "ip": r.ip,
                "zone": r.zone,
                "criticality": r.criticality,
                "pairs": int(r.pairs),
                "risk_sum": int(r.risk_sum or 0),
                "risk_max": int(r.risk_max or 0),
            }
            for r in top_hosts
        ],
    }


def high_risk_stats(db: Session, minimum: int) -> dict[str, Any]:
    """Показатели по всем статусам. Сначала отбираем пары, затем считаем хосты, CVE и топы."""
    scope = VmHostCve.risk >= minimum
    distinct_cves = func.count(VmHostCve.cve_id.distinct())
    counts = db.execute(base_select([
        func.count().label("pairs_all"),
        func.count(VmHostCve.host_id.distinct()).label("hosts"),
        distinct_cves.label("cves"),
        distinct_cves.filter(VmCve.epss.is_(None)).label("cves_without_epss"),
        distinct_cves.filter(VmCve.cvss_source == "none").label("cves_without_nvd"),
        func.count(VmZone.name.distinct()).filter(VmZone.marked.is_(False)).label("unmarked_zones"),
    ]).outerjoin(VmZone, VmZone.name == VmHost.zone).where(scope)).mappings().one()
    return {"minimum": minimum, **counts, **_rankings(db, scope)}


def compute_stats(db: Session) -> dict[str, Any]:
    pairs = int(db.execute(select(func.count()).select_from(VmHostCve)).scalar() or 0)
    return {
        "pairs": pairs,
        # Гистограмма всех баллов нужна списку при любых границах уровней.
        "facets": raw_facets(db, VulnFilters()) if pairs else {},
        **_rankings(db),
        "high_risk": high_risk_stats(db, load_settings(db).weights.levels.high),
        "computed_at": dt.datetime.now(dt.UTC).isoformat(),
    }


def refresh_stats(db: Session) -> dict[str, Any]:
    stats = compute_stats(db)
    row = db.get(AppSetting, STATS_KEY)
    if row is None:
        row = AppSetting(key=STATS_KEY)
        db.add(row)
    row.value_json = json.dumps(stats, ensure_ascii=False)
    row.updated_at = dt.datetime.now(dt.UTC)
    db.commit()
    # Слой матрицы читает свой кэш и меняется ровно тогда же, когда обзор.
    from api.modules.vm.services.attack_layer import refresh as refresh_attack_layer

    refresh_attack_layer(db)
    return stats


def load_stats(db: Session) -> dict[str, Any]:
    row = db.get(AppSetting, STATS_KEY)
    if row is None or not row.value_json or row.value_json == "{}":
        return refresh_stats(db)
    return dict(json.loads(row.value_json))
