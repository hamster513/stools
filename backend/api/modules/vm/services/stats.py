"""Кэш обзора: распределение и топы считаются после каждого пересчёта,
а не на каждый заход на экран — на 4,7 млн пар это шесть секунд.

Лежит в app_setting['vm.stats']; поменяться данные могут только через
rescore_pairs, который его и обновляет.
"""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db.models import AppSetting
from api.modules.vm.models import VmCve, VmHost, VmHostCve
from api.modules.vm.services.query import VulnFilters, base_select, raw_facets

STATS_KEY = "vm.stats"


def compute_stats(db: Session) -> dict[str, Any]:
    pairs = int(db.execute(select(func.count()).select_from(VmHostCve)).scalar() or 0)
    # Фасеты без фильтров — самый частый запрос таблицы; считаются здесь же. Уровней в кэше
    # нет, есть гистограмма балла: уровни выводятся при чтении по текущим порогам.
    all_facets = raw_facets(db, VulnFilters()) if pairs else {}
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
        .group_by(VmHost.id, VmHost.hostname, VmHost.ip, VmHost.zone, VmHost.criticality)
        .order_by(func.sum(VmHostCve.risk).desc())
        .limit(10)
    ).all()
    return {
        "pairs": pairs,
        "facets": all_facets,
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
