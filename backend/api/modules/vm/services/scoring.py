"""Обогащение витрины `vm_cve`, Impact хостов и пересчёт пар (спека §4).

Порядок всегда один: справочники → `vm_cve.cve_factor`, зоны и веса →
`vm_host.impact`, затем `vm_host_cve` одним UPDATE. Каждая функция
идемпотентна: её можно звать после любого изменения входа.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any
from typing import cast as typing_cast

from sqlalchemy import Integer as SaInteger
from sqlalchemy import Table, bindparam, case, cast, delete, func, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from api.modules.vm.core.risk import (
    CveInputs,
    best_exploit_type,
    best_msf_rank,
    cve_factor,
    host_impact,
)
from api.modules.vm.core.weights import Weights
from api.modules.vm.models import (
    VmCve,
    VmHost,
    VmHostCve,
    VmRefEpss,
    VmRefExploitdb,
    VmRefExploitdbCve,
    VmRefMsf,
    VmRefMsfCve,
    VmRefNvd,
    VmZone,
)
from api.modules.vm.services.jobs import JobHandle

BATCH = 5000

#: Core-таблицы для массовых UPDATE: ORM-вариант с bindparam в WHERE
#: требует отключать синхронизацию сессии, а здесь она и не нужна.
CVE_T = typing_cast(Table, VmCve.__table__)
HOST_T = typing_cast(Table, VmHost.__table__)
PAIR_T = typing_cast(Table, VmHostCve.__table__)


def _chunks(items: Sequence[str], size: int = BATCH) -> Iterable[Sequence[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def ensure_cves(db: Session, cve_ids: Iterable[str]) -> list[str]:
    """Завести пустые строки `vm_cve` для новых идентификаторов; вернуть их."""
    wanted = sorted(set(cve_ids))
    new: list[str] = []
    for chunk in _chunks(wanted):
        existing = set(db.execute(select(VmCve.cve_id).where(VmCve.cve_id.in_(chunk))).scalars())
        fresh = [c for c in chunk if c not in existing]
        if fresh:
            db.execute(CVE_T.insert(), [{"cve_id": c} for c in fresh])
            new.extend(fresh)
    db.commit()
    return new


def drop_orphan_cves(db: Session) -> int:
    """CVE, у которых не осталось ни одной пары, витрине не нужны."""
    used = select(VmHostCve.cve_id).distinct()
    result = typing_cast(CursorResult[Any], db.execute(delete(CVE_T).where(CVE_T.c.cve_id.not_in(used))))
    db.commit()
    return int(result.rowcount or 0)


def _refs_for(
    db: Session, chunk: Sequence[str]
) -> tuple[dict[str, VmRefNvd], dict[str, VmRefEpss], dict[str, list[str]], dict[str, list[int]]]:
    nvd = {r.cve_id: r for r in db.execute(select(VmRefNvd).where(VmRefNvd.cve_id.in_(chunk))).scalars()}
    epss = {r.cve_id: r for r in db.execute(select(VmRefEpss).where(VmRefEpss.cve_id.in_(chunk))).scalars()}
    exdb: dict[str, list[str]] = {}
    for cve_id, etype in db.execute(
        select(VmRefExploitdbCve.cve_id, VmRefExploitdb.type)
        .join(VmRefExploitdb, VmRefExploitdb.exploit_id == VmRefExploitdbCve.exploit_id)
        .where(VmRefExploitdbCve.cve_id.in_(chunk))
    ):
        exdb.setdefault(cve_id, []).append(etype)
    msf: dict[str, list[int]] = {}
    for cve_id, rank in db.execute(
        select(VmRefMsfCve.cve_id, VmRefMsf.rank)
        .join(VmRefMsf, VmRefMsf.fullname == VmRefMsfCve.fullname)
        .where(VmRefMsfCve.cve_id.in_(chunk))
    ):
        msf.setdefault(cve_id, []).append(rank)
    return nvd, epss, exdb, msf


def rebuild_cves(
    db: Session, weights: Weights, cve_ids: Sequence[str] | None = None, handle: JobHandle | None = None
) -> int:
    """Собрать поля `vm_cve` из справочников и посчитать `cve_factor`.

    `cve_ids=None` — все CVE витрины (после загрузки справочника или смены
    весов); список — только новые после импорта.
    """
    ids = list(cve_ids) if cve_ids is not None else list(db.execute(select(VmCve.cve_id)).scalars())
    stmt = (
        update(CVE_T)
        .where(CVE_T.c.cve_id == bindparam("b_cve_id"))
        .values(
            cvss=bindparam("b_cvss"),
            cvss_source=bindparam("b_cvss_source"),
            v3_av=bindparam("b_v3_av"),
            v3_pr=bindparam("b_v3_pr"),
            v3_ui=bindparam("b_v3_ui"),
            v2_av=bindparam("b_v2_av"),
            v2_ac=bindparam("b_v2_ac"),
            v2_au=bindparam("b_v2_au"),
            epss=bindparam("b_epss"),
            epss_percentile=bindparam("b_epss_percentile"),
            exploitdb_type=bindparam("b_exploitdb_type"),
            exploits_count=bindparam("b_exploits_count"),
            msf_rank=bindparam("b_msf_rank"),
            msf_modules=bindparam("b_msf_modules"),
            description=bindparam("b_description"),
            published=bindparam("b_published"),
            cve_factor=bindparam("b_cve_factor"),
        )
    )
    done = 0
    for chunk in _chunks(ids):
        nvd, epss, exdb, msf = _refs_for(db, chunk)
        params = []
        for cve_id in chunk:
            n = nvd.get(cve_id)
            e = epss.get(cve_id)
            cvss, source = None, "none"
            if n is not None and n.cvss_v3 is not None:
                cvss, source = n.cvss_v3, "nvd_v3"
            elif n is not None and n.cvss_v2 is not None:
                cvss, source = n.cvss_v2, "nvd_v2"
            exdb_type = best_exploit_type(exdb.get(cve_id, []), weights)
            msf_rank = best_msf_rank(msf.get(cve_id, []), weights)
            inputs = CveInputs(
                epss=e.epss if e is not None else None,
                cvss=cvss,
                v3_av=n.v3_av if n else None,
                v3_pr=n.v3_pr if n else None,
                v3_ui=n.v3_ui if n else None,
                v2_av=n.v2_av if n else None,
                v2_ac=n.v2_ac if n else None,
                v2_au=n.v2_au if n else None,
                exploitdb_type=exdb_type,
                msf_rank=msf_rank,
            )
            params.append(
                {
                    "b_cve_id": cve_id,
                    "b_cvss": cvss,
                    "b_cvss_source": source,
                    "b_v3_av": inputs.v3_av,
                    "b_v3_pr": inputs.v3_pr,
                    "b_v3_ui": inputs.v3_ui,
                    "b_v2_av": inputs.v2_av,
                    "b_v2_ac": inputs.v2_ac,
                    "b_v2_au": inputs.v2_au,
                    "b_epss": inputs.epss,
                    "b_epss_percentile": e.percentile if e is not None else None,
                    "b_exploitdb_type": exdb_type,
                    "b_exploits_count": len(exdb.get(cve_id, [])),
                    "b_msf_rank": msf_rank,
                    "b_msf_modules": len(msf.get(cve_id, [])),
                    "b_description": n.description if n else None,
                    "b_published": n.published if n else None,
                    "b_cve_factor": cve_factor(inputs, weights),
                }
            )
        if params:
            db.execute(stmt, params)
            db.commit()
        done += len(chunk)
        if handle is not None:
            handle.tick(done, total=len(ids))
    return done


def rebuild_hosts_impact(db: Session, weights: Weights, handle: JobHandle | None = None) -> int:
    zones = {z.name: z for z in db.execute(select(VmZone)).scalars()}
    rows = db.execute(select(VmHost.id, VmHost.criticality, VmHost.zone)).all()
    stmt = update(HOST_T).where(HOST_T.c.id == bindparam("b_id")).values(impact=bindparam("b_impact"))
    for i in range(0, len(rows), BATCH):
        params = []
        for host_id, crit, zone_name in rows[i : i + BATCH]:
            zone = zones.get(zone_name)
            params.append(
                {
                    "b_id": host_id,
                    "b_impact": host_impact(
                        crit or None,
                        internet=bool(zone and zone.internet_access),
                        confidential=bool(zone and zone.confidential_data),
                        w=weights,
                    ),
                }
            )
        db.execute(stmt, params)
        db.commit()
        if handle is not None:
            handle.tick(min(i + BATCH, len(rows)), total=len(rows))
    return len(rows)


def rescore_pairs(db: Session) -> int:
    """risk = round(min(1, impact × cve_factor) × 100) одним запросом.

    Округление — FLOOR(x + 0.5), а не CAST(x + 0.5): CAST double precision
    в integer Postgres сам округляет (до чётного), и прибавленная половина
    округлялась второй раз — риск завышался на единицу (67.18 → 68).
    FLOOR отбрасывает дробную часть на обоих диалектах, так что половина
    добавляется ровно один раз.
    """
    raw = (
        select(HOST_T.c.impact * CVE_T.c.cve_factor)
        .where(HOST_T.c.id == PAIR_T.c.host_id, CVE_T.c.cve_id == PAIR_T.c.cve_id)
        .scalar_subquery()
    )
    clamped = case((raw >= 1.0, 100), else_=cast(func.floor(raw * 100.0 + 0.5), SaInteger))
    result = typing_cast(CursorResult[Any], db.execute(update(PAIR_T).values(risk_raw=raw, risk=clamped)))
    db.commit()
    # Обзор читает кэш: пересчёт — единственное, что меняет риск.
    from api.modules.vm.services.stats import refresh_stats

    refresh_stats(db)
    return int(result.rowcount or 0)


def recalculate(db: Session, handle: JobHandle, weights: Weights) -> None:
    """Задача `recalculate`: после смены весов или разметки зон."""
    handle.stage("cves", message="множители CVE")
    rebuild_cves(db, weights, None, handle)
    handle.stage("hosts", message="Impact хостов")
    rebuild_hosts_impact(db, weights, handle)
    handle.stage("pairs", message="риск пар")
    n = rescore_pairs(db)
    handle.stage("done", message=f"пересчитано пар: {n}")


def pair_count(db: Session) -> int:
    return int(db.execute(select(func.count()).select_from(VmHostCve)).scalar() or 0)
