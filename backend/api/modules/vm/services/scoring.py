"""Обогащение витрины `vm_cve`, ценность хостов и пересчёт пар (спека 2026-10-21 §9).

Порядок всегда один: справочники → `vm_cve.likelihood`, `cvss10`, `av_class`, KEV;
зоны и веса → `vm_host.value`, `internet`; затем `vm_host_cve` одним UPDATE.
Каждая функция идемпотентна: её можно звать после любого изменения входа.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import threading
from collections.abc import Callable, Iterable, Sequence
from typing import Any
from typing import cast as typing_cast

from sqlalchemy import Integer as SaInteger
from sqlalchemy import Table, bindparam, case, cast, delete, func, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from api.db.models import AppSetting
from api.llm_settings import read_setting
from api.modules.vm.core.risk import (
    CveInputs,
    av_class,
    best_exploit_type,
    best_msf_rank,
    host_value,
    likelihood,
)
from api.modules.vm.core.weights import Weights
from api.modules.vm.models import (
    VmCve,
    VmHost,
    VmHostCve,
    VmRefEpss,
    VmRefExploitdb,
    VmRefExploitdbCve,
    VmRefKev,
    VmRefMsf,
    VmRefMsfCve,
    VmRefNvd,
    VmRefState,
    VmZone,
)
from api.modules.vm.services.jobs import (
    DATA_KINDS,
    JobHandle,
    active_job,
    lock_job_start,
    run_job,
    start_job,
)

log = logging.getLogger(__name__)

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
) -> tuple[
    dict[str, VmRefNvd], dict[str, VmRefEpss], dict[str, list[str]], dict[str, list[int]], dict[str, VmRefKev]
]:
    nvd = {r.cve_id: r for r in db.execute(select(VmRefNvd).where(VmRefNvd.cve_id.in_(chunk))).scalars()}
    epss = {r.cve_id: r for r in db.execute(select(VmRefEpss).where(VmRefEpss.cve_id.in_(chunk))).scalars()}
    kev = {r.cve_id: r for r in db.execute(select(VmRefKev).where(VmRefKev.cve_id.in_(chunk))).scalars()}
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
    return nvd, epss, exdb, msf, kev


def rebuild_cves(
    db: Session, weights: Weights, cve_ids: Sequence[str] | None = None, handle: JobHandle | None = None
) -> int:
    """Собрать поля `vm_cve` из справочников и посчитать члены CVE: `likelihood`,
    `cvss10`, `av_class` (тяжесть без reach — reach зависит ещё и от хоста).

    `cve_ids=None` — все CVE витрины (после загрузки справочника или смены
    весов); список — только новые после импорта.
    """
    ids = list(cve_ids) if cve_ids is not None else list(db.execute(select(VmCve.cve_id)).scalars())
    # Без загруженного каталога «нет в KEV» — незнание, а не факт: карточка это пометит.
    kev_loaded = db.get(VmRefState, "kev") is not None
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
            kev=bindparam("b_kev"),
            kev_added=bindparam("b_kev_added"),
            kev_ransomware=bindparam("b_kev_ransomware"),
            kev_due=bindparam("b_kev_due"),
            likelihood=bindparam("b_likelihood"),
            cvss10=bindparam("b_cvss10"),
            av_class=bindparam("b_av_class"),
        )
    )
    done = 0
    for chunk in _chunks(ids):
        nvd, epss, exdb, msf, kev = _refs_for(db, chunk)
        params = []
        for cve_id in chunk:
            n = nvd.get(cve_id)
            e = epss.get(cve_id)
            k = kev.get(cve_id)
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
                av=(n.v3_av or n.v2_av) if n else None,
                exploitdb_type=exdb_type,
                msf_rank=msf_rank,
                kev=k is not None,
                kev_added=k.date_added if k else None,
                kev_loaded=kev_loaded,
            )
            params.append(
                {
                    "b_cve_id": cve_id,
                    "b_cvss": cvss,
                    "b_cvss_source": source,
                    "b_v3_av": n.v3_av if n else None,
                    "b_v3_pr": n.v3_pr if n else None,
                    "b_v3_ui": n.v3_ui if n else None,
                    "b_v2_av": n.v2_av if n else None,
                    "b_v2_ac": n.v2_ac if n else None,
                    "b_v2_au": n.v2_au if n else None,
                    "b_epss": inputs.epss,
                    "b_epss_percentile": e.percentile if e is not None else None,
                    "b_exploitdb_type": exdb_type,
                    "b_exploits_count": len(exdb.get(cve_id, [])),
                    "b_msf_rank": msf_rank,
                    "b_msf_modules": len(msf.get(cve_id, [])),
                    "b_description": n.description if n else None,
                    "b_published": n.published if n else None,
                    "b_kev": inputs.kev,
                    "b_kev_added": inputs.kev_added,
                    "b_kev_ransomware": bool(k and k.ransomware),
                    "b_kev_due": k.due_date if k else None,
                    "b_likelihood": likelihood(inputs, weights)[0].value,
                    "b_cvss10": cvss / 10.0 if cvss is not None else None,
                    "b_av_class": av_class(n.v3_av, n.v2_av) if n else "none",
                }
            )
        if params:
            db.execute(stmt, params)
            db.commit()
        done += len(chunk)
        if handle is not None:
            handle.tick(done, total=len(ids))
    return done


def rebuild_hosts_value(db: Session, weights: Weights, handle: JobHandle | None = None) -> int:
    """`vm_host.value` (V) и `vm_host.internet` по критичности и разметке зоны."""
    zones = {z.name: z for z in db.execute(select(VmZone)).scalars()}
    rows = db.execute(select(VmHost.id, VmHost.criticality, VmHost.zone)).all()
    stmt = (
        update(HOST_T)
        .where(HOST_T.c.id == bindparam("b_id"))
        .values(value=bindparam("b_value"), internet=bindparam("b_internet"))
    )
    for i in range(0, len(rows), BATCH):
        params = []
        for host_id, crit, zone_name in rows[i : i + BATCH]:
            zone = zones.get(zone_name)
            internet = bool(zone and zone.internet_access)
            params.append(
                {
                    "b_id": host_id,
                    "b_value": host_value(
                        crit or None,
                        internet=internet,
                        confidential=bool(zone and zone.confidential_data),
                        w=weights,
                    ),
                    "b_internet": internet,
                }
            )
        db.execute(stmt, params)
        db.commit()
        if handle is not None:
            handle.tick(min(i + BATCH, len(rows)), total=len(rows))
    return len(rows)


def rescore_pairs(db: Session, weights: Weights) -> int:
    """risk_raw = L × CVSS' × reach × V, risk = round(100 × risk_raw) в 0..100 — одним
    `UPDATE vm_host_cve … FROM vm_host, vm_cve`. reach — `CASE` по классу вектора CVE и
    доступу хоста из интернета; веса уходят параметрами запроса.

    Округление — FLOOR(x + 0.5), а не CAST(x + 0.5): CAST double precision
    в integer Postgres сам округляет (до чётного), и прибавленная половина
    округлялась второй раз — риск завышался на единицу (67.18 → 68).
    FLOOR отбрасывает дробную часть на обоих диалектах, так что половина
    добавляется ровно один раз (`core.risk.score` округляет так же).
    """
    w = weights
    reach = case(
        ((CVE_T.c.av_class == "network") & HOST_T.c.internet, w.reach.network_internet),
        (CVE_T.c.av_class == "network", w.reach.network_internal),
        (CVE_T.c.av_class == "adjacent", w.reach.adjacent),
        (CVE_T.c.av_class == "local", w.reach.local),
        else_=w.reach_unknown,
    )
    raw = CVE_T.c.likelihood * func.coalesce(CVE_T.c.cvss10, w.cvss_missing) * reach * HOST_T.c.value
    clamped = case(
        (raw >= 1.0, 100),
        (raw <= 0.0, 0),
        else_=cast(func.floor(raw * 100.0 + 0.5), SaInteger),
    )
    result = typing_cast(
        CursorResult[Any],
        db.execute(
            update(PAIR_T)
            .where(HOST_T.c.id == PAIR_T.c.host_id, CVE_T.c.cve_id == PAIR_T.c.cve_id)
            .values(risk_raw=raw, risk=clamped)
        ),
    )
    db.commit()
    # Обзор читает кэш: пересчёт — единственное, что меняет риск.
    from api.modules.vm.services.stats import refresh_stats

    refresh_stats(db)
    return int(result.rowcount or 0)


def recalculate(db: Session, handle: JobHandle, weights: Weights) -> None:
    """Задача `recalculate`: после смены весов или разметки зон."""
    handle.stage("cves", message="вероятность и тяжесть CVE")
    rebuild_cves(db, weights, None, handle)
    handle.stage("hosts", message="ценность хостов")
    rebuild_hosts_value(db, weights, handle)
    handle.stage("pairs", message="риск пар")
    n = rescore_pairs(db, weights)
    # Маркер — только после полного прохода: прерванный пересчёт оставит его старым,
    # и следующий старт API поставит пересчёт заново.
    write_formula_version(db)
    handle.stage("done", message=f"пересчитано пар: {n}")


#: Версия формулы риска. Растёт, когда меняется сама формула: риск пар, посчитанный
#: прежней версией, неверен, пока не пройдёт полный `recalculate`.
FORMULA_VERSION = 2
#: Ключ в `app_setting`: какой версией формулы посчитан риск пар.
FORMULA_VERSION_KEY = "vm_formula_version"


def read_formula_version(db: Session) -> int:
    raw = read_setting(db, FORMULA_VERSION_KEY)
    return 0 if raw is None else int(json.loads(raw))


def write_formula_version(db: Session) -> None:
    row = db.get(AppSetting, FORMULA_VERSION_KEY)
    if row is None:
        row = AppSetting(key=FORMULA_VERSION_KEY)
        db.add(row)
    row.value_json = json.dumps(FORMULA_VERSION)
    row.updated_at = dt.datetime.now(dt.UTC)
    db.commit()


def pair_count(db: Session) -> int:
    return int(db.execute(select(func.count()).select_from(VmHostCve)).scalar() or 0)


#: Кто запустил пересчёт после обновления схемы: человека у задачи нет.
AUTO_STARTED_BY = "после обновления"


def _in_thread(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, name="stools-vm-rescore", daemon=True).start()


#: Как задача уходит из старта API: старт её не ждёт. Тесты подменяют на вызов на месте.
spawn: Callable[[Callable[[], None]], None] = _in_thread


def ensure_rescored(db: Session) -> int | None:
    """Пересчёт после смены формулы: риск пар посчитан прежней версией, пока полный
    `recalculate` не запишет маркер `FORMULA_VERSION`. Признак — пары есть, а маркер
    нет или он старше. Справочники не нужны: и без них новая формула даёт другие числа.
    Задача ставится не поверх идущей; прерванная не пишет маркер — следующий старт
    поставит её снова. Возвращает номер поставленной задачи или None."""
    from api.modules.vm.services.settings import load_settings

    if db.execute(select(VmHostCve.host_id).limit(1)).first() is None:
        return None
    if read_formula_version(db) >= FORMULA_VERSION:
        return None
    lock_job_start(db)
    if active_job(db, [*DATA_KINDS, "bulk_status"]) is not None:
        db.rollback()
        return None
    job_id = start_job(db, "recalculate", AUTO_STARTED_BY, message="риск по новой формуле после обновления")

    def work(session: Session, handle: JobHandle) -> None:
        recalculate(session, handle, load_settings(session).weights)

    log.warning("VM: риск пар посчитан по старой формуле — поставлен пересчёт, задача #%s", job_id)
    spawn(lambda: run_job(job_id, work))
    return job_id


def ensure_vm_rescored() -> None:
    """Для lifespan API: своя сессия. Сбой не мешает старту — пересчёт можно запустить вручную."""
    from api.db.base import get_sessionmaker

    try:
        with get_sessionmaker()() as db:
            ensure_rescored(db)
    except Exception:  # старт API важнее автоматического пересчёта
        log.exception("VM: проверка пересчёта после обновления не удалась")
