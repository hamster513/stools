"""Обогащение витрины `vm_cve`, ценность хостов и пересчёт пар (спека 2026-10-21 §9).

Порядок всегда один: справочники → `vm_cve.likelihood`, `cvss10`, `av_class`, KEV;
зоны и веса → `vm_host.value`, `internet`; затем `vm_host_cve` и `vm_image_cve` —
каждая одним UPDATE (`rescore_all`).
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
from sqlalchemy import (
    Table,
    bindparam,
    case,
    cast,
    delete,
    exists,
    func,
    null,
    select,
    tuple_,
    update,
)
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

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
    VmImage,
    VmImageCve,
    VmRefState,
    VmZone,
)
from api.modules.vm.services.ghsa_mapping import canonical_finding_id, is_ghsa, reference_metrics
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
IMAGE_T = typing_cast(Table, VmImage.__table__)
IMAGE_PAIR_T = typing_cast(Table, VmImageCve.__table__)


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
    """CVE, у которых не осталось ни одной пары — ни с хостом, ни с образом, — витрине не нужны."""
    on_hosts = select(VmHostCve.cve_id).distinct()
    on_images = select(VmImageCve.cve_id).distinct()
    result = typing_cast(
        CursorResult[Any],
        db.execute(delete(CVE_T).where(CVE_T.c.cve_id.not_in(on_hosts), CVE_T.c.cve_id.not_in(on_images))),
    )
    db.commit()
    return int(result.rowcount or 0)


def rebuild_cves(
    db: Session, weights: Weights, cve_ids: Sequence[str] | None = None, handle: JobHandle | None = None
) -> int:
    """Собрать поля `vm_cve` из справочников и посчитать члены CVE: `likelihood`,
    `cvss10`, `av_class` (тяжесть без reach — reach зависит ещё и от хоста).

    `cve_ids=None` — все CVE витрины (после загрузки справочника или смены
    весов); список — только новые после импорта.
    """
    if cve_ids is None:
        # Older Harbor syncs retained GHSA findings but did not create their mart rows.
        # A reference import must enrich those explicit observations immediately.
        observed = db.scalars(select(VmImageCve.cve_id).distinct().where(
            func.upper(VmImageCve.cve_id).like("GHSA-%"),
        ))
        ensure_cves(db, (identifier for identifier in observed if is_ghsa(identifier)))
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
        references = reference_metrics(db, chunk)
        params = []
        for cve_id in chunk:
            reference = references[cve_id]
            n, e, k, g = reference.nvd, reference.epss, reference.kev, reference.ghsa
            cvss, source = None, "none"
            v3_av, v3_pr, v3_ui = (n.v3_av, n.v3_pr, n.v3_ui) if n else (None, None, None)
            v2_av, v2_ac, v2_au = (n.v2_av, n.v2_ac, n.v2_au) if n else (None, None, None)
            if n is not None and n.cvss_v3 is not None:
                cvss, source = n.cvss_v3, "nvd_v3"
            elif n is not None and n.cvss_v2 is not None:
                cvss, source = n.cvss_v2, "nvd_v2"
            elif g is not None and g.cvss is not None:
                cvss = g.cvss
                major = g.cvss_version[:1]
                source = f"ghsa_v{major}" if major in {"2", "3", "4"} else "ghsa"
                vector = dict(part.split(":", 1) for part in (g.cvss_vector or "").split("/") if ":" in part)
                av = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}.get(vector.get("AV", ""))
                if major == "2":
                    v3_av, v3_pr, v3_ui = None, None, None
                    v2_av = av
                    v2_ac = {"L": "LOW", "M": "MEDIUM", "H": "HIGH"}.get(vector.get("AC", ""))
                    v2_au = {"N": "NONE", "S": "SINGLE", "M": "MULTIPLE"}.get(vector.get("Au", ""))
                else:
                    v3_av = av
                    v3_pr = {"N": "NONE", "L": "LOW", "H": "HIGH"}.get(vector.get("PR", ""))
                    v3_ui = {"N": "NONE", "R": "REQUIRED", "P": "PASSIVE", "A": "ACTIVE"}.get(vector.get("UI", ""))
                    v2_av, v2_ac, v2_au = None, None, None
            exdb_type = best_exploit_type(reference.exploit_types, weights)
            msf_rank = best_msf_rank(reference.msf_ranks, weights)
            inputs = CveInputs(
                epss=e.epss if e is not None else None,
                cvss=cvss,
                av=v3_av or v2_av,
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
                    "b_v3_av": v3_av,
                    "b_v3_pr": v3_pr,
                    "b_v3_ui": v3_ui,
                    "b_v2_av": v2_av,
                    "b_v2_ac": v2_ac,
                    "b_v2_au": v2_au,
                    "b_epss": inputs.epss,
                    "b_epss_percentile": e.percentile if e is not None else None,
                    "b_exploitdb_type": exdb_type,
                    "b_exploits_count": len(reference.exploit_types),
                    "b_msf_rank": msf_rank,
                    "b_msf_modules": len(reference.msf_ranks),
                    "b_description": n.description if n and n.description else (g.description or g.summary if g else None),
                    "b_published": n.published if n and n.published else (g.published.date() if g and g.published else None),
                    "b_kev": inputs.kev,
                    "b_kev_added": inputs.kev_added,
                    "b_kev_ransomware": bool(k and k.ransomware),
                    "b_kev_due": k.due_date if k else None,
                    "b_likelihood": likelihood(inputs, weights)[0].value,
                    "b_cvss10": cvss / 10.0 if cvss is not None else None,
                    "b_av_class": av_class(v3_av, v2_av),
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
    result = typing_cast(
        CursorResult[Any],
        db.execute(
            update(PAIR_T)
            .where(HOST_T.c.id == PAIR_T.c.host_id, CVE_T.c.cve_id == PAIR_T.c.cve_id)
            .values(risk_raw=raw, risk=_clamped(raw))
        ),
    )
    db.commit()
    # Обзор читает кэш: пересчёт — единственное, что меняет риск.
    from api.modules.vm.services.stats import refresh_stats

    refresh_stats(db)
    return int(result.rowcount or 0)


def _clamped(raw: ColumnElement[Any]) -> ColumnElement[Any]:
    """risk = round(100 × raw) в 0..100; почему FLOOR(x + 0.5) — в `rescore_pairs`."""
    return case(
        (raw >= 1.0, 100),
        (raw <= 0.0, 0),
        else_=cast(func.floor(raw * 100.0 + 0.5), SaInteger),
    )


def image_value(w: Weights) -> float:
    """V образа: базовая ценность — у образа нет ни критичности, ни зоны. Одна функция,
    чтобы потом заменить её ценностью из Assets."""
    return host_value(None, False, False, w)


def rescore_image_pairs(db: Session, weights: Weights) -> int:
    """Риск пар «образ × CVE» по той же формуле, что у хостов: одним
    `UPDATE vm_image_cve … FROM vm_cve`, reach — как у хоста без доступа из интернета,
    V — `image_value`. Пары, чьего идентификатора нет в витрине, получают NULL.
    Затем на образе — наибольший риск и число находок с риском без дублей CVE/GHSA.
    Возвращает число пар, получивших риск.
    """
    w = weights
    reach = case(
        (CVE_T.c.av_class == "network", w.reach.network_internal),
        (CVE_T.c.av_class == "adjacent", w.reach.adjacent),
        (CVE_T.c.av_class == "local", w.reach.local),
        else_=w.reach_unknown,
    )
    raw = CVE_T.c.likelihood * func.coalesce(CVE_T.c.cvss10, w.cvss_missing) * reach * image_value(w)
    in_mart = exists().where(CVE_T.c.cve_id == IMAGE_PAIR_T.c.cve_id)
    db.execute(
        update(IMAGE_PAIR_T)
        .where(~in_mart, IMAGE_PAIR_T.c.risk_raw.is_not(None) | IMAGE_PAIR_T.c.risk.is_not(None))
        .values(risk_raw=null(), risk=null())
    )
    result = typing_cast(
        CursorResult[Any],
        db.execute(
            update(IMAGE_PAIR_T)
            .where(CVE_T.c.cve_id == IMAGE_PAIR_T.c.cve_id)
            .values(risk_raw=raw, risk=_clamped(raw))
        ),
    )
    pairs = IMAGE_PAIR_T.alias("p")
    of_image = pairs.c.image_id == IMAGE_T.c.id
    # Many images repeat the same identifier. Resolve its bounded alias component
    # once per distinct observed ID, rather than once per package finding.
    identifiers = select(IMAGE_PAIR_T.c.cve_id).distinct().cte("observed_image_ids")
    canonical_ids = select(
        identifiers.c.cve_id,
        canonical_finding_id(identifiers.c.cve_id).label("canonical"),
    ).cte("canonical_image_ids").prefix_with("MATERIALIZED")
    counted_pairs = pairs.join(canonical_ids, canonical_ids.c.cve_id == pairs.c.cve_id)
    db.execute(
        update(IMAGE_T).values(
            risk_max=select(func.max(pairs.c.risk)).where(of_image).scalar_subquery(),
            cves_scored=select(func.count(func.distinct(tuple_(
                canonical_ids.c.canonical, pairs.c.package, pairs.c.installed_version,
            )))).select_from(counted_pairs).where(of_image, pairs.c.risk.is_not(None)).scalar_subquery(),
        )
    )
    db.commit()
    return int(result.rowcount or 0)


def rescore_all(db: Session, weights: Weights) -> int:
    """Полный пересчёт риска: пары хостов и пары образов. Возвращает сумму пар."""
    return rescore_pairs(db, weights) + rescore_image_pairs(db, weights)


def recalculate(db: Session, handle: JobHandle, weights: Weights) -> None:
    """Задача `recalculate`: после смены весов или разметки зон."""
    handle.stage("cves", message="вероятность и тяжесть CVE")
    rebuild_cves(db, weights, None, handle)
    handle.stage("hosts", message="ценность хостов")
    rebuild_hosts_value(db, weights, handle)
    handle.stage("pairs", message="риск пар")
    n = rescore_all(db, weights)
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
