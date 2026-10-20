"""Синхронизация с модулями VM, KSC и AD (спека §2 «Синхронизация»).

Assets читает таблицы и файлы модулей сам; модули знают об Assets одним вызовом
`request_sync(db, source)` в конце успешного импорта. Задача синхронизирует все
источники сразу: пересчёт карточки зависит от наблюдений всех источников.

`seen_at`: VM — время последнего импорта (другого у VM нет), KSC и AD — `collected_at`
последнего снапшота каждого сервера и домена.
"""
from __future__ import annotations

import json
import logging
import threading
from collections import defaultdict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, func, select, text
from sqlalchemy.orm import Session

from api.jobs import JobCancelled, JobHandle, active_job, run_job, start_job
from api.modules.assets.core.matching import Observed, is_ip, normalize_fqdn, normalize_name
from api.modules.assets.findings_adapter import reconcile as reconcile_findings
from api.modules.assets.models import Asset, AssetJob, AssetObservation
from api.modules.assets.services.assets import (
    MatchIndex,
    apply_observation,
    load_settings,
    observed,
    recompute,
    settings_row,
)
from api.modules.assets.services.networks import load_networks
from api.modules.assets.services.users import (
    AdExportCache,
    ksc_host_users,
    read_ad_export,
    sync_users,
)
from api.platform.scheduler import PlatformSchedule
from api.timeutil import utcnow

log = logging.getLogger("stools.assets")

SYNC_SOURCES = ("vm", "ksc", "ad")
SOURCE_TITLES = {"vm": "VM", "ksc": "KSC", "ad": "AD"}
#: Итог задачи: после источников — пользователи (`services.users`); `users_failed` — шаг пользователей не удался.
COUNT_TITLES = {**SOURCE_TITLES, "users": "пользователи"}
USERS_FAILED = "users_failed"
USERS_FAILED_TEXT = "пользователи: сбой, см. журнал"
#: Кто запустил задачу после импорта модуля: человека у неё нет.
AUTO_STARTED_BY = "после импорта"
#: Прогресс и проверка отмены — раз в столько наблюдений.
TICK_EVERY = 500
#: Ключ advisory-блокировки синхронизации («SYNC» в ASCII): одна на всю базу.
SYNC_LOCK_KEY = 0x53594E43
BUSY_MESSAGE = "синхронизация уже идёт"
WAIT_MESSAGE = "ждёт окончания записи результатов скана или DNS"
#: Кто запустил синхронизацию по расписанию; цель у расписания одна — весь модуль.
SCHEDULE_STARTED_BY = "расписание"
SCHEDULE_TARGET_ID = 0


def _in_thread(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, name="stools-assets-sync", daemon=True).start()


#: Как задача уходит из потока импорта модуля: импорт не ждёт синхронизацию.
#: Тесты подменяют на вызов на месте (поток пережил бы тест).
spawn: Callable[[Callable[[], None]], None] = _in_thread


def request_sync(db: Session, source: str) -> int | None:
    """Если включено `sync_after_import` и синхронизация не идёт — запустить её; иначе None.
    Если идёт — попросить её пройти ещё раз: она читала источники до этого импорта.
    Вызывается после фиксации импорта модуля: задача читает уже записанные данные."""
    if not load_settings(db)["sync_after_import"]:
        return None
    if active_job(db, AssetJob, ("sync",)) is not None:
        _set_rerun(db, True)
        return None
    job_id = start_job(db, AssetJob, "sync", AUTO_STARTED_BY, message=source)
    spawn(lambda: run_job(AssetJob, job_id, lambda s, h: sync_job(s, h, SOURCE_TITLES.get(source, source))))
    return job_id


def schedule_handler(db: Session, schedule: PlatformSchedule) -> int | None:
    """Обработчик планировщика `assets/sync`: None — синхронизация уже идёт (повтор на следующем тике)."""
    if active_job(db, AssetJob, ("sync",)) is not None:
        return None
    job_id = start_job(db, AssetJob, "sync", SCHEDULE_STARTED_BY, message=SCHEDULE_STARTED_BY)
    spawn(lambda: run_job(AssetJob, job_id, lambda s, h: sync_job(s, h, "по расписанию")))
    return job_id


def sync_job(db: Session, handle: JobHandle, trigger: str) -> None:
    """Итог задачи — что её запустило и сколько наблюдений дал каждый источник."""
    counts = run_sync(db, handle)
    if counts is None:
        return
    parts = [USERS_FAILED_TEXT if s == USERS_FAILED else f"{COUNT_TITLES[s]} {n}" for s, n in counts.items()]
    handle.stage("done", message=f"{trigger}: " + " · ".join(parts))


# ---- Чтение источников ----------------------------------------------------


def _host_names(hostname: str) -> tuple[str, str, str]:
    """(имя, FQDN, домен) из имени хоста VM: домен выводится из имени с точкой."""
    if is_ip(hostname):
        return "", "", ""
    fqdn = normalize_fqdn(hostname)
    short, domain = normalize_name(hostname)
    name = hostname.strip().split(".", 1)[0] if short else ""
    return name, fqdn, domain if fqdn else ""


def observations_from_vm(db: Session) -> Iterator[Observed]:
    from api.modules.vm.models import VmHost, VmHostCve, VmImport

    seen_at = db.execute(select(func.max(VmImport.finished_at))).scalar() or utcnow()
    cves = dict(db.execute(select(VmHostCve.host_id, func.count()).group_by(VmHostCve.host_id)).tuples().all())
    for h in db.execute(select(VmHost).order_by(VmHost.id)).scalars():
        name, fqdn, domain = _host_names(h.hostname)
        yield Observed(
            source="vm", source_key=f"{h.hostname}|{h.ip}", name=name, fqdn=fqdn, domain=domain, ip=h.ip,
            ips=[h.ip] if h.ip else [], os=h.os_name, seen_at=seen_at,
            extra={"zone": h.zone, "groups": h.groups, "cve_count": int(cves.get(h.id, 0))},
        )


def _owner_unresolved(owner: Any) -> bool:
    """Владелец задан в KSC, но среди пользователей хоста не найден: `{"owner_id": …}` без SID и имени."""
    return isinstance(owner, dict) and bool(owner.get("owner_id")) and not (owner.get("sid") or owner.get("sam"))


def observations_from_ksc(db: Session) -> Iterator[Observed]:
    from api.modules.ksc.models import KscHost, KscServer
    from api.modules.ksc.services.snapshots import latest_snapshot

    for server in db.execute(select(KscServer).order_by(KscServer.id)).scalars():
        snap = latest_snapshot(db, server.id)
        if snap is None:
            continue
        for h in db.execute(select(KscHost).where(KscHost.snapshot_id == snap.id).order_by(KscHost.id)).scalars():
            fqdn = normalize_fqdn(h.fqdn)
            extra = json.loads(h.extra_json or "{}")
            users_collected, _people, session_groups = ksc_host_users(extra)
            yield Observed(
                source="ksc", source_key=f"{server.id}:{h.host_id}", name=h.name or fqdn.partition(".")[0], fqdn=fqdn, domain=h.domain,
                ip=h.ip, ips=[h.ip] if h.ip else [], os=h.os, seen_at=snap.collected_at,
                extra={
                    "group_path": h.group_path, "tags": extra.get("tags", []), "components": json.loads(h.components_json or "[]"),
                    "agent_alive": h.agent_alive, "protection": h.protection, "server_id": server.id,
                    # Пользователи хоста (§2.1): собраны ли, группы с сеансом и владелец вне списка
                    # (`{owner_id}`, ссылки на него нет) — только показ.
                    "users_collected": users_collected, "session_groups": session_groups,
                    "owner_unresolved": _owner_unresolved(extra.get("owner")),
                },
            )


def _ad_observations(db: Session, data_dir: Path, cache: AdExportCache | None = None) -> tuple[list[Observed], bool]:
    """Компьютеры последнего снапшота каждого домена из файла выгрузки; второе — все ли файлы
    прочитаны: без файла домена его компьютеры нельзя считать пропавшими. `cache` — разобранные
    выгрузки прохода: их же берёт шаг пользователей."""
    from api.modules.ad.core.checks.clusters import cluster_kind
    from api.modules.ad.core.export import ExportFormatError, filetime_to_datetime
    from api.modules.ad.models import AdDomain
    from api.modules.ad.services.snapshots import latest_snapshot

    out: list[Observed] = []
    complete = True
    for domain in db.execute(select(AdDomain).order_by(AdDomain.id)).scalars():
        snap = latest_snapshot(db, domain.id)
        if snap is None:
            continue
        try:
            export = read_ad_export(cache, data_dir, snap.id)
        except (ExportFormatError, OSError, ValueError) as exc:
            complete = False
            log.warning("снапшот AD #%s не прочитан: %s", snap.id, type(exc).__name__)
            continue
        dns_root = export.domain.dns_root.lower()
        for o in export.objects:
            if o.cls != "computer":
                continue
            last = filetime_to_datetime(o.lastLogonTimestamp)
            out.append(Observed(
                source="ad", source_key=o.sid or o.dn, name=(o.sam or o.name or "").rstrip("$"),
                fqdn=normalize_fqdn(o.dNSHostName or ""), domain=dns_root or export.domain.netbios.lower(),
                os=o.operatingSystem or "", seen_at=snap.collected_at,
                extra={
                    "dn": o.dn, "enabled": o.enabled, "last_logon": last.isoformat() if last else None,
                    "os_version": o.operatingSystemVersion or "", "domain_id": domain.id,
                    # cluster | role — виртуальное имя кластера, не хост; node — узел.
                    "cluster": cluster_kind(o.spn),
                    "laps": o.lapsExpiry is not None or o.lapsNewExpiry is not None,
                },
            ))
    return out, complete


def observations_from_ad(db: Session, data_dir: Path) -> Iterator[Observed]:
    yield from _ad_observations(db, data_dir)[0]


def _read(db: Session, source: str, data_dir: Path, cache: AdExportCache | None = None) -> tuple[list[Observed], bool]:
    if source == "vm":
        return list(observations_from_vm(db)), True
    if source == "ksc":
        return list(observations_from_ksc(db)), True
    if source == "ad":
        return _ad_observations(db, data_dir, cache)
    raise ValueError(f"неизвестный источник «{source}»")


# ---- Задача ---------------------------------------------------------------


def _migrate_ksc_keys(db: Session) -> None:
    """Ключ KSC был `host_id`, стал `server_id:host_id` (одинаковые host_id на двух серверах
    терялись). Старое наблюдение получает новый ключ — сервер записан в его `extra`, — а не
    уходит в пропавшие рядом с новой копией."""
    old = db.execute(
        select(AssetObservation).where(AssetObservation.source == "ksc", AssetObservation.source_key.not_like("%:%"))
    ).scalars()
    for row in old:
        server_id = (row.extra or {}).get("server_id")
        if server_id is not None:
            row.source_key = f"{server_id}:{row.source_key}"
    db.flush()


def _set_rerun(db: Session, value: bool) -> None:
    row = settings_row(db)
    row.data = {**(row.data or {}), "rerun_requested": value}
    db.commit()


def _take_rerun(db: Session) -> bool:
    """Просили ли пройти ещё раз; просьба снимается."""
    row = settings_row(db)
    asked = bool((row.data or {}).get("rerun_requested"))
    if asked:
        row.data = {**row.data, "rerun_requested": False}
    db.commit()
    return asked


@contextmanager
def sync_lock(db: Session, *, wait: bool = False) -> Iterator[bool]:
    """Синхронизация одна на базу: две параллельные вставили бы одно наблюдение дважды; запись
    результатов скана берёт ту же блокировку (`wait=True` — ждать, а не отказываться).
    Блокировка транзакционная, на отдельном соединении: задача фиксирует работу после каждого
    источника, а блокировка нужна до конца всех проходов. Процесс умер — соединение закрылось,
    блокировка снята."""
    bind = db.get_bind()
    engine = bind if isinstance(bind, Engine) else bind.engine
    with engine.connect() as conn:
        try:
            if wait:
                conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": SYNC_LOCK_KEY})
                yield True
            else:
                yield bool(conn.execute(text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": SYNC_LOCK_KEY}).scalar())
        finally:
            conn.rollback()


def try_lock_in_transaction(db: Session) -> bool:
    """Блокировка синхронизации в транзакции самой сессии — до её фиксации или отката: правка
    реестра человеком (объединение, отвязка) не идёт поперёк синхронизации и записи скана или DNS."""
    return bool(db.execute(text("SELECT pg_try_advisory_xact_lock(:key)"), {"key": SYNC_LOCK_KEY}).scalar())


def _earlier_sync_running(db: Session, job_id: int) -> bool:
    """Идёт ли синхронизация, заведённая раньше этой. Раньше — чтобы две, заведённые почти разом,
    не отказались обе, сочтя занятой друг друга: более поздняя уступает, ранняя ждёт блокировку."""
    return db.execute(
        select(AssetJob.id).where(AssetJob.kind == "sync", AssetJob.status == "running", AssetJob.id < job_id).limit(1)
    ).first() is not None


def run_sync(db: Session, handle: JobHandle, sources: tuple[str, ...] = SYNC_SOURCES) -> dict[str, int] | None:
    """Проход по источникам; если за время прохода попросили ещё (`request_sync` во время
    синхронизации) — ещё проход. None — синхронизацию уже ведёт другая задача: эта просит
    её пройти ещё раз и завершается, ничего не записав. Остаётся окно: просьба, пришедшая между последней проверкой
    и закрытием задачи, исполнится следующей синхронизацией.

    Блокировку держит не синхронизация, а запись результатов скана или DNS — задача ждёт её
    окончания, а не отбрасывается: иначе синхронизация после импорта терялась бы."""
    with sync_lock(db) as acquired:
        if acquired:
            return _locked_sync(db, handle, sources)
    if _earlier_sync_running(db, handle.id):
        # Задачу завели не зря (импорт), а идущая могла прочитать источник раньше него.
        _set_rerun(db, True)
        handle.stage("done", message=BUSY_MESSAGE)
        return None
    handle.stage("pending", message=WAIT_MESSAGE)  # заодно фиксирует: ожидание без открытой транзакции
    with sync_lock(db, wait=True):
        return _locked_sync(db, handle, sources)


def _locked_sync(db: Session, handle: JobHandle, sources: tuple[str, ...]) -> dict[str, int]:
    _take_rerun(db)  # этот проход и так прочитает всё
    counts = _sync_pass(db, handle, sources)
    while _take_rerun(db):
        counts = _sync_pass(db, handle, sources)
    reconcile_findings(db, f"синхронизация, задача #{handle.id}")
    return counts


def _sync_pass(db: Session, handle: JobHandle, sources: tuple[str, ...]) -> dict[str, int]:
    """Читает источники, для каждого наблюдения — match → upsert asset_observation → пересчёт
    актива; пропавшим ставит gone_at. Возвращает число наблюдений по источникам и, если среди
    источников AD или KSC, — число пользователей (`users`)."""
    from api.settings import get_settings

    data_dir = get_settings().data_dir
    now = utcnow()
    _migrate_ksc_keys(db)
    index = MatchIndex.load(db)
    rows = {(r.source, r.source_key): r for r in db.execute(select(AssetObservation)).scalars()}
    networks = load_networks(db)
    ad_cache: AdExportCache = {}
    counts: dict[str, int] = {}
    for source in sources:
        found, complete = _read(db, source, data_dir, ad_cache)
        handle.stage("sync", total=len(found), message=f"{SOURCE_TITLES.get(source, source)}: хостов {len(found)}")
        seen: set[str] = set()
        for i, obs in enumerate(found, start=1):
            # Один ключ дважды (два одинаковых хоста в выгрузке VM) — берётся первый.
            if obs.source_key in seen:
                continue
            seen.add(obs.source_key)
            apply_observation(db, obs, index=index, rows=rows, networks=networks)
            if i % TICK_EVERY == 0:
                handle.tick(i)
        if complete:
            touched: set[int] = set()
            for (src, key), row in rows.items():
                if src == source and key not in seen and row.gone_at is None:
                    row.gone_at = now
                    touched.add(row.asset_id)
                    if (row.extra or {}).get("users_collected"):
                        row.extra = {**row.extra, "users_collected": False}  # хоста в KSC нет — и пользователей
            db.flush()
            # Наблюдения задетых активов группируются одним проходом: перебор всех строк
            # на каждый актив был бы квадратичным на тысячах пропавших хостов.
            per_asset: dict[int, list[AssetObservation]] = defaultdict(list)
            for row in rows.values():
                if row.asset_id in touched:
                    per_asset[row.asset_id].append(row)
            for asset_id in sorted(touched):
                asset = db.get(Asset, asset_id)
                if asset is not None:
                    recompute(db, asset, networks)
                    index.put(asset, [observed(r, extra={}) for r in per_asset[asset_id]])
        db.commit()
        counts[source] = len(seen)
    # Пользователи — последним шагом: связям с хостами нужны уже сопоставленные активы.
    # Сбой шага не ломает проход: хосты уже записаны, сверка находок и повторный проход идут дальше.
    if "ad" in sources or "ksc" in sources:
        try:
            counts["users"] = sync_users(db, handle, data_dir, now, ad_cache)["users"]
            db.commit()
        except JobCancelled:
            raise
        except Exception:
            db.rollback()
            log.exception("синхронизация пользователей не удалась, хосты синхронизированы")
            counts[USERS_FAILED] = 1
    return counts


def sync_status(db: Session) -> dict[str, Any]:
    """Время последней синхронизации и что сейчас лежит по каждому источнику."""
    last = db.execute(
        select(AssetJob).where(AssetJob.kind == "sync", AssetJob.status == "done").order_by(AssetJob.finished_at.desc(), AssetJob.id.desc())
    ).scalars().first()
    running = active_job(db, AssetJob, ("sync",))
    per_source: dict[str, dict[str, Any]] = {s: {"live": 0, "gone": 0, "seen_at": None} for s in SYNC_SOURCES}
    stmt = select(
        AssetObservation.source,
        func.count().filter(AssetObservation.gone_at.is_(None)),
        func.count().filter(AssetObservation.gone_at.is_not(None)),
        func.max(AssetObservation.seen_at),
    ).group_by(AssetObservation.source)
    for source, live, gone, seen_at in db.execute(stmt).tuples():
        per_source[source] = {"live": int(live), "gone": int(gone), "seen_at": seen_at.isoformat() if seen_at else None}
    return {
        "last_sync_at": last.finished_at.isoformat() if last and last.finished_at else None,
        "last_job_id": last.id if last else None,
        "running_job_id": running.id if running else None,
        "sources": per_source,
    }
