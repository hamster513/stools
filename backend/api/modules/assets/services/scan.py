"""Задача скана сети (спека §3): сканер → наблюдения `scan`, `gone_at` не ответившим,
итог в сети; что скан знает об адресе — для расхождений «не отвечает» и «запись DNS без хоста».

Одновременно идёт один скан на весь модуль: сканы делят сетевой стек контейнера API, а
планировщик просто подождёт следующего тика.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import threading
import time
from collections.abc import Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.jobs import JobCancelled, JobHandle, active_job, run_job, start_job
from api.modules.assets.core import dns as dns_core
from api.modules.assets.core import scanner
from api.modules.assets.core.matching import Observed, normalize_fqdn, normalize_name
from api.modules.assets.models import Asset, AssetDns, AssetJob, AssetObservation, Network
from api.modules.assets.services.assets import apply_observation, recompute
from api.modules.assets.services.networks import load_networks, scan_target
from api.modules.assets.services.sync import sync_lock
from api.platform.scheduler import PlatformSchedule
from api.timeutil import utcnow

log = logging.getLogger("stools.assets")

#: Кто запустил скан по расписанию: человека у задачи нет.
SCHEDULE_STARTED_BY = "расписание"
#: Прогресс и проверка отмены пишут в базу — не чаще раза в столько секунд.
REPORT_EVERY_S = 1.0
PORTS_ONLY = "ICMP недоступен — только порты"


class ScanBusy(Exception):
    """Уже идёт скан."""


class ScanDisabled(Exception):
    """У сети выключено сканирование."""


def _in_thread(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, name="stools-assets-scan", daemon=True).start()


#: Как задача уходит из запроса или тика планировщика: те её не ждут. Тесты подменяют на вызов на месте.
spawn: Callable[[Callable[[], None]], None] = _in_thread

#: Проверка «скан не идёт» и создание задачи — одним шагом: два запроса подряд не запустят два скана.
_start_lock = threading.Lock()


def start_scan(db: Session, network: Network, started_by: str) -> int:
    """Создать задачу скана сети и отправить её в поток. ScanBusy — идёт другой скан,
    ScanDisabled — у сети выключено сканирование."""
    if not network.scan_enabled:
        raise ScanDisabled(f"сканирование сети {network.cidr} выключено — включите его в форме сети")
    network_id = network.id
    with _start_lock:
        running = active_job(db, AssetJob, ("scan",))
        if running is not None:
            raise ScanBusy(f"идёт скан #{running.id} ({running.message}), дождитесь его")
        job_id = start_job(db, AssetJob, "scan", started_by, message=f"сеть {network.cidr}")
    spawn(lambda: run_job(AssetJob, job_id, lambda s, h: run_scan(s, h, network_id)))
    return job_id


def schedule_handler(db: Session, schedule: PlatformSchedule) -> int | None:
    """Обработчик планировщика `assets/scan`: None — идёт другой скан или у сети выключено
    сканирование (строка в лог); планировщик попробует на следующем тике."""
    network = db.get(Network, schedule.target_id)
    if network is None:
        raise LookupError(f"сеть {schedule.target_id} расписания {schedule.id} не найдена")
    try:
        return start_scan(db, network, SCHEDULE_STARTED_BY)
    except ScanBusy:
        return None
    except ScanDisabled as exc:
        log.warning("расписание %s пропущено: %s", schedule.id, exc)
        return None


def _observation(host: scanner.HostResult, seen_at: Any) -> Observed:
    fqdn = normalize_fqdn(host.ptr)
    name, domain = normalize_name(host.ptr)
    hint = scanner.os_hint(host.ttl)
    return Observed(
        source="scan", source_key=host.ip, name=name, fqdn=fqdn, domain=domain, ip=host.ip, seen_at=seen_at,
        extra={"ports": list(host.ports), "ttl": host.ttl, "rtt_ms": host.rtt_ms, "icmp": host.icmp,
               "os_hint": hint, "os_hint_by_ttl": bool(hint)},
    )


def ptr_resolver(db: Session) -> scanner.Resolver | None:
    """PTR через первый включённый DNS-сервер `direct` (спека §3 п.3); такого нет — None,
    и сканер спрашивает системный резолвер."""
    row = db.execute(
        select(AssetDns).where(AssetDns.enabled.is_(True), AssetDns.mode == "direct").order_by(AssetDns.id)
    ).scalars().first()
    if row is None:
        return None
    try:
        server = dns_core.server_address(row.server.strip()) if row.server.strip() else None
    except dns_core.DnsError:
        return None
    timeout = row.timeout_ms / 1000

    async def resolve(ip: str) -> str:
        try:
            return await asyncio.to_thread(dns_core.resolve_ptr, ip, server, timeout)
        except dns_core.DnsError:
            return ""

    return resolve


def run_scan(db: Session, handle: JobHandle, network_id: int) -> None:
    """scanner.scan → наблюдения scan (apply_observation), gone_at не ответившим адресам цели,
    network.last_scan_at/last_scan_alive. Без ICMP-сокета — режим «только порты» (extra.icmp = None).

    Пока идёт скан, сессия задачи не держит открытую транзакцию. Запись результатов — под той же
    блокировкой, что синхронизация (обе заводят активы: параллельно завели бы один хост дважды),
    и по свежей строке сети: правка сети за время скана не теряется, а если сеть удалили —
    результаты отбрасываются."""
    network = db.get(Network, network_id)
    if network is None:
        raise LookupError("сеть удалена")
    target = scan_target(network)
    cidr = network.cidr
    scanned = set(scanner.addresses(target, scanner.own_addresses()))
    use_icmp = scanner.icmp_available()
    mode = "" if use_icmp else f" · {PORTS_ONLY}"
    handle.stage("scan", total=len(scanned), message=f"сеть {cidr}: адресов {len(scanned)}{mode}")
    started = utcnow()
    resolver = ptr_resolver(db)
    db.commit()

    last = [0.0, 0.0]  # когда писали прогресс и проверяли отмену

    def on_progress(done: int, total: int) -> None:
        now = time.monotonic()
        if done == total or now - last[0] >= REPORT_EVERY_S:
            last[0] = now
            handle.report_progress(done, total, f"сеть {cidr}: {done} из {total}{mode}")

    def cancelled() -> bool:
        now = time.monotonic()
        if now - last[1] < REPORT_EVERY_S:
            return False
        last[1] = now
        try:
            return handle.cancelled()
        finally:
            db.commit()  # чтение флага не оставляет транзакцию открытой до конца скана

    try:
        found = asyncio.run(scanner.scan(target, on_progress=on_progress, cancelled=cancelled, use_icmp=use_icmp, resolver=resolver))
    except scanner.ScanCancelled:
        raise JobCancelled() from None

    with sync_lock(db, wait=True):
        current = db.get(Network, network_id, with_for_update=True, populate_existing=True)
        if current is None:
            db.rollback()
            handle.stage("done", message=f"сеть {cidr} удалена во время скана — результаты не записаны")
            return
        alive = set()
        for host in found:
            apply_observation(db, _observation(host, started))
            alive.add(host.ip)
        previous = db.execute(
            select(AssetObservation).where(AssetObservation.source == "scan", AssetObservation.gone_at.is_(None))
        ).scalars().all()
        touched = set()
        for row in previous:
            if row.ip in scanned and row.ip not in alive:
                row.gone_at = started
                touched.add(row.asset_id)
        db.flush()
        networks = load_networks(db)
        for asset_id in sorted(touched):
            asset = db.get(Asset, asset_id)
            if asset is not None:
                recompute(db, asset, networks)
        current.last_scan_at = started
        current.last_scan_alive = len(found)
        db.commit()
    gone = f" · пропало {len(touched)}" if touched else ""
    handle.stage("done", message=f"сеть {cidr}: живых {len(found)} из {len(scanned)}{gone}{mode}")


# ---- Что скан знает об адресе ----------------------------------------------


ScanProbes = tuple[Callable[[str], bool], Callable[[str], bool | None]]


def scan_probes(db: Session) -> ScanProbes:
    """(адрес в сети, которую уже сканировали; ответил ли он последнему скану — None, если не сканировался).
    Живой — есть наблюдение scan без gone_at: каждый скан снимает его с не ответивших адресов."""
    scanned: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]] = []
    for cidr, exclude in db.execute(select(Network.cidr, Network.exclude).where(Network.last_scan_at.is_not(None))):
        try:
            scanned.append((ipaddress.ip_network(cidr, strict=False), [ipaddress.ip_network(e, strict=False) for e in exclude or []]))
        except ValueError:
            continue
    live = set()
    if scanned:
        for ip in db.execute(
            select(AssetObservation.ip).where(AssetObservation.source == "scan", AssetObservation.gone_at.is_(None))
        ).scalars():
            try:
                live.add(ipaddress.ip_address(ip))
            except ValueError:
                continue

    def covered(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(
            addr.version == net.version and addr in net and not any(addr.version == x.version and addr in x for x in excl)
            for net, excl in scanned
        )

    def alive(ip: str) -> bool | None:
        if not covered(ip):
            return None
        return ipaddress.ip_address(ip) in live

    return covered, alive
