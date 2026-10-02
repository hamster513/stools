"""Задача DNS (спека §4): прямые и обратные запросы к серверу `direct`, чтение AD-integrated зон
через подключение AD → наблюдения `dns`; имена и адреса, которых DNS больше не знает, — `gone_at`.

Одновременно идёт одна задача DNS на модуль: обновления пишут одни и те же наблюдения, а
планировщик подождёт следующего тика. Таймаут — не «имени нет»: наблюдение остаётся живым.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import functools
import ipaddress
import logging
import math
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.jobs import JobCancelled, JobHandle, active_job, run_job, start_job
from api.modules.ad.core.ldap_collector import Pacer, ldap3_searcher
from api.modules.ad.models import AdConnection
from api.modules.ad.services import connections as ad_connections
from api.modules.assets.core import dns as dns_core
from api.modules.assets.core.dns import (
    TYPE_A,
    TYPE_AAAA,
    Answer,
    DnsError,
    DnsRecord,
    RateLimiter,
    read_ad_zone,
)
from api.modules.assets.core.matching import Observed, normalize_fqdn, normalize_ip, normalize_name
from api.modules.assets.findings_adapter import reconcile as reconcile_findings
from api.modules.assets.models import Asset, AssetDns, AssetJob, AssetObservation
from api.modules.assets.services.assets import apply_observation, recompute
from api.modules.assets.services.networks import load_networks
from api.modules.assets.services.sync import sync_lock
from api.platform.scheduler import PlatformSchedule
from api.timeutil import utcnow

log = logging.getLogger("stools.assets")

SCHEDULE_STARTED_BY = "расписание"
#: Прогресс и проверка отмены пишут в базу — не чаще раза в столько секунд.
REPORT_EVERY_S = 1.0
#: Столько ошибок без единого ответа — сервер недоступен: задача падает, а не ждёт таймаут на каждом имени.
DEAD_AFTER = 5
#: Прогресс записи — раз в столько наблюдений.
WRITE_REPORT_EVERY = 200


class DnsBusy(Exception):
    """Уже идёт задача DNS."""


class DnsDisabled(Exception):
    """DNS-сервер выключен."""


def _in_thread(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, name="stools-assets-dns", daemon=True).start()


#: Как задача уходит из запроса или тика планировщика. Тесты подменяют на вызов на месте.
spawn: Callable[[Callable[[], None]], None] = _in_thread

_start_lock = threading.Lock()


def label(row: AssetDns) -> str:
    if row.mode == "ad":
        return row.title or f"зоны AD {', '.join(row.zones or [])}"
    return row.title or row.server or "системный резолвер"


def start_dns(db: Session, row: AssetDns, started_by: str) -> int:
    """Создать задачу DNS и отправить её в поток. DnsBusy — идёт другая, DnsDisabled — сервер выключен."""
    if not row.enabled:
        raise DnsDisabled(f"DNS-сервер «{label(row)}» выключен — включите его в форме")
    dns_id = row.id
    with _start_lock:
        running = active_job(db, AssetJob, ("dns",))
        if running is not None:
            raise DnsBusy(f"идёт обновление DNS #{running.id} ({running.message}), дождитесь его")
        job_id = start_job(db, AssetJob, "dns", started_by, message=label(row))

    def work(s: Session, h: JobHandle) -> None:
        run_dns(s, h, dns_id)

    spawn(lambda: run_job(AssetJob, job_id, work))
    return job_id


def schedule_handler(db: Session, schedule: PlatformSchedule) -> int | None:
    """Обработчик планировщика `assets/dns`: None — идёт другая задача DNS или сервер выключен
    (строка в лог); планировщик попробует на следующем тике."""
    row = db.get(AssetDns, schedule.target_id)
    if row is None:
        raise LookupError(f"DNS-сервер {schedule.target_id} расписания {schedule.id} не найден")
    try:
        return start_dns(db, row, SCHEDULE_STARTED_BY)
    except DnsBusy:
        return None
    except DnsDisabled as exc:
        log.warning("расписание %s пропущено: %s", schedule.id, exc)
        return None


def estimate(queries: int, rate_per_s: int) -> str:
    """Оценка длительности запросов по темпу — нижняя граница: таймауты в неё не входят."""
    minutes = max(1, math.ceil(queries / max(1, rate_per_s) / 60))
    return f"~{queries} запросов при {rate_per_s}/с ≈ {minutes} мин"


@dataclass(slots=True)
class _Settings:
    """Настройка на момент запуска: строку могут поменять или удалить, пока идут запросы."""

    id: int
    label: str
    mode: str
    server: str
    ad_connection_id: int | None
    zones: list[str]
    forward: bool
    reverse: bool
    zone_read: bool
    rate_per_s: int
    timeout: float

    @classmethod
    def of(cls, row: AssetDns) -> _Settings:
        return cls(
            id=row.id, label=label(row), mode=row.mode, server=row.server.strip(), ad_connection_id=row.ad_connection_id,
            zones=list(row.zones or []), forward=row.forward, reverse=row.reverse, zone_read=row.zone_read,
            rate_per_s=row.rate_per_s, timeout=row.timeout_ms / 1000,
        )


class _Run:
    """Одна задача: сначала запросы (без открытой транзакции), потом запись всего найденного разом."""

    def __init__(self, db: Session, handle: JobHandle, cfg: _Settings, started: dt.datetime) -> None:
        self.db = db
        self.handle = handle
        self.cfg = cfg
        self.started = started
        self.counts = {"forward": 0, "forward_found": 0, "reverse": 0, "reverse_found": 0, "zone": 0, "gone": 0, "errors": 0}
        self.answered = 0
        #: Что записать: наблюдения, ключи (FQDN или IP), которых DNS больше не знает, и имена каждой прочитанной зоны.
        self.found: list[Observed] = []
        self.missing: list[str] = []
        self.zone_hosts: dict[str, set[str]] = {}
        self._last = [0.0, 0.0]

    def phase(self, name: str, total: int, message: str) -> None:
        self.handle.stage(name, total=total, message=message)
        self._last = [0.0, 0.0]

    def step(self, done: int, total: int, message: str) -> None:
        now = time.monotonic()
        if done == total or now - self._last[0] >= REPORT_EVERY_S:
            self._last[0] = now
            self.handle.report_progress(done, total, message)
        if now - self._last[1] >= REPORT_EVERY_S:
            self._last[1] = now
            if self.handle.cancelled():
                raise JobCancelled()
            self.db.commit()  # чтение флага не оставляет транзакцию открытой на время запросов

    def ask(self, fn: Callable[[str, str | None, float], Answer], what: str, server: str | None) -> Answer | None:
        """Ответ или None (ошибка сервера: про имя ничего не известно)."""
        try:
            answer = fn(what, server, self.cfg.timeout)
        except DnsError:
            self.counts["errors"] += 1
            if not self.answered and self.counts["errors"] >= DEAD_AFTER:
                raise DnsError(
                    f"DNS-сервер {self.cfg.server or 'системного резолвера'} не отвечает: {self.counts['errors']} запросов без ответа"
                ) from None
            return None
        self.answered += 1
        return answer


def _ip_order(ip: str) -> tuple[int, int]:
    addr = ipaddress.ip_address(ip)
    return addr.version, int(addr)


def known_names(db: Session) -> list[str]:
    """Канонические FQDN активов и FQDN живых наблюдений."""
    names = set(db.execute(select(Asset.fqdn).where(Asset.merged_into.is_(None), Asset.fqdn != "")).scalars())
    names |= set(db.execute(
        select(AssetObservation.fqdn).where(AssetObservation.gone_at.is_(None), AssetObservation.fqdn != "")
    ).scalars())
    return sorted({n for n in (normalize_fqdn(x) for x in names) if n})


def known_ips(db: Session) -> list[str]:
    """Канонические IP активов и IP живых наблюдений — среди них и ответившие последнему скану."""
    ips = set(db.execute(select(Asset.ip).where(Asset.merged_into.is_(None), Asset.ip != "")).scalars())
    ips |= set(db.execute(select(AssetObservation.ip).where(AssetObservation.gone_at.is_(None), AssetObservation.ip != "")).scalars())
    return sorted({a for a in (normalize_ip(x) for x in ips) if a}, key=_ip_order)


def _extra(record_type: str, ttl: int | None, stamp: dt.datetime | None, server: str, **more: Any) -> dict[str, Any]:
    return {"record_type": record_type, "ttl": ttl, "record_timestamp": stamp.isoformat() if stamp else None, "server": server, **more}


def _forward(run: _Run, names: list[str], server: str | None, rate: RateLimiter, est: str) -> None:
    run.phase("forward", len(names), f"прямые запросы: имён {len(names)} · {est}")
    lookup = functools.partial(dns_core.lookup_a, before=rate.wait)  # A и AAAA — два запроса темпа
    for i, name in enumerate(names, 1):
        answer = run.ask(lookup, name, server)
        run.counts["forward"] += 1
        if answer is not None and answer.values:
            short, domain = normalize_name(name)
            run.found.append(Observed(
                source="dns", source_key=name, name=short, fqdn=name, domain=domain, ip=answer.values[0], ips=list(answer.values),
                seen_at=run.started, extra=_extra(answer.record_type, answer.ttl, None, run.cfg.server),
            ))
            run.counts["forward_found"] += 1
        elif answer is not None:
            run.missing.append(name)
        run.step(i, len(names), f"прямые запросы: {i} из {len(names)}")


def _reverse(run: _Run, ips: list[str], server: str | None, rate: RateLimiter, est: str) -> None:
    run.phase("reverse", len(ips), f"обратные запросы: адресов {len(ips)} · {est}")
    lookup = functools.partial(dns_core.lookup_ptr, before=rate.wait)
    for i, ip in enumerate(ips, 1):
        answer = run.ask(lookup, ip, server)
        run.counts["reverse"] += 1
        if answer is not None and answer.values:
            ptr = answer.values[0]
            short, domain = normalize_name(ptr)
            run.found.append(Observed(
                source="dns", source_key=ip, name=short, fqdn=normalize_fqdn(ptr), domain=domain, ip=ip,
                seen_at=run.started, extra=_extra("PTR", answer.ttl, None, run.cfg.server),
            ))
            run.counts["reverse_found"] += 1
        elif answer is not None:
            run.missing.append(ip)
        run.step(i, len(ips), f"обратные запросы: {i} из {len(ips)}")


def _read_zones(run: _Run) -> tuple[str, dict[str, dict[str, list[DnsRecord]]]]:
    """Записи всех зон настройки: {зона: {FQDN: записи}}; соединение закрывается до записи в базу."""
    conn = run.db.get(AdConnection, run.cfg.ad_connection_id) if run.cfg.ad_connection_id is not None else None
    if conn is None:
        raise LookupError("подключение AD этого DNS-сервера удалено — выберите другое в форме")
    host, base_dn, page_size, pause_ms = conn.host, conn.base_dn, conn.page_size, conn.pause_ms
    run.phase("connecting", 0, host)

    def check_cancel() -> None:
        if run.handle.cancelled():
            raise JobCancelled()
        run.db.commit()

    c = ad_connections.ldap3_connection(conn)
    run.db.commit()
    try:
        domain_dn = ad_connections.root_dse_of(c, base_dn)["defaultNamingContext"]
        # Тот же дозатор, что у сборщика AD: пауза подключения между запросами к контроллеру.
        searcher = ldap3_searcher(c, page_size=page_size, pacer=Pacer(pause_ms, check_cancel=check_cancel))
        zones: dict[str, dict[str, list[DnsRecord]]] = {}
        for zone in run.cfg.zones:
            run.phase("zone", 0, f"зона {zone}")
            records: dict[str, list[DnsRecord]] = defaultdict(list)
            for fqdn, record in read_ad_zone(searcher, domain_dn, zone):
                records[fqdn].append(record)
            zones[zone] = records
    finally:
        with contextlib.suppress(Exception):
            c.unbind()
    return host, zones


def _zones(run: _Run) -> None:
    host, zones = _read_zones(run)
    for zone, records in zones.items():
        # CNAME без адреса — псевдоним, а не хост: отдельный актив он не заводит.
        hosts = {fqdn: [r for r in recs if r.type in (TYPE_A, TYPE_AAAA)] for fqdn, recs in records.items()}
        hosts = {fqdn: recs for fqdn, recs in hosts.items() if recs}
        for fqdn, recs in sorted(hosts.items()):
            ips = sorted({normalize_ip(r.value) for r in recs}, key=_ip_order)
            stamps = [r.timestamp for r in recs if r.timestamp]
            stamp = max(stamps) if stamps else None
            short, domain = normalize_name(fqdn)
            run.found.append(Observed(
                source="dns", source_key=fqdn, name=short, fqdn=fqdn, domain=domain, ip=ips[0], ips=ips,
                # Штамп динамической записи — когда хост сам обновил запись; у статической его нет.
                seen_at=stamp or run.started,
                extra=_extra("A" if any(r.type == TYPE_A for r in recs) else "AAAA", min(r.ttl for r in recs), stamp, host, zone=zone),
            ))
            run.counts["zone"] += 1
        run.zone_hosts[zone] = set(hosts)


def _write(run: _Run) -> bool:
    """Найденное — наблюдениями, пропавшее — gone_at; под той же блокировкой, что синхронизация и
    запись скана (все они заводят активы). False — настройку удалили, пока шли запросы."""
    db = run.db
    with sync_lock(db, wait=True):
        row = db.get(AssetDns, run.cfg.id, populate_existing=True)
        if row is None:
            db.rollback()
            return False
        run.phase("write", len(run.found), f"запись: наблюдений {len(run.found)}")
        networks = load_networks(db)
        for i, obs in enumerate(run.found, 1):
            apply_observation(db, obs, networks=networks)
            # Без проверки отмены и фиксации: запись — одним шагом.
            if i % WRITE_REPORT_EVERY == 0:
                run.handle.report_progress(i, len(run.found), f"запись: {i} из {len(run.found)}")
        live = list(db.execute(
            select(AssetObservation).where(AssetObservation.source == "dns", AssetObservation.gone_at.is_(None))
        ).scalars())
        missing = set(run.missing)
        touched = set()
        for o in live:
            zone = (o.extra or {}).get("zone")
            if o.source_key in missing or (zone in run.zone_hosts and o.source_key not in run.zone_hosts[zone]):
                o.gone_at = run.started
                touched.add(o.asset_id)
                run.counts["gone"] += 1
        db.flush()
        for asset_id in sorted(touched):
            asset = db.get(Asset, asset_id)
            if asset is not None:
                recompute(db, asset, networks)
        row.last_run_at = run.started
        db.commit()
        reconcile_findings(db, f"DNS {run.cfg.label}, задача #{run.handle.id}")
    return True


def summary(cfg: _Settings, counts: dict[str, int]) -> str:
    parts = []
    if cfg.mode == "ad":
        parts.append(f"из зон {counts['zone']}")
    else:
        if cfg.forward:
            parts.append(f"прямых {counts['forward']} · найдено {counts['forward_found']}")
        if cfg.reverse:
            parts.append(f"обратных {counts['reverse']} · имён {counts['reverse_found']}")
    if counts["gone"]:
        parts.append(f"пропало {counts['gone']}")
    if counts["errors"]:
        parts.append(f"ошибок {counts['errors']}")
    return f"{cfg.label}: " + " · ".join(parts)


def run_dns(db: Session, handle: JobHandle, dns_id: int) -> dict[str, int]:
    """forward/reverse/zone по настройке → наблюдения dns; пропавшие имена и адреса — gone_at; счётчики.

    Запросы идут без открытой транзакции, запись — одним шагом в конце под блокировкой синхронизации:
    отмена во время запросов ничего не записывает."""
    row = db.get(AssetDns, dns_id)
    if row is None:
        raise LookupError("DNS-сервер удалён")
    cfg = _Settings.of(row)
    run = _Run(db, handle, cfg, utcnow())
    if cfg.mode == "ad":
        if cfg.zone_read:
            _zones(run)
    else:
        names = known_names(db) if cfg.forward else []
        ips = known_ips(db) if cfg.reverse else []
        db.commit()
        # Имя сервера разрешается один раз на задачу, а не на каждый запрос.
        server = dns_core.server_address(cfg.server) if cfg.server else None
        rate = RateLimiter(cfg.rate_per_s)
        # На имя — A и AAAA (AAAA не спрашивается, если имени нет), на адрес — PTR.
        est = estimate(2 * len(names) + len(ips), cfg.rate_per_s)
        if cfg.forward:
            _forward(run, names, server, rate, est)
        if cfg.reverse:
            _reverse(run, ips, server, rate, est)
    if not _write(run):
        handle.stage("done", message=f"{cfg.label}: настройку удалили во время запросов — результаты не записаны")
        return run.counts
    handle.stage("done", message=summary(cfg, run.counts))
    return run.counts
