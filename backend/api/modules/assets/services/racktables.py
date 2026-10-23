"""Задача RackTables (спека 2026-10-13): сети из `listCells(ipv4net)` → сети Assets, имена
адресов из `getIPAddressList` по каждой сети → наблюдения `rt`; адреса, пропавшие из
RackTables или потерявшие имя, — `gone_at`.

Одна задача RackTables одновременно. Запросы идут без открытой транзакции, запись — одним
шагом под блокировкой синхронизации.
"""
from __future__ import annotations

import datetime as dt
import logging
import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.crypto import decrypt
from api.jobs import JobCancelled, JobHandle, active_job, run_job, start_job
from api.modules.assets.core.dns import RateLimiter
from api.modules.assets.core.matching import Observed, normalize_name
from api.modules.assets.core.racktables import Client, RtAddress, RtError, RtNetwork, narrowest
from api.modules.assets.findings_adapter import reconcile as reconcile_findings
from api.modules.assets.models import (
    Asset,
    AssetJob,
    AssetObservation,
    AssetRacktables,
    Network,
)
from api.modules.assets.services.assets import apply_observation, recompute
from api.modules.assets.services.networks import apply_zone_rules, load_networks, reassign_assets
from api.modules.assets.services.sync import sync_lock
from api.platform.scheduler import PlatformSchedule
from api.timeutil import utcnow

log = logging.getLogger("stools.assets")

SCHEDULE_STARTED_BY = "расписание"
ORIGIN = "racktables"
REPORT_EVERY_S = 1.0
#: Столько ошибок подряд без единого ответа — API недоступен: задача падает, а не ждёт таймауты.
DEAD_AFTER = 5
WRITE_REPORT_EVERY = 200


class RtBusy(Exception):
    """Уже идёт задача RackTables."""


class RtDisabled(Exception):
    """Подключение выключено."""


def _in_thread(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, name="stools-assets-rt", daemon=True).start()


#: Как задача уходит из запроса или тика планировщика. Тесты подменяют на вызов на месте.
spawn: Callable[[Callable[[], None]], None] = _in_thread

_start_lock = threading.Lock()


def label(row: AssetRacktables) -> str:
    return row.title or row.url


def client(row: AssetRacktables, *, before: Callable[[], None] | None = None) -> Client:
    return Client(row.url, row.username, decrypt(row.password), verify=row.verify_tls, timeout=row.timeout_ms / 1000, before=before)


def start_rt(db: Session, row: AssetRacktables, started_by: str) -> int:
    """Создать задачу и отправить её в поток. RtBusy — идёт другая, RtDisabled — подключение выключено."""
    if not row.enabled:
        raise RtDisabled(f"подключение RackTables «{label(row)}» выключено — включите его в форме")
    rt_id = row.id
    with _start_lock:
        running = active_job(db, AssetJob, ("rt",))
        if running is not None:
            raise RtBusy(f"идёт проход RackTables #{running.id} ({running.message}), дождитесь его")
        job_id = start_job(db, AssetJob, "rt", started_by, message=label(row))

    def work(s: Session, h: JobHandle) -> None:
        run_rt(s, h, rt_id)

    spawn(lambda: run_job(AssetJob, job_id, work))
    return job_id


def schedule_handler(db: Session, schedule: PlatformSchedule) -> int | None:
    """Обработчик планировщика `assets/rt`: None — идёт другая задача или подключение выключено."""
    row = db.get(AssetRacktables, schedule.target_id)
    if row is None:
        raise LookupError(f"подключение RackTables {schedule.target_id} расписания {schedule.id} не найдено")
    try:
        return start_rt(db, row, SCHEDULE_STARTED_BY)
    except RtBusy:
        return None
    except RtDisabled as exc:
        log.warning("расписание %s пропущено: %s", schedule.id, exc)
        return None


def estimate(queries: int, rate_per_s: int) -> str:
    minutes = max(1, math.ceil(queries / max(1, rate_per_s) / 60))
    return f"~{queries} запросов при {rate_per_s}/с ≈ {minutes} мин"


@dataclass(slots=True)
class _Settings:
    """Настройка на момент запуска: строку могут поменять или удалить, пока идут запросы."""

    id: int
    label: str
    rate_per_s: int

    @classmethod
    def of(cls, row: AssetRacktables) -> _Settings:
        return cls(id=row.id, label=label(row), rate_per_s=row.rate_per_s)


class _Run:
    def __init__(self, db: Session, handle: JobHandle, cfg: _Settings, started: dt.datetime) -> None:
        self.db = db
        self.handle = handle
        self.cfg = cfg
        self.started = started
        self.counts = {
            "networks": 0, "networks_new": 0, "networks_updated": 0, "networks_manual": 0, "networks_wide": 0,
            "addresses": 0, "gone": 0, "errors": 0,
        }
        self.answered = 0
        self.networks: list[RtNetwork] = []
        self.found: list[Observed] = []
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

    def addresses(self, api: Client, network: RtNetwork) -> list[RtAddress] | None:
        """Адреса сети или None — ошибка запроса (про сеть ничего не известно)."""
        try:
            got = api.addresses(network)
        except RtError as exc:
            self.counts["errors"] += 1
            if not self.answered and self.counts["errors"] >= DEAD_AFTER:
                raise RtError(f"RackTables не отвечает: {self.counts['errors']} запросов без ответа, последняя ошибка — {exc}") from None
            log.warning("RackTables: сеть %s не прочитана: %s", network.cidr, exc)
            return None
        self.answered += 1
        return got


def _observed(run: _Run, network: RtNetwork, a: RtAddress) -> Observed:
    short, domain = normalize_name(a.name)
    return Observed(
        source="rt", source_key=a.ip, name=short, fqdn=a.name.lower().rstrip(".") if "." in a.name else "", domain=domain, ip=a.ip,
        seen_at=run.started,
        extra={"comment": a.comment, "reserved": a.reserved, "network": network.cidr, "network_name": network.name, "vlan": network.vlan},
    )


def _collect(run: _Run, api: Client) -> None:
    run.phase("networks", 0, "список сетей")
    run.networks = narrowest(api.networks())
    run.answered += 1
    run.counts["networks"] = len(run.networks)
    # Контейнеры шире /16 в Assets не создаются, а запрос адресов по ним — самый тяжёлый для базы RackTables
    # (диапазон на миллионы адресов); их адреса почти всегда лежат в дочерних сетях.
    asked = [n for n in run.networks if not n.too_wide]
    total = len(asked)
    run.phase("addresses", total, f"адреса сетей: {total} · {estimate(total, run.cfg.rate_per_s)}")
    seen: set[str] = set()
    for i, network in enumerate(asked, 1):
        got = run.addresses(api, network)
        for a in got or []:
            # Адрес родительской сети повторяет адрес дочерней: остаётся самая узкая (сети идут от узких).
            if a.ip in seen:
                continue
            seen.add(a.ip)
            run.found.append(_observed(run, network, a))
        run.counts["addresses"] = len(run.found)
        run.step(i, total, f"адреса сетей: {i} из {total} · имён {len(run.found)}")


def _upsert_networks(db: Session, run: _Run) -> None:
    """Сети RT → сети Assets: новые создаются, свои обновляются (название, описание, VLAN, явные и
    унаследованные теги, дата импорта), описанные вручную с тем же CIDR не трогаются, шире /16 пропускаются.
    Группы своих сетей — по правилам (ручную группу правила не трогают); не подошло ни одно — публичная
    сеть получает External (`zone_source="racktables"`)."""
    mine = {n.origin_key: n for n in db.execute(select(Network).where(Network.origin == ORIGIN)).scalars()}
    by_cidr = {n.cidr: n for n in db.execute(select(Network)).scalars()}
    for net in run.networks:
        if net.too_wide:
            run.counts["networks_wide"] += 1
            continue
        row = mine.get(net.rt_id)
        if row is None and net.cidr in by_cidr:
            run.counts["networks_manual"] += 1
            continue
        if row is None:
            row = Network(cidr=net.cidr, origin=ORIGIN, origin_key=net.rt_id, scan_enabled=False)
            db.add(row)
            by_cidr[net.cidr] = row
            run.counts["networks_new"] += 1
        elif row.cidr != net.cidr and net.cidr in by_cidr:
            # CIDR сменился в RT на занятый другой сетью: оставляем старый, чтобы не ломать уникальность.
            run.counts["networks_manual"] += 1
            continue
        else:
            run.counts["networks_updated"] += 1
        row.cidr, row.title, row.description, row.vlan = net.cidr, net.name, net.comment, net.vlan
        row.tags, row.implicit_tags, row.origin_seen_at = list(net.explicit_tags), list(net.implicit_tags), run.started
    db.flush()
    apply_zone_rules(db, origin=ORIGIN)
    reassign_assets(db)


def _write(run: _Run) -> bool:
    """Сети, наблюдения и пропавшие — под той же блокировкой, что синхронизация и запись скана.
    False — подключение удалили, пока шли запросы."""
    db = run.db
    with sync_lock(db, wait=True):
        row = db.get(AssetRacktables, run.cfg.id, populate_existing=True)
        if row is None:
            db.rollback()
            return False
        run.phase("write", len(run.found), f"запись: сетей {len(run.networks)}, наблюдений {len(run.found)}")
        _upsert_networks(db, run)
        networks = load_networks(db)
        for i, obs in enumerate(run.found, 1):
            apply_observation(db, obs, networks=networks)
            if i % WRITE_REPORT_EVERY == 0:
                run.handle.report_progress(i, len(run.found), f"запись: {i} из {len(run.found)}")
        present = {o.source_key for o in run.found}
        touched = set()
        for o in db.execute(select(AssetObservation).where(AssetObservation.source == "rt", AssetObservation.gone_at.is_(None))).scalars():
            if o.source_key not in present:
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
        reconcile_findings(db, f"RackTables {run.cfg.label}, задача #{run.handle.id}")
    return True


def summary(cfg: _Settings, counts: dict[str, int]) -> str:
    parts = [
        f"сетей {counts['networks']} · новых {counts['networks_new']} · обновлено {counts['networks_updated']}",
        f"имён адресов {counts['addresses']}",
    ]
    if counts["networks_manual"]:
        parts.append(f"описаны вручную {counts['networks_manual']}")
    if counts["networks_wide"]:
        parts.append(f"шире /16 пропущено {counts['networks_wide']}")
    if counts["gone"]:
        parts.append(f"пропало {counts['gone']}")
    if counts["errors"]:
        parts.append(f"ошибок {counts['errors']}")
    return f"{cfg.label}: " + " · ".join(parts)


def run_rt(db: Session, handle: JobHandle, rt_id: int) -> dict[str, int]:
    """Сети и адреса RackTables → сети Assets и наблюдения rt; пропавшие — gone_at; счётчики."""
    row = db.get(AssetRacktables, rt_id)
    if row is None:
        raise LookupError("подключение RackTables удалено")
    cfg = _Settings.of(row)
    run = _Run(db, handle, cfg, utcnow())
    rate = RateLimiter(cfg.rate_per_s)
    api = client(row, before=rate.wait)
    db.commit()
    try:
        _collect(run, api)
    finally:
        api.close()
    if not _write(run):
        handle.stage("done", message=f"{cfg.label}: подключение удалили во время запросов — результаты не записаны")
        return run.counts
    handle.stage("done", message=summary(cfg, run.counts))
    return run.counts
