"""Задача скана: наблюдения `scan`, «не отвечает», «найдено сканером», gone_at, занятость,
ручки запуска и расписания, запуск планировщиком. Сканер подменён — пакеты не уходят."""
from __future__ import annotations

import datetime as dt
import logging
import threading
import time
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from api.db.base import get_sessionmaker
from api.jobs import start_job
from api.modules.assets.core import scanner
from api.modules.assets.core.matching import Observed
from api.modules.assets.core.scanner import HostResult, ScanTarget
from api.modules.assets.models import (
    DEFAULT_ZONES,
    Asset,
    AssetJob,
    AssetObservation,
    AssetZone,
    Network,
)
from api.modules.assets.services import scan as scan_service
from api.modules.assets.services.assets import apply_observation
from api.modules.assets.services.scan import ScanBusy, schedule_handler, start_scan
from api.modules.assets.services.sync import SYNC_LOCK_KEY
from api.platform.scheduler import PlatformSchedule, tick

NOW = dt.datetime.now(dt.UTC)


@pytest.fixture(autouse=True)
def inline_spawn(monkeypatch: pytest.MonkeyPatch) -> None:
    """Задача скана уходит в поток; в тестах — на месте, иначе поток пережил бы тест."""
    monkeypatch.setattr(scan_service, "spawn", lambda fn: fn())


class FakeScan:
    """Подмена `scanner.scan`: отдаёт заданных живых, запоминает цель; `during` — что сделать
    посреди скана (правка сети другим запросом, проверка соединений)."""

    def __init__(self) -> None:
        self.alive: list[HostResult] = []
        self.targets: list[ScanTarget] = []
        self.during: Callable[[], None] | None = None

    async def __call__(self, target: ScanTarget, **kw: Any) -> list[HostResult]:
        self.targets.append(target)
        kw["cancelled"]()
        if self.during is not None:
            self.during()
        return list(self.alive)


@pytest.fixture
def fake_scan(monkeypatch: pytest.MonkeyPatch) -> FakeScan:
    fake = FakeScan()
    monkeypatch.setattr(scanner, "scan", fake)
    monkeypatch.setattr(scanner, "icmp_available", lambda: True)
    return fake


@pytest.fixture
def analyst(db_session: Session, client_as: Callable[[str], TestClient]) -> TestClient:
    for name in DEFAULT_ZONES:
        if db_session.get(AssetZone, name) is None:
            db_session.add(AssetZone(name=name, title=name, description=""))
    db_session.commit()
    return client_as("analyst")


@pytest.fixture
def network(analyst: TestClient, db_session: Session) -> Network:
    r = analyst.post("/api/assets/networks", json={"cidr": "10.10.0.0/24", "scan_enabled": True, "ports": [22, 445]})
    assert r.status_code == 201, r.text
    net = db_session.get(Network, r.json()["id"])
    assert net is not None
    return net


def host(ip: str, ptr: str = "", ttl: int | None = 128, ports: list[int] | None = None) -> HostResult:
    return HostResult(ip=ip, icmp=True, ttl=ttl, rtt_ms=0.8, ports=ports if ports is not None else [445], ptr=ptr)


def add(db: Session, source: str, name: str, ip: str, **extra: Any) -> int:
    asset, _ = apply_observation(db, Observed(source=source, source_key=f"{source}-{name or ip}", name=name, ip=ip, seen_at=NOW, extra=extra))
    db.commit()
    return asset.id


def codes(c: TestClient, code: str) -> set[str]:
    r = c.get("/api/assets/assets", params={"code": code})
    assert r.status_code == 200, r.text
    return {i["ip"] for i in r.json()["items"]}


def last_job(db: Session) -> AssetJob:
    db.expire_all()
    job = db.execute(select(AssetJob).order_by(AssetJob.id.desc())).scalars().first()
    assert job is not None
    return job


def test_scan_job_creates_observations_and_codes(analyst: TestClient, db_session: Session, network: Network, fake_scan: FakeScan) -> None:
    add(db_session, "ksc", "srv01", "10.10.0.11")  # известен, но скану не ответит
    add(db_session, "dns", "", "10.10.0.9", record_type="A")  # запись зоны без живого хоста
    add(db_session, "ksc", "ws01", "10.20.0.5")  # вне сканируемых сетей — «не отвечает» не про него
    fake_scan.alive = [host("10.10.0.5"), host("10.10.0.7", ptr="ws07.corp.local", ttl=63, ports=[22])]

    job_id = start_scan(db_session, network, "tester")
    job = last_job(db_session)
    assert job.id == job_id and job.kind == "scan" and job.status == "done", job.error
    assert "живых 2" in job.message
    assert fake_scan.targets[0].cidr == "10.10.0.0/24" and fake_scan.targets[0].ports == [22, 445]
    assert fake_scan.targets[0].icmp_timeout == 1.0 and fake_scan.targets[0].tcp_timeout == 2.0

    rows = {r.source_key: r for r in db_session.execute(select(AssetObservation).where(AssetObservation.source == "scan")).scalars()}
    assert set(rows) == {"10.10.0.5", "10.10.0.7"}
    ws07 = rows["10.10.0.7"]
    assert (ws07.name, ws07.fqdn, ws07.domain, ws07.ip, ws07.os) == ("ws07", "ws07.corp.local", "corp.local", "10.10.0.7", "")
    assert ws07.extra == {"ports": [22], "ttl": 63, "rtt_ms": 0.8, "icmp": True, "os_hint": "Linux/сетевое", "os_hint_by_ttl": True}
    assert rows["10.10.0.5"].extra["os_hint"] == "Windows"

    db_session.refresh(network)
    assert network.last_scan_alive == 2 and network.last_scan_at is not None

    assert codes(analyst, "unknown_host") == {"10.10.0.5", "10.10.0.7"}
    assert codes(analyst, "unreachable") == {"10.10.0.11"}
    assert codes(analyst, "dns_orphan") == {"10.10.0.9"}
    stats = analyst.get(f"/api/assets/networks/{network.id}").json()["stats"]
    assert stats["alive_last_scan"] == 2 and stats["unknown_hosts"] == 2


def test_known_host_answering_is_not_unreachable(analyst: TestClient, db_session: Session, network: Network, fake_scan: FakeScan) -> None:
    add(db_session, "ksc", "srv01", "10.10.0.11")
    fake_scan.alive = [host("10.10.0.11")]
    start_scan(db_session, network, "tester")
    assert codes(analyst, "unreachable") == set()
    assert codes(analyst, "unknown_host") == set()  # скан прилип к srv01 по IP, а не завёл новый актив


def test_no_scan_no_unreachable(analyst: TestClient, db_session: Session, network: Network) -> None:
    add(db_session, "ksc", "srv01", "10.10.0.11")
    assert codes(analyst, "unreachable") == set()


def test_rescan_marks_missing_host_gone(analyst: TestClient, db_session: Session, network: Network, fake_scan: FakeScan) -> None:
    fake_scan.alive = [host("10.10.0.5"), host("10.10.0.7")]
    start_scan(db_session, network, "tester")
    fake_scan.alive = [host("10.10.0.5")]
    start_scan(db_session, network, "tester")
    db_session.expire_all()
    rows = {r.source_key: r for r in db_session.execute(select(AssetObservation).where(AssetObservation.source == "scan")).scalars()}
    assert rows["10.10.0.5"].gone_at is None and rows["10.10.0.7"].gone_at is not None
    db_session.refresh(network)
    assert network.last_scan_alive == 1
    assert codes(analyst, "unknown_host") == {"10.10.0.5"}


def test_ports_only_mode_without_icmp(analyst: TestClient, db_session: Session, network: Network, fake_scan: FakeScan,
                                      monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner, "icmp_available", lambda: False)
    fake_scan.alive = [HostResult(ip="10.10.0.5", icmp=None, ttl=None, rtt_ms=None, ports=[445], ptr="")]
    r = analyst.post(f"/api/assets/networks/{network.id}/scan")
    assert r.status_code == 202, r.text
    assert r.json()["icmp"] is False
    job = last_job(db_session)
    assert job.status == "done" and "только порты" in job.message
    row = db_session.execute(select(AssetObservation).where(AssetObservation.source == "scan")).scalar_one()
    assert row.extra["icmp"] is None and row.extra["ttl"] is None and row.extra["os_hint"] == ""


def test_one_scan_at_a_time(analyst: TestClient, db_session: Session, network: Network, fake_scan: FakeScan) -> None:
    start_job(db_session, AssetJob, "scan", "tester")
    with pytest.raises(ScanBusy):
        start_scan(db_session, network, "tester")
    r = analyst.post(f"/api/assets/networks/{network.id}/scan")
    assert r.status_code == 409 and "скан" in r.json()["detail"]
    sched = PlatformSchedule(module="assets", kind="scan", target_id=network.id, interval_hours=24, enabled=True)
    assert schedule_handler(db_session, sched) is None
    assert fake_scan.targets == []


def test_scan_disabled_network_is_refused(analyst: TestClient, db_session: Session, network: Network, fake_scan: FakeScan) -> None:
    assert analyst.put(f"/api/assets/networks/{network.id}", json={"scan_enabled": False}).status_code == 200
    r = analyst.post(f"/api/assets/networks/{network.id}/scan")
    assert r.status_code == 409 and "выключено" in r.json()["detail"]
    assert analyst.post("/api/assets/networks/999999/scan").status_code == 404
    assert fake_scan.targets == []


def test_api_scan_starts_job(analyst: TestClient, db_session: Session, network: Network, fake_scan: FakeScan) -> None:
    fake_scan.alive = [host("10.10.0.5")]
    r = analyst.post(f"/api/assets/networks/{network.id}/scan")
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["icmp"] is True
    job = analyst.get(f"/api/assets/jobs/{body['job_id']}").json()
    assert job["kind"] == "scan" and job["status"] == "done" and job["started_by"] == "user-analyst"


def scan_rows(db: Session) -> dict[str, AssetObservation]:
    db.expire_all()
    return {r.source_key: r for r in db.execute(select(AssetObservation).where(AssetObservation.source == "scan")).scalars()}


def test_address_taken_by_another_host_does_not_rename_old_asset(
    analyst: TestClient, db_session: Session, network: Network, fake_scan: FakeScan,
) -> None:
    """DHCP: адрес достался другому хосту. Старый актив держит имя, его наблюдение скана пропало;
    новый хост — новый актив с наблюдением скана по этому адресу."""
    srv = add(db_session, "ksc", "srv01", "10.10.0.5")
    fake_scan.alive = [host("10.10.0.5", ptr="srv01.corp.local")]
    start_scan(db_session, network, "tester")
    assert scan_rows(db_session)["10.10.0.5"].asset_id == srv

    fake_scan.alive = [host("10.10.0.5", ptr="ws09.corp.local")]
    start_scan(db_session, network, "tester")
    rows = scan_rows(db_session)
    live = rows["10.10.0.5"]
    assert live.gone_at is None and live.name == "ws09" and live.asset_id != srv
    old = [r for r in rows.values() if r.asset_id == srv]
    assert len(old) == 1 and old[0].gone_at is not None and old[0].name == "srv01"
    srv_asset, ws_asset = db_session.get(Asset, srv), db_session.get(Asset, live.asset_id)
    assert srv_asset is not None and srv_asset.name == "srv01"
    assert ws_asset is not None and ws_asset.name == "ws09" and ws_asset.ip == "10.10.0.5"

    # Следующий скан с тем же ws09 — правило 1, без новых активов.
    start_scan(db_session, network, "tester")
    assert scan_rows(db_session)["10.10.0.5"].asset_id == ws_asset.id
    assert len(db_session.execute(select(Asset)).scalars().all()) == 2


def test_scan_without_ptr_keeps_address_on_asset(analyst: TestClient, db_session: Session, network: Network, fake_scan: FakeScan) -> None:
    fake_scan.alive = [host("10.10.0.5", ptr="srv01.corp.local")]
    start_scan(db_session, network, "tester")
    first = scan_rows(db_session)["10.10.0.5"].asset_id
    fake_scan.alive = [host("10.10.0.5")]
    start_scan(db_session, network, "tester")
    rows = scan_rows(db_session)
    assert list(rows) == ["10.10.0.5"] and rows["10.10.0.5"].asset_id == first and rows["10.10.0.5"].gone_at is None


def test_scan_waits_for_sync_lock(analyst: TestClient, db_session: Session, network: Network, fake_scan: FakeScan) -> None:
    """Пока синхронизация держит блокировку и ещё не зафиксировала новый актив, скан не пишет:
    иначе не увидел бы его и завёл второй актив на тот же хост."""
    fake_scan.alive = [host("10.10.0.5", ptr="srv05.corp.local")]
    locked = threading.Event()

    def sync_like() -> None:
        with get_sessionmaker()() as s:
            s.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": SYNC_LOCK_KEY})
            apply_observation(s, Observed(source="ksc", source_key="ksc-srv05", name="srv05", ip="10.10.0.5", seen_at=NOW))
            locked.set()
            time.sleep(1.0)
            s.commit()

    holder = threading.Thread(target=sync_like)
    holder.start()
    assert locked.wait(5)
    started = time.monotonic()
    start_scan(db_session, network, "tester")
    waited = time.monotonic() - started
    holder.join()
    assert last_job(db_session).status == "done"
    assert waited >= 0.5
    assets = db_session.execute(select(Asset)).scalars().all()
    assert len(assets) == 1
    assert {r.source for r in db_session.execute(select(AssetObservation)).scalars()} == {"ksc", "scan"}


def test_no_open_transaction_during_scan(analyst: TestClient, db_session: Session, network: Network, fake_scan: FakeScan) -> None:
    """Скан идёт минутами: сессия задачи не держит открытую транзакцию (снапшот, блокировки)."""
    db_session.commit()
    idle: list[int] = []

    def check() -> None:
        with get_sessionmaker()() as s:
            idle.append(int(s.execute(text(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND state LIKE 'idle in transaction%'"
            )).scalar() or 0))

    fake_scan.during = check
    start_scan(db_session, network, "tester")
    assert last_job(db_session).status == "done"
    assert idle == [0]


def test_network_edited_during_scan_keeps_results(analyst: TestClient, db_session: Session, network: Network, fake_scan: FakeScan) -> None:
    fake_scan.alive = [host("10.10.0.5")]
    network_id = network.id

    def edit() -> None:
        with get_sessionmaker()() as s:
            row = s.get(Network, network_id)
            assert row is not None
            row.title = "правка посреди скана"
            s.commit()

    fake_scan.during = edit
    start_scan(db_session, network, "tester")
    assert last_job(db_session).status == "done"
    db_session.expire_all()
    row = db_session.get(Network, network_id)
    assert row is not None and row.title == "правка посреди скана" and row.last_scan_alive == 1
    assert set(scan_rows(db_session)) == {"10.10.0.5"}


def test_network_deleted_during_scan_drops_results(analyst: TestClient, db_session: Session, network: Network, fake_scan: FakeScan) -> None:
    fake_scan.alive = [host("10.10.0.5")]
    network_id = network.id
    db_session.commit()
    fake_scan.during = lambda: analyst.delete(f"/api/assets/networks/{network_id}")
    start_scan(db_session, network, "tester")
    job = last_job(db_session)
    assert job.status == "done" and "удалена" in job.message, (job.status, job.error, job.message)
    assert scan_rows(db_session) == {}


def test_schedule_of_disabled_network_is_skipped_quietly(
    analyst: TestClient, db_session: Session, network: Network, fake_scan: FakeScan, caplog: pytest.LogCaptureFixture,
) -> None:
    url = f"/api/assets/networks/{network.id}"
    assert analyst.put(url, json={"scan_enabled": False}).status_code == 200
    r = analyst.put(f"{url}/schedule", json={"interval_hours": 24, "window_from": None, "window_to": None, "enabled": True})
    assert r.status_code == 422 and "выключено" in r.json()["detail"]
    sched = PlatformSchedule(module="assets", kind="scan", target_id=network.id, interval_hours=24, enabled=True)
    db_session.expire_all()
    with caplog.at_level(logging.WARNING):
        assert schedule_handler(db_session, sched) is None
    warned = [rec for rec in caplog.records if "выключено" in rec.getMessage()]
    assert len(warned) == 1 and warned[0].exc_info is None
    assert fake_scan.targets == []


def test_scan_target_carries_rate(analyst: TestClient, db_session: Session, network: Network, fake_scan: FakeScan) -> None:
    assert analyst.put(f"/api/assets/networks/{network.id}", json={"rate_per_s": 50}).status_code == 200
    db_session.expire_all()
    start_scan(db_session, network, "tester")
    assert fake_scan.targets[0].rate_per_s == 50


def test_schedule_create_read_and_delete(analyst: TestClient, db_session: Session, network: Network) -> None:
    url = f"/api/assets/networks/{network.id}/schedule"
    assert analyst.get(url).json() is None
    r = analyst.put(url, json={"interval_hours": 24, "window_from": "02:00", "window_to": "05:00", "enabled": True})
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["interval_hours"], body["window_from"], body["window_to"], body["enabled"]) == (24, "02:00", "05:00", True)
    assert body["next_run_at"] is not None and body["tz"]
    db_session.expire_all()
    sched = db_session.execute(select(PlatformSchedule)).scalar_one()
    assert (sched.module, sched.kind, sched.target_id) == ("assets", "scan", network.id)
    listed = analyst.get(f"/api/assets/networks/{network.id}").json()
    assert listed["schedule_id"] == sched.id and listed["schedule"]["window_from"] == "02:00"
    assert analyst.get("/api/assets/networks").json()[0]["schedule"]["interval_hours"] == 24
    assert analyst.get(url).json()["id"] == sched.id

    r = analyst.put(url, json={"interval_hours": 12, "window_from": None, "window_to": None, "enabled": False})
    assert r.status_code == 200 and r.json()["id"] == sched.id and r.json()["enabled"] is False

    assert analyst.put(url, json={"interval_hours": 12, "window_from": "02:00", "window_to": None, "enabled": True}).status_code == 422
    assert analyst.put(url, json={"interval_hours": 0, "window_from": None, "window_to": None, "enabled": True}).status_code == 422

    assert analyst.delete(url).status_code == 204
    db_session.expire_all()
    assert db_session.execute(select(PlatformSchedule)).scalars().all() == []
    after = analyst.get(f"/api/assets/networks/{network.id}").json()
    assert after["schedule_id"] is None and after["schedule"] is None


def test_scheduler_tick_runs_scan(analyst: TestClient, db_session: Session, network: Network, fake_scan: FakeScan) -> None:
    fake_scan.alive = [host("10.10.0.5")]
    r = analyst.put(f"/api/assets/networks/{network.id}/schedule",
                    json={"interval_hours": 1, "window_from": None, "window_to": None, "enabled": True})
    assert r.status_code == 200, r.text
    started = tick(db_session, NOW + dt.timedelta(hours=2))
    assert len(started) == 1
    job = db_session.get(AssetJob, started[0])
    assert job is not None and job.kind == "scan" and job.started_by == "расписание"
    db_session.refresh(job)
    assert job.status == "done", job.error
    assert fake_scan.targets[0].cidr == "10.10.0.0/24"


def test_auditor_cannot_scan_or_schedule(analyst: TestClient, network: Network, client_as: Callable[[str], TestClient]) -> None:
    auditor = client_as("auditor")
    url = f"/api/assets/networks/{network.id}"
    assert auditor.get(f"{url}/schedule").status_code == 200
    assert auditor.post(f"{url}/scan").status_code == 403
    assert auditor.put(f"{url}/schedule", json={"interval_hours": 24, "window_from": None, "window_to": None, "enabled": True}).status_code == 403
    assert auditor.delete(f"{url}/schedule").status_code == 403
