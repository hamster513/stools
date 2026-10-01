"""Задача скана: наблюдения `scan`, «не отвечает», «найдено сканером», gone_at, занятость,
ручки запуска и расписания, запуск планировщиком. Сканер подменён — пакеты не уходят."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.jobs import start_job
from api.modules.assets.core import scanner
from api.modules.assets.core.matching import Observed
from api.modules.assets.core.scanner import HostResult, ScanTarget
from api.modules.assets.models import DEFAULT_ZONES, AssetJob, AssetObservation, AssetZone, Network
from api.modules.assets.services import scan as scan_service
from api.modules.assets.services.assets import apply_observation
from api.modules.assets.services.scan import ScanBusy, schedule_handler, start_scan
from api.platform.scheduler import PlatformSchedule, tick

NOW = dt.datetime.now(dt.UTC)


@pytest.fixture(autouse=True)
def inline_spawn(monkeypatch: pytest.MonkeyPatch) -> None:
    """Задача скана уходит в поток; в тестах — на месте, иначе поток пережил бы тест."""
    monkeypatch.setattr(scan_service, "spawn", lambda fn: fn())


class FakeScan:
    """Подмена `scanner.scan`: отдаёт заданных живых, запоминает цель."""

    def __init__(self) -> None:
        self.alive: list[HostResult] = []
        self.targets: list[ScanTarget] = []

    async def __call__(self, target: ScanTarget, **_kw: Any) -> list[HostResult]:
        self.targets.append(target)
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
