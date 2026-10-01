"""Задача DNS: прямые и обратные запросы, чтение зоны AD, «пропавшие» имена, ручки, расписание,
PTR сканера через настроенный сервер. DNS — поддельный сервер на 127.0.0.1, LDAP — подделка."""
from __future__ import annotations

import asyncio
import datetime as dt
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.jobs import JobHandle, start_job
from api.modules.ad.models import AdConnection
from api.modules.assets.core import dns as dns_core
from api.modules.assets.core import scanner
from api.modules.assets.core.matching import Observed
from api.modules.assets.core.scanner import HostResult, ScanTarget
from api.modules.assets.models import (
    DEFAULT_ZONES,
    Asset,
    AssetDns,
    AssetJob,
    AssetObservation,
    AssetZone,
    Network,
)
from api.modules.assets.services import dns as dns_service
from api.modules.assets.services import scan as scan_service
from api.modules.assets.services.assets import apply_observation
from api.modules.assets.services.dns import DnsBusy, schedule_handler, start_dns
from api.platform.scheduler import PlatformSchedule, tick
from tests.assets.fake_dns import (
    FakeAdConnection,
    FakeDnsServer,
    FakeZoneLdap,
    a_record,
    cname_record,
)

NOW = dt.datetime.now(dt.UTC)
OLD = NOW - dt.timedelta(days=60)
STAMP = (NOW - dt.timedelta(days=2)).replace(minute=0, second=0, microsecond=0)


@pytest.fixture(autouse=True)
def inline_spawn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dns_service, "spawn", lambda fn: fn())
    monkeypatch.setattr(scan_service, "spawn", lambda fn: fn())


@pytest.fixture
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeDnsServer]:
    with FakeDnsServer() as server:
        monkeypatch.setattr(dns_core, "PORT", server.port)
        yield server


@pytest.fixture
def analyst(db_session: Session, client_as: Callable[[str], TestClient]) -> TestClient:
    for name in DEFAULT_ZONES:
        if db_session.get(AssetZone, name) is None:
            db_session.add(AssetZone(name=name, title=name, description=""))
    db_session.commit()
    return client_as("analyst")


@pytest.fixture
def zone_ldap(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> tuple[FakeZoneLdap, AdConnection]:
    ldap = FakeZoneLdap()
    conn = AdConnection(title="CORP", host="dc01.corp.local", username="CORP\\svc", password="", pause_ms=0)
    db_session.add(conn)
    db_session.commit()
    fake_conn = FakeAdConnection()
    monkeypatch.setattr(dns_service.ad_connections, "ldap3_connection", lambda c: fake_conn)
    monkeypatch.setattr(dns_service, "ldap3_searcher", lambda c, **kw: ldap.search)
    return ldap, conn


def add(db: Session, source: str, key: str, *, name: str = "", fqdn: str = "", ip: str = "", seen: dt.datetime = NOW, **extra: Any) -> int:
    asset, _ = apply_observation(db, Observed(source=source, source_key=key, name=name, fqdn=fqdn, ip=ip, seen_at=seen, extra=extra))
    db.commit()
    return asset.id


def direct(c: TestClient, **kw: Any) -> int:
    body = {"title": "DNS", "mode": "direct", "server": "127.0.0.1", "forward": True, "reverse": False, "timeout_ms": 1000, **kw}
    r = c.post("/api/assets/dns", json=body)
    assert r.status_code == 201, r.text
    return int(r.json()["id"])


def run(c: TestClient, dns_id: int, db: Session) -> AssetJob:
    r = c.post(f"/api/assets/dns/{dns_id}/run")
    assert r.status_code == 202, r.text
    db.expire_all()
    job = db.get(AssetJob, r.json()["job_id"])
    assert job is not None and job.kind == "dns"
    return job


def codes(c: TestClient, code: str) -> set[str]:
    r = c.get("/api/assets/assets", params={"code": code})
    assert r.status_code == 200, r.text
    return {i["ip"] for i in r.json()["items"]}


def dns_rows(db: Session) -> dict[str, AssetObservation]:
    db.expire_all()
    return {r.source_key: r for r in db.execute(select(AssetObservation).where(AssetObservation.source == "dns")).scalars()}


# ---- Прямые запросы ---------------------------------------------------------


def test_forward_moves_ip_and_old_sources_become_stale(analyst: TestClient, db_session: Session, fake_dns: FakeDnsServer) -> None:
    asset_id = add(db_session, "vm", "msk1.corp.local|10.10.0.20", name="msk1.corp.local", ip="10.10.0.20", seen=OLD)
    assert add(db_session, "ksc", "1:77", name="msk1", fqdn="msk1.corp.local", ip="10.10.0.20", seen=OLD) == asset_id
    fake_dns.add("msk1.corp.local", "A", "10.10.0.21")

    dns_id = direct(analyst)
    job = run(analyst, dns_id, db_session)
    assert job.status == "done", job.error
    assert "прямых 1" in job.message and "найдено 1" in job.message

    asset = db_session.get(Asset, asset_id)
    assert asset is not None and asset.ip == "10.10.0.21"
    row = dns_rows(db_session)["msk1.corp.local"]
    assert row.asset_id == asset_id and (row.name, row.fqdn, row.domain, row.ip) == ("msk1", "msk1.corp.local", "corp.local", "10.10.0.21")
    assert row.extra == {"record_type": "A", "ttl": 300, "record_timestamp": None, "server": "127.0.0.1"}
    assert codes(analyst, "stale") == {"10.10.0.21"}
    stale = {d["source"] for d in analyst.get(f"/api/assets/assets/{asset_id}").json()["discrepancies"] if d["code"] == "stale"}
    assert stale == {"vm", "ksc"}
    listed = analyst.get("/api/assets/dns").json()
    assert listed[0]["last_run_at"] is not None


def test_forward_name_gone_and_timeout_kept(analyst: TestClient, db_session: Session, fake_dns: FakeDnsServer) -> None:
    add(db_session, "ksc", "1:2", name="srv02", fqdn="srv02.corp.local", ip="10.10.0.6")
    add(db_session, "ksc", "1:3", name="slow", fqdn="slow.corp.local", ip="10.10.0.7")
    fake_dns.add("srv02.corp.local", "A", "10.10.0.6")
    fake_dns.add("slow.corp.local", "A", "10.10.0.7")
    dns_id = direct(analyst, timeout_ms=300)
    assert run(analyst, dns_id, db_session).status == "done"
    rows = dns_rows(db_session)
    assert set(rows) == {"srv02.corp.local", "slow.corp.local"} and all(r.gone_at is None for r in rows.values())

    del fake_dns.records[("srv02.corp.local", "A")]
    fake_dns.silent.add("slow.corp.local")
    job = run(analyst, dns_id, db_session)
    assert job.status == "done", job.error
    assert "пропало 1" in job.message and "ошибок 1" in job.message
    rows = dns_rows(db_session)
    assert rows["srv02.corp.local"].gone_at is not None
    # Таймаут — не «имени больше нет».
    assert rows["slow.corp.local"].gone_at is None


def test_cancel_during_queries_writes_nothing(analyst: TestClient, db_session: Session, fake_dns: FakeDnsServer,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
    add(db_session, "ksc", "1:1", name="srv01", fqdn="srv01.corp.local", ip="10.10.0.5")
    fake_dns.add("srv01.corp.local", "A", "10.10.0.5")
    monkeypatch.setattr(JobHandle, "cancelled", lambda _self: True)
    job = run(analyst, direct(analyst), db_session)
    assert job.status == "cancelled"
    assert dns_rows(db_session) == {}
    assert analyst.get("/api/assets/dns").json()[0]["last_run_at"] is None


def test_dead_server_fails_job(analyst: TestClient, db_session: Session, fake_dns: FakeDnsServer) -> None:
    for i in range(7):
        add(db_session, "ksc", f"1:{i}", name=f"h{i}", fqdn=f"h{i}.corp.local", ip=f"10.10.0.{40 + i}")
        fake_dns.silent.add(f"h{i}.corp.local")
    job = run(analyst, direct(analyst, timeout_ms=100), db_session)
    assert job.status == "failed" and "не отвечает" in (job.error or "")


# ---- Обратные запросы -------------------------------------------------------


def test_reverse_names_scan_host(analyst: TestClient, db_session: Session, fake_dns: FakeDnsServer) -> None:
    srv01 = add(db_session, "ksc", "1:1", name="srv01", fqdn="srv01.corp.local", ip="10.10.0.30")
    known_scan = add(db_session, "scan", "10.10.0.5", ip="10.10.0.5")
    unknown_scan = add(db_session, "scan", "10.10.0.7", ip="10.10.0.7")
    fake_dns.ptr("10.10.0.5", "srv01.corp.local")
    fake_dns.ptr("10.10.0.7", "ws07.corp.local")

    job = run(analyst, direct(analyst, forward=False, reverse=True), db_session)
    assert job.status == "done", job.error
    assert "обратных 3" in job.message
    rows = dns_rows(db_session)
    assert set(rows) == {"10.10.0.5", "10.10.0.7"}
    # Имя известно — привязка по FQDN (правило 2), а не к хосту скана с тем же адресом.
    assert rows["10.10.0.5"].asset_id == srv01 != known_scan
    assert rows["10.10.0.5"].extra["record_type"] == "PTR"
    # Имя никому не известно — к хосту скана по адресу (правило 5): у него появляется имя.
    assert rows["10.10.0.7"].asset_id == unknown_scan
    asset = db_session.get(Asset, unknown_scan)
    assert asset is not None and (asset.name, asset.fqdn) == ("ws07", "ws07.corp.local")
    # PTR не отменяет «найдено сканером, нигде не описано».
    assert "10.10.0.7" in codes(analyst, "unknown_host")

    fake_dns.records.pop(("7.0.10.10.in-addr.arpa", "PTR"))
    run(analyst, direct(analyst, forward=False, reverse=True), db_session)
    assert dns_rows(db_session)["10.10.0.7"].gone_at is not None


# ---- Зона AD ----------------------------------------------------------------


def test_zone_read_and_dns_orphan(analyst: TestClient, db_session: Session, zone_ldap: tuple[FakeZoneLdap, AdConnection]) -> None:
    ldap, conn = zone_ldap
    ldap.zones["corp.local"] = {
        "@": [a_record("10.10.0.2")],
        "_ldap._tcp": [a_record("10.10.0.2")],
        "srv09": [a_record("10.10.0.9", stamp=STAMP)],
        "srv01": [a_record("10.10.0.5")],
        "web": [cname_record("srv01.corp.local")],
    }
    r = analyst.post("/api/assets/networks", json={"cidr": "10.10.0.0/24", "scan_enabled": True})
    assert r.status_code == 201, r.text
    net = db_session.get(Network, r.json()["id"])
    assert net is not None
    net.last_scan_at = NOW
    db_session.commit()
    add(db_session, "scan", "10.10.0.5", ip="10.10.0.5")

    r = analyst.post("/api/assets/dns", json={"title": "AD", "mode": "ad", "ad_connection_id": conn.id,
                                              "zones": ["corp.local", "lab.local"], "zone_read": True})
    assert r.status_code == 201, r.text
    dns_id = r.json()["id"]
    job = run(analyst, dns_id, db_session)
    assert job.status == "done", job.error
    assert "из зон 2" in job.message

    rows = dns_rows(db_session)
    assert set(rows) == {"srv09.corp.local", "srv01.corp.local"}
    srv09 = rows["srv09.corp.local"]
    assert srv09.seen_at == STAMP
    assert srv09.extra == {"record_type": "A", "ttl": 300, "record_timestamp": STAMP.isoformat(), "server": "dc01.corp.local", "zone": "corp.local"}
    assert rows["srv01.corp.local"].extra["record_timestamp"] is None
    assert codes(analyst, "dns_orphan") == {"10.10.0.9"}

    del ldap.zones["corp.local"]["srv09"]
    assert run(analyst, dns_id, db_session).status == "done"
    rows = dns_rows(db_session)
    assert rows["srv09.corp.local"].gone_at is not None and rows["srv01.corp.local"].gone_at is None


def test_zone_ldap_error_fails_job(analyst: TestClient, db_session: Session, zone_ldap: tuple[FakeZoneLdap, AdConnection]) -> None:
    ldap, conn = zone_ldap
    ldap.failing.add("corp.local")
    r = analyst.post("/api/assets/dns", json={"mode": "ad", "ad_connection_id": conn.id, "zones": ["corp.local"], "zone_read": True})
    job = run(analyst, r.json()["id"], db_session)
    assert job.status == "failed" and "контроллер ответил" in (job.error or "")


# ---- Ручки ------------------------------------------------------------------


def test_crud_and_validation(analyst: TestClient, db_session: Session, zone_ldap: tuple[FakeZoneLdap, AdConnection]) -> None:
    _ldap, conn = zone_ldap
    assert analyst.get("/api/assets/dns").json() == []
    bad = [
        {"mode": "direct", "forward": False, "reverse": False},
        {"mode": "direct", "server": "bad host!"},
        {"mode": "ad", "zones": ["corp.local"], "zone_read": True},
        {"mode": "ad", "ad_connection_id": conn.id, "zones": [], "zone_read": True},
        {"mode": "ad", "ad_connection_id": conn.id, "zones": ["corp.local"], "zone_read": False},
        {"mode": "ad", "ad_connection_id": 999999, "zones": ["corp.local"], "zone_read": True},
        {"mode": "ad", "ad_connection_id": conn.id, "zones": ["bad zone"], "zone_read": True},
        {"mode": "other"},
        {"mode": "direct", "rate_per_s": 0},
    ]
    for body in bad:
        assert analyst.post("/api/assets/dns", json=body).status_code == 422, body

    r = analyst.post("/api/assets/dns", json={"title": "DC", "mode": "direct", "server": "dc01.corp.local"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert (body["forward"], body["reverse"], body["zone_read"], body["rate_per_s"], body["timeout_ms"], body["enabled"]) == (True, True, False, 50, 3000, True)
    assert body["schedule"] is None and body["last_run_at"] is None
    dns_id = body["id"]

    r = analyst.put(f"/api/assets/dns/{dns_id}", json={"title": "AD", "mode": "ad", "ad_connection_id": conn.id,
                                                       "zones": ["Corp.Local.", "corp.local"], "zone_read": True, "enabled": False})
    assert r.status_code == 200, r.text
    assert r.json()["zones"] == ["corp.local"] and r.json()["enabled"] is False
    assert analyst.put("/api/assets/dns/999999", json={"mode": "direct"}).status_code == 404
    # Выключенный сервер вручную не запускается.
    assert analyst.post(f"/api/assets/dns/{dns_id}/run").status_code == 409

    url = f"/api/assets/dns/{dns_id}/schedule"
    r = analyst.put(url, json={"interval_hours": 24, "window_from": "02:00", "window_to": "05:00", "enabled": True})
    assert r.status_code == 200, r.text
    db_session.expire_all()
    sched = db_session.execute(select(PlatformSchedule)).scalar_one()
    assert (sched.module, sched.kind, sched.target_id) == ("assets", "dns", dns_id)
    assert analyst.get("/api/assets/dns").json()[0]["schedule"]["window_from"] == "02:00"
    assert analyst.put(url, json={"interval_hours": 0, "enabled": True}).status_code == 422
    assert analyst.delete(url).status_code == 204
    db_session.expire_all()
    assert db_session.execute(select(PlatformSchedule)).scalars().all() == []

    analyst.put(url, json={"interval_hours": 24, "enabled": True})
    assert analyst.delete(f"/api/assets/dns/{dns_id}").status_code == 204
    db_session.expire_all()
    assert analyst.get("/api/assets/dns").json() == []
    assert db_session.execute(select(PlatformSchedule)).scalars().all() == []
    assert analyst.delete(f"/api/assets/dns/{dns_id}").status_code == 404


def test_one_dns_job_at_a_time(analyst: TestClient, db_session: Session, fake_dns: FakeDnsServer) -> None:
    dns_id = direct(analyst)
    start_job(db_session, AssetJob, "dns", "tester")
    row = db_session.get(AssetDns, dns_id)
    assert row is not None
    with pytest.raises(DnsBusy):
        start_dns(db_session, row, "tester")
    r = analyst.post(f"/api/assets/dns/{dns_id}/run")
    assert r.status_code == 409 and "DNS" in r.json()["detail"]
    sched = PlatformSchedule(module="assets", kind="dns", target_id=dns_id, interval_hours=24, enabled=True)
    assert schedule_handler(db_session, sched) is None


def test_scheduler_tick_runs_dns(analyst: TestClient, db_session: Session, fake_dns: FakeDnsServer) -> None:
    add(db_session, "ksc", "1:1", name="srv01", fqdn="srv01.corp.local", ip="10.10.0.5")
    fake_dns.add("srv01.corp.local", "A", "10.10.0.5")
    dns_id = direct(analyst)
    r = analyst.put(f"/api/assets/dns/{dns_id}/schedule", json={"interval_hours": 1, "enabled": True})
    assert r.status_code == 200, r.text
    started = tick(db_session, NOW + dt.timedelta(hours=2))
    assert len(started) == 1
    job = db_session.get(AssetJob, started[0])
    assert job is not None
    db_session.refresh(job)
    assert job.kind == "dns" and job.status == "done" and job.started_by == "расписание", job.error
    assert "srv01.corp.local" in dns_rows(db_session)


def test_auditor_cannot_write(analyst: TestClient, db_session: Session, fake_dns: FakeDnsServer, client_as: Callable[[str], TestClient]) -> None:
    dns_id = direct(analyst)
    auditor = client_as("auditor")
    assert auditor.get("/api/assets/dns").status_code == 200
    assert auditor.post("/api/assets/dns", json={"mode": "direct"}).status_code == 403
    assert auditor.put(f"/api/assets/dns/{dns_id}", json={"mode": "direct"}).status_code == 403
    assert auditor.delete(f"/api/assets/dns/{dns_id}").status_code == 403
    assert auditor.post(f"/api/assets/dns/{dns_id}/run").status_code == 403
    assert auditor.put(f"/api/assets/dns/{dns_id}/schedule", json={"interval_hours": 24, "enabled": True}).status_code == 403
    assert auditor.delete(f"/api/assets/dns/{dns_id}/schedule").status_code == 403


# ---- PTR сканера ------------------------------------------------------------


def test_scan_ptr_uses_configured_server(analyst: TestClient, db_session: Session, fake_dns: FakeDnsServer,
                                         monkeypatch: pytest.MonkeyPatch) -> None:
    fake_dns.ptr("10.10.0.5", "srv01.corp.local")
    seen: dict[str, Any] = {}

    async def fake_scan(target: ScanTarget, **kw: Any) -> list[HostResult]:
        seen["resolver"] = kw.get("resolver")
        return []

    monkeypatch.setattr(scanner, "scan", fake_scan)
    monkeypatch.setattr(scanner, "icmp_available", lambda: True)
    r = analyst.post("/api/assets/networks", json={"cidr": "10.10.0.0/24", "scan_enabled": True})
    net = db_session.get(Network, r.json()["id"])
    assert net is not None

    scan_service.start_scan(db_session, net, "tester")
    assert seen["resolver"] is None  # DNS-сервера нет — системный резолвер сканера

    direct(analyst, server="127.0.0.1", reverse=True)
    scan_service.start_scan(db_session, net, "tester")
    resolver = seen["resolver"]
    assert resolver is not None
    assert asyncio.run(resolver("10.10.0.5")) == "srv01.corp.local"
    assert asyncio.run(resolver("10.10.0.77")) == ""
