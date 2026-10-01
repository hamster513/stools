"""Обзор модуля, настройки порогов и синхронизации, поиск актива по хосту модуля (ссылки «в Assets»)."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.assets.models import AssetDns, AssetSettings, AssetZone, Network
from api.modules.ksc.models import KscServer
from tests.assets.synthetic import load_all

NOW = dt.datetime.now(dt.UTC)


@pytest.fixture
def analyst(db_session: Session, app_settings: Any, client_as: Callable[[str], TestClient]) -> TestClient:
    """Аналитик и три источника, синхронизированные через ручку."""
    db_session.add(AssetSettings(data={"sync_after_import": False}))
    if db_session.get(AssetZone, "Internal") is None:  # зоны кладёт миграция; база тестов может быть чистой
        db_session.add(AssetZone(name="Internal", title="Internal", description=""))
    db_session.commit()
    load_all(db_session, Path(app_settings.data_dir), NOW)
    c = client_as("analyst")
    r = c.post("/api/assets/sync")
    assert r.status_code == 202, r.text
    assert c.get(f"/api/assets/jobs/{r.json()['job_id']}").json()["status"] == "done"
    return c


def asset_id(c: TestClient, name: str) -> int:
    items = c.get("/api/assets/assets", params={"q": name}).json()["items"]
    return int(next(i for i in items if i["name"].lower() == name)["id"])


# ---- Обзор ------------------------------------------------------------------


def test_overview_counts_match_synthetic(analyst: TestClient) -> None:
    body = analyst.get("/api/assets/overview").json()
    assert body["assets_total"] == 4
    assert body["by_source"] == {"vm": 2, "ksc": 2, "ad": 3, "scan": 0, "dns": 0}
    # ws01 — нет агента; old01 — неактивный AD; msk1 — VM и KSC расходятся по IP.
    assert body["codes"]["no_av"] == 1 and body["codes"]["ad_inactive"] == 1 and body["codes"]["conflict"] == 1
    # Адреса есть у msk1 и srv01, сетей не описано.
    assert body["codes"]["no_network"] == 2
    assert body["by_zone"] == {"": 4}
    assert body["networks"] == {"total": 0, "scanned": 0, "no_network_assets": 2}
    assert body["last_scans"] == [] and body["last_dns"] == []
    assert body["sync"]["last_sync_at"] is not None and body["sync"]["running_job_id"] is None
    # Обзор считает теми же фасетами, что и список.
    facets = analyst.get("/api/assets/assets").json()["facets"]
    assert body["codes"] == facets["code"] and body["by_source"] == facets["source"]


def test_overview_networks_zones_and_last_runs(analyst: TestClient, db_session: Session) -> None:
    r = analyst.post("/api/assets/networks", json={"cidr": "10.10.0.0/24", "title": "Серверы", "zone": "Internal"})
    assert r.status_code == 201, r.text
    assert analyst.post("/api/assets/networks", json={"cidr": "10.20.0.0/24"}).status_code == 201
    older, newer = NOW - dt.timedelta(days=2), NOW - dt.timedelta(hours=1)
    for cidr, when, alive in (("10.20.0.0/24", older, 0), ("10.10.0.0/24", newer, 3)):
        net = db_session.execute(select(Network).where(Network.cidr == cidr)).scalar_one()
        net.last_scan_at, net.last_scan_alive = when, alive
    for i in range(12):
        db_session.add(AssetDns(title=f"dns{i:02}", server=f"10.10.0.{i + 1}", last_run_at=NOW - dt.timedelta(hours=i)))
    db_session.add(AssetDns(title="никогда", server="10.10.0.99"))
    db_session.commit()

    body = analyst.get("/api/assets/overview").json()
    assert body["by_zone"] == {"Internal": 1, "": 3}  # srv01 в 10.10.0.0/24
    assert body["networks"] == {"total": 2, "scanned": 2, "no_network_assets": 1}  # msk1 вне сетей
    assert [(s["cidr"], s["title"], s["last_scan_alive"]) for s in body["last_scans"]] == [
        ("10.10.0.0/24", "Серверы", 3), ("10.20.0.0/24", "", 0),
    ]
    assert body["last_scans"][0]["network_id"] and body["last_scans"][0]["last_scan_at"]
    assert len(body["last_dns"]) == 10 and body["last_dns"][0]["title"] == "dns00" and body["last_dns"][-1]["title"] == "dns09"
    assert set(body["last_dns"][0]) == {"dns_id", "title", "last_run_at"}
    # Сеть srv01 отсканирована, а его адреса среди живых нет.
    assert body["codes"]["unreachable"] == 1


# ---- Настройки --------------------------------------------------------------


@pytest.fixture
def plain(db_session: Session, client_as: Callable[[str], TestClient]) -> TestClient:
    return client_as("analyst")


def test_settings_defaults_and_round_trip(plain: TestClient, db_session: Session) -> None:
    assert plain.get("/api/assets/settings").json() == {"inactive_days": 30, "stale_days": 30, "sync_after_import": True}
    db_session.add(AssetSettings(data={"rerun_requested": True}))
    db_session.commit()

    r = plain.put("/api/assets/settings", json={"inactive_days": 10, "stale_days": 0, "sync_after_import": False})
    assert r.status_code == 200, r.text
    assert r.json() == {"inactive_days": 10, "stale_days": 0, "sync_after_import": False}
    assert plain.get("/api/assets/settings").json() == r.json()
    db_session.expire_all()
    rows = list(db_session.execute(select(AssetSettings)).scalars())
    # Строка одна, служебная просьба синхронизации не потерялась.
    assert len(rows) == 1 and rows[0].data["rerun_requested"] is True and rows[0].data["stale_days"] == 0


@pytest.mark.parametrize("body", [
    {"inactive_days": 0, "stale_days": 30, "sync_after_import": True},
    {"inactive_days": 30, "stale_days": -1, "sync_after_import": True},
    {"inactive_days": 30, "stale_days": 30},
    {"inactive_days": 30, "stale_days": 30, "sync_after_import": "может быть"},
])
def test_settings_validation(plain: TestClient, body: dict[str, Any]) -> None:
    assert plain.put("/api/assets/settings", json=body).status_code == 422


def test_stale_days_changes_discrepancies(analyst: TestClient) -> None:
    """Порог устаревания из настроек сразу меняет код: обе даты msk1 сегодня — при 0 дней это `stale`."""
    assert asset_id(analyst, "msk1") in {i["id"] for i in analyst.get("/api/assets/assets", params={"code": "conflict"}).json()["items"]}
    assert analyst.put("/api/assets/settings", json={"inactive_days": 30, "stale_days": 0, "sync_after_import": False}).status_code == 200
    stale = analyst.get("/api/assets/assets", params={"code": "stale"}).json()["items"]
    assert [i["name"].lower() for i in stale] == ["msk1"]


# ---- Поиск актива по хосту модуля --------------------------------------------


def test_lookup_ksc_and_vm(analyst: TestClient, db_session: Session) -> None:
    srv01 = asset_id(analyst, "srv01")
    server_id = db_session.execute(select(KscServer.id)).scalar_one()

    def lookup(**params: Any) -> Any:
        return analyst.get("/api/assets/lookup", params=params)

    r = lookup(source="ksc", key=f"{server_id}:h-srv01")
    assert r.status_code == 200 and r.json() == {"asset_id": srv01}
    assert lookup(source="ksc", key="h-srv01", server_id=server_id).json() == {"asset_id": srv01}
    assert lookup(source="ksc", key="h-srv01", server_id=server_id + 1).status_code == 404
    assert lookup(source="ksc", key="h-nope", server_id=server_id).status_code == 404
    assert lookup(source="vm", key="srv01.corp.local|10.10.0.11").json() == {"asset_id": srv01}
    assert lookup(source="vm", key="msk1|192.168.6.53").json() == {"asset_id": asset_id(analyst, "msk1")}
    assert lookup(source="vm", key="msk1|10.0.0.1").status_code == 404
    assert lookup(source="nope", key="x").status_code == 422


def test_lookup_follows_merge(analyst: TestClient, db_session: Session) -> None:
    """После объединения наблюдение живёт у первого актива — ссылка ведёт туда же."""
    ws01, old01 = asset_id(analyst, "ws01"), asset_id(analyst, "old01")
    assert analyst.post(f"/api/assets/assets/{ws01}/merge", json={"other_id": old01}).status_code == 200
    detail = analyst.get(f"/api/assets/assets/{ws01}").json()
    old_key = next(o["source_key"] for o in detail["observations"] if o["name"].lower() == "old01")
    assert analyst.get("/api/assets/lookup", params={"source": "ad", "key": old_key}).json() == {"asset_id": ws01}


# ---- Роли -------------------------------------------------------------------


def test_auditor_reads_but_cannot_change_settings(analyst: TestClient, client_as: Callable[[str], TestClient]) -> None:
    auditor = client_as("auditor")
    assert auditor.get("/api/assets/overview").status_code == 200
    assert auditor.get("/api/assets/settings").status_code == 200
    assert auditor.get("/api/assets/lookup", params={"source": "vm", "key": "msk1|192.168.6.53"}).status_code == 200
    r = auditor.put("/api/assets/settings", json={"inactive_days": 30, "stale_days": 30, "sync_after_import": True})
    assert r.status_code == 403
