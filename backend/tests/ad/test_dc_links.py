"""Контроллеры домена из сводки, связанные с Assets, VM и антивирусом (спека §7)."""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.modules.ad.models import AdDomain, AdSnapshot
from api.modules.ad.services import dc_links as dc_links_service
from api.modules.assets.models import Asset, AssetObservation
from api.modules.ksc.models import KscHost, KscServer, KscSnapshot
from api.modules.vm.models import VmCve, VmHost, VmHostCve

NOW = dt.datetime(2026, 10, 1, tzinfo=dt.UTC)


def _domain(db: Session, summary: dict[str, Any] | None) -> int:
    domain = AdDomain(sid="S-1-5-21-7-8-9", dns_root="corp.local", netbios="CORP", dn="DC=corp,DC=local")
    db.add(domain)
    db.flush()
    db.add(AdSnapshot(domain_id=domain.id, collected_at=NOW, source="file", summary_json=json.dumps(summary) if summary is not None else ""))
    db.commit()
    return domain.id


SUMMARY = {
    "dcs": [
        {"name": "DC01", "dn": "CN=DC01,OU=Domain Controllers,DC=corp,DC=local", "dns": "dc01.corp.local"},
        {"name": "DC02", "dn": "CN=DC02,OU=Domain Controllers,DC=corp,DC=local", "dns": "dc02.corp.local"},
    ],
    "subnets": [{"name": "10.0.0.0/24", "site": "Default-First-Site-Name"}],
}


def _asset(db: Session, name: str, ip: str, ips: tuple[str, ...] = (), gone_ips: tuple[str, ...] = ()) -> int:
    asset = Asset(name=name, name_key=name.lower(), fqdn=f"{name.lower()}.corp.local", domain="corp.local", ip=ip)
    db.add(asset)
    db.flush()
    db.add(AssetObservation(asset_id=asset.id, source="ad", source_key=f"sid-{name}", name=name, ip=ip, ips=[ip, *ips], seen_at=NOW))
    if gone_ips:
        db.add(AssetObservation(asset_id=asset.id, source="scan", source_key=gone_ips[0], ip=gone_ips[0], ips=list(gone_ips), seen_at=NOW, gone_at=NOW))
    return asset.id


@pytest.fixture
def scenario(db_session: Session) -> dict[str, int]:
    domain_id = _domain(db_session, SUMMARY)
    dc01 = _asset(db_session, "DC01", "10.0.0.5", ips=("10.0.1.7",), gone_ips=("10.0.0.99",))
    dc02 = _asset(db_session, "DC02", "10.9.9.9")
    # У DC01 в VM две критичные уязвимости (одна с эксплойтом) и одна средняя; имя хоста — FQDN в другом регистре.
    host = VmHost(hostname="DC01.CORP.LOCAL", ip="10.0.0.5")
    db_session.add(host)
    db_session.add_all([VmCve(cve_id="CVE-2026-0001", exploits_count=2), VmCve(cve_id="CVE-2026-0002"), VmCve(cve_id="CVE-2026-0003")])
    db_session.flush()
    db_session.add_all([
        VmHostCve(host_id=host.id, cve_id="CVE-2026-0001", risk=90),
        VmHostCve(host_id=host.id, cve_id="CVE-2026-0002", risk=70),
        VmHostCve(host_id=host.id, cve_id="CVE-2026-0003", risk=40),
    ])
    # KSC: DC01 есть только в последнем снапшоте сервера, DC02 — только в прежнем.
    server = KscServer(name="ksc01")
    db_session.add(server)
    db_session.flush()
    old = KscSnapshot(server_id=server.id, collected_at=NOW - dt.timedelta(days=7), source="file")
    new = KscSnapshot(server_id=server.id, collected_at=NOW, source="file")
    db_session.add_all([old, new])
    db_session.flush()
    db_session.add_all([KscHost(snapshot_id=old.id, host_id="h2", name="DC02"), KscHost(snapshot_id=new.id, host_id="h1", name="dc01")])
    db_session.commit()
    return {"domain_id": domain_id, "dc01": dc01, "dc02": dc02}


def test_dc_links_assets_vm_ksc(auth_client: TestClient, scenario: dict[str, int]) -> None:
    r = auth_client.get(f"/api/ad/domains/{scenario['domain_id']}/dc-links")
    assert r.status_code == 200, r.text
    first, second = r.json()
    assert first == {
        "name": "DC01", "asset_id": scenario["dc01"], "ips": ["10.0.0.5", "10.0.1.7"], "in_ad_subnet": True,
        "vm": {"critical": 2, "exploitable": 1}, "ksc_agent": True,
    }
    assert second == {
        "name": "DC02", "asset_id": scenario["dc02"], "ips": ["10.9.9.9"], "in_ad_subnet": False,
        "vm": None, "ksc_agent": False,
    }


def test_dc_without_asset_and_without_ksc_data(auth_client: TestClient, db_session: Session) -> None:
    domain_id = _domain(db_session, {"dcs": [{"name": "DC01", "dn": "CN=DC01", "dns": "dc01.corp.local"}], "subnets": []})
    (row,) = auth_client.get(f"/api/ad/domains/{domain_id}/dc-links").json()
    assert row == {"name": "DC01", "asset_id": None, "ips": [], "in_ad_subnet": None, "vm": None, "ksc_agent": None}


def test_asset_found_by_fqdn_and_no_subnets_gives_unknown(auth_client: TestClient, db_session: Session) -> None:
    domain_id = _domain(db_session, {"dcs": [{"name": "DC01", "dn": "CN=DC01", "dns": "DC01.corp.local"}], "subnets": []})
    asset = Asset(name="", name_key="", fqdn="dc01.corp.local", ip="10.0.0.5")
    db_session.add(asset)
    db_session.commit()
    (row,) = auth_client.get(f"/api/ad/domains/{domain_id}/dc-links").json()
    assert row["asset_id"] == asset.id and row["ips"] == ["10.0.0.5"] and row["in_ad_subnet"] is None


def test_failing_foreign_modules_give_none_not_500(auth_client: TestClient, scenario: dict[str, int], monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_: Any) -> Any:
        raise RuntimeError("таблицы модуля нет")

    for name in ("_asset_of", "_vm_counts", "_ksc_names"):
        monkeypatch.setattr(dc_links_service, name, boom)
    r = auth_client.get(f"/api/ad/domains/{scenario['domain_id']}/dc-links")
    assert r.status_code == 200, r.text
    for row in r.json():
        assert row["asset_id"] is None and row["ips"] == [] and row["in_ad_subnet"] is None
        assert row["vm"] is None and row["ksc_agent"] is None


def test_unknown_domain_404_and_no_summary_empty(auth_client: TestClient, db_session: Session) -> None:
    assert auth_client.get("/api/ad/domains/999999/dc-links").status_code == 404
    domain_id = _domain(db_session, None)
    assert auth_client.get(f"/api/ad/domains/{domain_id}/dc-links").json() == []
    bare = AdDomain(sid="S-1-5-21-1-1-1", dns_root="empty.local")
    db_session.add(bare)
    db_session.commit()
    assert auth_client.get(f"/api/ad/domains/{bare.id}/dc-links").json() == []


def test_sql_error_in_one_module_keeps_other_fields(auth_client: TestClient, scenario: dict[str, int], monkeypatch: pytest.MonkeyPatch) -> None:
    """Ошибка запроса (нет таблицы) откатывает только свою точку сохранения: остальные поля читаются."""
    from sqlalchemy import text

    def missing_table(db: Session, _names: Any) -> Any:
        return db.execute(text("SELECT 1 FROM vm_table_that_does_not_exist")).scalar()

    monkeypatch.setattr(dc_links_service, "_vm_counts", missing_table)
    first, second = auth_client.get(f"/api/ad/domains/{scenario['domain_id']}/dc-links").json()
    assert first["vm"] is None and second["vm"] is None
    assert first["asset_id"] == scenario["dc01"] and second["asset_id"] == scenario["dc02"]
    assert first["ksc_agent"] is True and second["in_ad_subnet"] is False
