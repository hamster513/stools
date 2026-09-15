from __future__ import annotations

import json
from typing import Any

from fastapi.testclient import TestClient

from api.modules.ad.core.export import load_export as load_ad_export
from api.modules.ksc.core.checks import CHECK_BY_CODE, run_all
from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.coverage import AdComputer, ad_computers_from_export, match
from api.modules.ksc.core.export import ExportIndex, load_export
from tests.ad.synthetic import build_export as build_ad
from tests.ksc.synthetic import export_bytes


def _ad(names: list[str]) -> list[AdComputer]:
    return [AdComputer(name=n, fqdn=f"{n.lower()}.corp.local", domain="corp.local", netbios="CORP", os="Windows 11", last_logon="2026-09-10") for n in names]


def test_match_by_fqdn_and_short_name() -> None:
    idx = ExportIndex(load_export(export_bytes()))
    cov = match(idx.hosts, _ad(["WS01", "WS02", "PRINT01"]))
    assert cov.ad_total == 3 and cov.ksc_total == 14
    assert {h for h in cov.both} == {"h-ws01", "h-ws02"}
    assert [c.name for c in cov.ad_only] == ["PRINT01"]
    assert "h-wg01" in cov.ksc_only and "h-ws03" in cov.ksc_only


def test_cover_checks() -> None:
    idx = ExportIndex(load_export(export_bytes()))
    idx.ad_computers = _ad(["WS01", "PRINT01"])
    f = run_all(idx, KscConfig())
    missing = [x for x in f if x.check == "COVER_AD_MISSING"]
    assert len(missing) == 1 and missing[0].host == "PRINT01" and missing[0].severity == "High" and missing[0].details["last_logon"] == "2026-09-10"
    only = {x.host for x in f if x.check == "COVER_KSC_ONLY"}
    assert only == {"WS02", "WS03", "WS04", "WS05", "WS06", "WS07", "WS08", "WS09", "WS10", "WS11", "SRV01", "LAB01", "WG01"}
    assert all(x.severity == "Info" for x in f if x.check == "COVER_KSC_ONLY")


def test_cover_checks_silent_without_ad() -> None:
    idx = ExportIndex(load_export(export_bytes()))
    assert idx.ad_computers is None
    f = run_all(idx, KscConfig())
    assert not [x for x in f if x.check.startswith("COVER_")]
    assert "COVER_AD_MISSING" in CHECK_BY_CODE


def test_ad_computers_from_export_uses_enabled_computers() -> None:
    export = load_ad_export(json.dumps(build_ad()).encode())
    computers = ad_computers_from_export(export)
    assert {c.name for c in computers} == {"WS01", "SRV01"}
    for c in computers:
        assert c.fqdn == f"{c.name.lower()}.corp.local"
        assert c.netbios == "CORP"
        year, month, day = c.last_logon.split("-")
        assert len(year) == 4 and len(month) == 2 and len(day) == 2
    # Сборщики AD сегодня не выгружают operatingSystem — поле остаётся пустым,
    # заполнится само, если выгрузка когда-нибудь станет его нести.
    assert all(c.os == "" for c in computers)

    raw = build_ad()
    ws01 = next(o for o in raw["objects"] if o.get("sam") == "WS01$")
    ws01["uac"] = 4096 | 0x2  # UAC_DISABLED
    disabled = ad_computers_from_export(load_ad_export(json.dumps(raw).encode()))
    assert {c.name for c in disabled} == {"SRV01"}


def test_service_finds_latest_ad_snapshot(auth_client: TestClient, db_session: Any, app_settings: Any) -> None:
    from api.modules.ksc.services.coverage import ad_computers_for

    export = load_export(export_bytes())
    assert ad_computers_for(db_session, export, app_settings.data_dir) is None
    ad = build_ad()
    r = auth_client.post("/api/ad/snapshots/file", files={"file": ("ad.json", json.dumps(ad).encode(), "application/json")})
    assert auth_client.get(f"/api/ad/jobs/{r.json()['job_id']}").json()["status"] == "done"
    computers = ad_computers_for(db_session, export, app_settings.data_dir)
    assert computers is not None and {c.name for c in computers} == {"WS01", "SRV01"}
    assert all(c.domain == "corp.local" and c.netbios == "CORP" for c in computers)
