"""Синхронизация с VM/KSC/AD: наблюдения, сопоставление, расхождения, gone_at, хуки модулей."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from api.jobs import run_job, start_job
from api.modules.assets.core.matching import Observed
from api.modules.assets.models import Asset, AssetJob, AssetObservation, AssetSettings
from api.modules.assets.services import sync as sync_service
from api.modules.assets.services.assets import apply_observation, asset_detail, pin_field
from api.modules.assets.services.sync import request_sync, run_sync
from api.modules.ksc.models import KscHost, KscServer
from api.modules.vm.models import VmHost
from tests.assets.synthetic import load_all, load_ksc


def set_settings(db: Session, **data: Any) -> None:
    row = db.execute(select(AssetSettings)).scalars().first()
    if row is None:
        db.add(AssetSettings(data=data))
    else:
        row.data = {**row.data, **data}
    db.commit()


def sync(db: Session) -> dict[str, int]:
    out: dict[str, int] = {}
    job_id = start_job(db, AssetJob, "sync", "tester")
    run_job(AssetJob, job_id, lambda s, h: out.update(run_sync(s, h)))
    job = db.get(AssetJob, job_id)
    db.refresh(job)
    assert job is not None and job.status == "done", job.error if job else None
    db.expire_all()
    return out


def live_assets(db: Session) -> dict[str, Asset]:
    rows = db.execute(select(Asset).where(Asset.merged_into.is_(None))).scalars()
    return {a.name_key: a for a in rows}


@pytest.fixture
def now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


@pytest.fixture
def loaded(db_session: Session, app_settings: Any, now: dt.datetime) -> Session:
    """Три источника без автоматической синхронизации: её запускает сам тест."""
    set_settings(db_session, sync_after_import=False)
    load_all(db_session, Path(app_settings.data_dir), now)
    return db_session


def test_sync_creates_one_asset_per_host(loaded: Session) -> None:
    counts = sync(loaded)
    assert counts == {"vm": 2, "ksc": 2, "ad": 3}
    assets = live_assets(loaded)
    assert set(assets) == {"msk1", "ws01", "srv01", "old01"}
    per_asset = dict(loaded.execute(select(AssetObservation.asset_id, func.count()).group_by(AssetObservation.asset_id)).tuples().all())
    assert per_asset[assets["srv01"].id] == 3 and per_asset[assets["msk1"].id] == 2
    assert assets["srv01"].fqdn == "srv01.corp.local" and assets["srv01"].ip == "10.10.0.11"
    # KSC свежее VM на час: канонический адрес — из KSC.
    assert assets["msk1"].ip == "192.168.2.23" and assets["msk1"].fqdn == "msk1.corp.local"


def test_msk1_conflict_then_stale_with_zero_threshold(loaded: Session) -> None:
    sync(loaded)
    msk1 = live_assets(loaded)["msk1"]
    found = [(d["code"], d["source"], d["field"]) for d in asset_detail(loaded, msk1.id)["discrepancies"]]
    assert ("conflict", "vm", "ip") in found and not any(c == "stale" for c, _, _ in found)
    set_settings(loaded, stale_days=0)
    found = [(d["code"], d["source"], d["field"]) for d in asset_detail(loaded, msk1.id)["discrepancies"]]
    assert ("stale", "vm", "ip") in found and not any(c == "conflict" for c, _, _ in found)


def test_ws01_has_no_av_and_old01_is_inactive(loaded: Session) -> None:
    sync(loaded)
    assets = live_assets(loaded)
    ws01 = {d["code"] for d in asset_detail(loaded, assets["ws01"].id)["discrepancies"]}
    old01 = {d["code"] for d in asset_detail(loaded, assets["old01"].id)["discrepancies"]}
    srv01 = {d["code"] for d in asset_detail(loaded, assets["srv01"].id)["discrepancies"]}
    assert "no_av" in ws01 and "ad_inactive" not in ws01
    assert "ad_inactive" in old01
    assert "no_av" not in srv01 and "ad_inactive" not in srv01


def test_ad_observation_carries_computer_attributes(loaded: Session) -> None:
    sync(loaded)
    obs = loaded.execute(select(AssetObservation).where(AssetObservation.source == "ad", AssetObservation.name == "OLD01")).scalar_one()
    assert obs.fqdn == "old01.corp.local" and obs.domain == "corp.local" and obs.os == "Windows 11 Pro"
    assert obs.extra["enabled"] is True and obs.extra["os_version"] == "10.0 (22631)"
    assert obs.extra["last_logon"].startswith(str((dt.datetime.now(dt.UTC) - dt.timedelta(days=120)).date()))


def test_repeated_sync_does_not_duplicate(loaded: Session) -> None:
    sync(loaded)
    sync(loaded)
    assert len(live_assets(loaded)) == 4
    assert loaded.execute(select(func.count()).select_from(AssetObservation)).scalar() == 7


def test_host_missing_from_vm_gets_gone_at(loaded: Session) -> None:
    sync(loaded)
    loaded.execute(VmHost.__table__.delete().where(VmHost.hostname == "srv01.corp.local"))
    loaded.commit()
    sync(loaded)
    vm_obs = loaded.execute(select(AssetObservation).where(AssetObservation.source == "vm", AssetObservation.source_key.startswith("srv01"))).scalar_one()
    assert vm_obs.gone_at is not None
    msk1_vm = loaded.execute(select(AssetObservation).where(AssetObservation.source == "vm", AssetObservation.source_key.startswith("msk1"))).scalar_one()
    assert msk1_vm.gone_at is None
    # Хост вернулся — наблюдение снова живое.
    loaded.add(VmHost(hostname="srv01.corp.local", ip="10.10.0.11", os_name="Windows Server 2022"))
    loaded.commit()
    sync(loaded)
    loaded.refresh(vm_obs)
    assert vm_obs.gone_at is None


def test_pinned_name_survives_resync(loaded: Session, now: dt.datetime) -> None:
    sync(loaded)
    srv01 = live_assets(loaded)["srv01"]

    def rename(name: str) -> None:
        loaded.execute(update(KscHost).where(KscHost.host_id == "h-srv01").values(name=name))
        loaded.commit()

    rename("CORE01")
    sync(loaded)
    loaded.refresh(srv01)
    assert srv01.name == "CORE01"  # без закрепления имя берётся у самого свежего источника
    pin_field(loaded, srv01.id, "name", True)
    loaded.commit()
    rename("CORE02")
    sync(loaded)
    loaded.refresh(srv01)
    assert srv01.name == "CORE01"


def ksc_keys(db: Session) -> list[str]:
    return sorted(db.execute(select(AssetObservation.source_key).where(AssetObservation.source == "ksc")).scalars())


def test_ksc_key_is_server_and_host(loaded: Session) -> None:
    sync(loaded)
    server_id = loaded.execute(select(KscServer.id)).scalar_one()
    assert ksc_keys(loaded) == [f"{server_id}:h-msk1", f"{server_id}:h-srv01"]
    srv01 = live_assets(loaded)["srv01"]
    links = asset_detail(loaded, srv01.id)["links"]
    assert links["ksc_host_id"] == "h-srv01" and links["ksc_server_id"] == server_id


def test_same_host_id_on_two_ksc_servers_is_kept(loaded: Session, app_settings: Any, now: dt.datetime) -> None:
    load_ksc(loaded, Path(app_settings.data_dir), [("SRV01", "10.10.0.11")], now, server="ksc02")
    counts = sync(loaded)
    assert counts["ksc"] == 3 and len(ksc_keys(loaded)) == 3
    srv01 = live_assets(loaded)["srv01"]
    assert sorted(o["source"] for o in asset_detail(loaded, srv01.id)["observations"]) == ["ad", "ksc", "ksc", "vm"]


def test_old_ksc_keys_are_migrated_not_duplicated(loaded: Session) -> None:
    sync(loaded)
    for row in loaded.execute(select(AssetObservation).where(AssetObservation.source == "ksc")).scalars():
        row.source_key = row.source_key.partition(":")[2]  # ключ до исправления — только host_id
    loaded.commit()
    sync(loaded)
    server_id = loaded.execute(select(KscServer.id)).scalar_one()
    assert ksc_keys(loaded) == [f"{server_id}:h-msk1", f"{server_id}:h-srv01"]
    assert loaded.execute(select(func.count()).select_from(AssetObservation).where(AssetObservation.gone_at.is_not(None))).scalar() == 0


def test_netbios_vm_name_is_matched_by_ad_domain_map(loaded: Session, now: dt.datetime) -> None:
    """У VM имя `CORP\\ws01`; рядом есть домен `corp.example` — первая метка неоднозначна,
    но выгрузка AD говорит, что CORP — это corp.local."""
    sync(loaded)
    apply_observation(loaded, Observed(source="dns", source_key="ws01.corp.example", fqdn="ws01.corp.example", ip="10.30.0.1", seen_at=now))
    loaded.add(VmHost(hostname="CORP\\ws01", ip="", os_name="Windows 11"))
    loaded.commit()
    sync(loaded)
    vm_obs = loaded.execute(select(AssetObservation).where(AssetObservation.source == "vm", AssetObservation.source_key == "CORP\\ws01|")).scalar_one()
    ad_obs = loaded.execute(select(AssetObservation).where(AssetObservation.source == "ad", AssetObservation.name == "WS01")).scalar_one()
    assert vm_obs.asset_id == ad_obs.asset_id


def test_single_observation_finds_asset_by_normalised_observation_name(db_session: Session, app_settings: Any, now: dt.datetime) -> None:
    """Одиночная привязка (скан, DNS) ищет кандидатов в базе: имя наблюдения `WS01$` или с точкой — то же `ws01`."""
    for canonical_name, obs_name in (("core", "WS01$"), ("edge", "SRV01.corp.local"), ("hub", "CORP\\WS02$")):
        asset = Asset(name=canonical_name, name_key=canonical_name, pinned={"name": True})
        db_session.add(asset)
        db_session.flush()
        db_session.add(AssetObservation(asset_id=asset.id, source="ksc", source_key=f"1:{obs_name}", name=obs_name, seen_at=now))
    db_session.commit()
    ids = dict(db_session.execute(select(Asset.name_key, Asset.id)).tuples().all())
    got, rule = apply_observation(db_session, Observed(source="vm", source_key="ws01|", name="ws01", seen_at=now))
    assert (got.id, rule) == (ids["core"], 4)
    got, rule = apply_observation(db_session, Observed(source="vm", source_key="srv01|", name="srv01", seen_at=now))
    assert (got.id, rule) == (ids["edge"], 4)
    got, rule = apply_observation(db_session, Observed(source="vm", source_key="ws02|", name="ws02", seen_at=now))
    assert (got.id, rule) == (ids["hub"], 4)


def test_ips_are_stored_normalised(db_session: Session, app_settings: Any, now: dt.datetime) -> None:
    asset, _ = apply_observation(db_session, Observed(source="scan", source_key="v6", ip="2001:DB8:0:0::5", ips=["2001:DB8:0:0::5"], seen_at=now))
    row = db_session.execute(select(AssetObservation).where(AssetObservation.source_key == "v6")).scalar_one()
    assert (row.ip, row.ips, asset.ip) == ("2001:db8::5", ["2001:db8::5"], "2001:db8::5")


def test_request_sync_respects_running_job_and_setting(db_session: Session, app_settings: Any) -> None:
    start_job(db_session, AssetJob, "sync", "tester")
    assert request_sync(db_session, "vm") is None


def test_request_sync_disabled_by_setting(db_session: Session, app_settings: Any) -> None:
    set_settings(db_session, sync_after_import=False)
    assert request_sync(db_session, "vm") is None
    assert db_session.execute(select(func.count()).select_from(AssetJob)).scalar() == 0


def test_request_sync_starts_job(db_session: Session, app_settings: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    started: list[Any] = []
    monkeypatch.setattr(sync_service, "spawn", started.append)
    job_id = request_sync(db_session, "ad")
    assert job_id is not None and len(started) == 1
    job = db_session.get(AssetJob, job_id)
    assert job is not None and job.kind == "sync" and job.message == "ad" and job.status == "running"


def test_ksc_import_requests_sync(db_session: Session, app_settings: Any, now: dt.datetime) -> None:
    load_ksc(db_session, Path(app_settings.data_dir), [("SRV01", "10.10.0.11")], now)
    jobs = db_session.execute(select(AssetJob)).scalars().all()
    assert [(j.kind, j.status, j.started_by) for j in jobs] == [("sync", "done", "после импорта")]
    assert jobs[0].message == "KSC: VM 0 · KSC 1 · AD 0"
    assert set(live_assets(db_session)) == {"srv01"}


def test_failing_assets_never_fail_the_import(db_session: Session, app_settings: Any, now: dt.datetime, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(db: Session, source: str) -> int | None:
        raise RuntimeError("assets сломался")

    monkeypatch.setattr(sync_service, "request_sync", boom)
    snap = load_ksc(db_session, Path(app_settings.data_dir), [("SRV01", "10.10.0.11")], now)
    assert snap.id is not None and snap.hosts == 1
