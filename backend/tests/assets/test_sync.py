"""Синхронизация с VM/KSC/AD: наблюдения, сопоставление, расхождения, gone_at, хуки модулей."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from api.jobs import run_job, start_job
from api.modules.assets.models import Asset, AssetJob, AssetObservation, AssetSettings
from api.modules.assets.services import sync as sync_service
from api.modules.assets.services.assets import asset_detail, pin_field
from api.modules.assets.services.sync import request_sync, run_sync
from api.modules.ksc.models import KscHost
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
