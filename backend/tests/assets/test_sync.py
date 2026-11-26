"""Синхронизация с VM/KSC/AD: наблюдения, сопоставление, расхождения, gone_at, хуки модулей."""
from __future__ import annotations

import datetime as dt
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session

from api.db.base import get_engine
from api.jobs import run_job, start_job
from api.modules.assets.core.matching import Observed
from api.modules.assets.models import Asset, AssetJob, AssetObservation, AssetSettings
from api.modules.assets.services import sync as sync_service
from api.modules.assets.services.assets import apply_observation, asset_detail, pin_field
from api.modules.assets.services.sync import request_sync, run_sync
from api.modules.ksc.models import KscHost, KscServer
from api.modules.vm.models import VmHost
from api.platform.scheduler import PlatformSchedule, tick
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
    assert counts == {"vm": 2, "ksc": 2, "ad": 3, "users": 17, "groups": 5}
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


def test_ad_observation_has_laps_flag(db_session: Session, app_settings: Any, now: dt.datetime) -> None:
    """LAPS — есть срок пароля нового (`lapsNewExpiry`) или старого (`lapsExpiry`) LAPS."""
    from tests.ad.synthetic import ft
    from tests.assets.synthetic import computer, load_ad

    set_settings(db_session, sync_after_import=False)
    load_ad(db_session, Path(app_settings.data_dir), [
        {**computer("WS01$", 1201, last_logon=now), "lapsNewExpiry": ft(-30)},
        {**computer("WS02$", 1202, last_logon=now), "lapsExpiry": ft(-30)},
        computer("WS03$", 1203, last_logon=now),
    ], now)
    sync(db_session)
    laps = dict(db_session.execute(select(AssetObservation.name, AssetObservation.extra).where(AssetObservation.source == "ad")).tuples().all())
    assert {name: extra["laps"] for name, extra in laps.items()} == {"WS01": True, "WS02": True, "WS03": False}


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
    assert srv01.name == "SRV01"  # AD главнее более свежего имени KSC
    srv01.name = "analyst alias"
    pin_field(loaded, srv01.id, "name", True)
    loaded.commit()
    rename("CORE02")
    sync(loaded)
    loaded.refresh(srv01)
    assert srv01.name == "analyst alias"
    pin_field(loaded, srv01.id, "name", False)
    assert srv01.name == "SRV01"


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
    asset, _ = apply_observation(db_session, Observed(source="dns", source_key="v6", ip="2001:DB8:0:0::5", ips=["2001:DB8:0:0::5"], seen_at=now))
    row = db_session.execute(select(AssetObservation).where(AssetObservation.source_key == "v6")).scalar_one()
    assert (row.ip, row.ips, asset.ip) == ("2001:db8::5", ["2001:db8::5"], "2001:db8::5")


def rerun_flag(db: Session) -> bool:
    data = db.execute(select(AssetSettings.data)).scalar()
    return bool((data or {}).get("rerun_requested"))


def test_sync_is_single_flight(loaded: Session) -> None:
    """Вторая синхронизация, пока первая держит блокировку, ничего не пишет и завершается."""
    start_job(loaded, AssetJob, "sync", "tester")  # первая: идёт и держит блокировку
    with get_engine().connect() as conn:
        assert conn.execute(text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": sync_service.SYNC_LOCK_KEY}).scalar()
        job_id = start_job(loaded, AssetJob, "sync", "tester")
        run_job(AssetJob, job_id, lambda s, h: sync_service.sync_job(s, h, "вручную"))
        conn.rollback()
    job = loaded.get(AssetJob, job_id)
    loaded.refresh(job)
    assert job is not None and (job.status, job.message) == ("done", "синхронизация уже идёт")
    assert loaded.execute(select(func.count()).select_from(AssetObservation)).scalar() == 0
    assert rerun_flag(loaded)  # держатель блокировки пройдёт ещё раз
    sync(loaded)
    assert loaded.execute(select(func.count()).select_from(AssetObservation)).scalar() == 7


def test_sync_waits_for_dns_or_rt_write(loaded: Session) -> None:
    """Блокировку держит запись DNS или RackTables, а не синхронизация: синхронизация ждёт её и проходит,
    а не отбрасывается как «уже идёт»."""
    locked = threading.Event()

    def writer() -> None:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": sync_service.SYNC_LOCK_KEY})
            locked.set()
            time.sleep(1.0)
            conn.rollback()

    holder = threading.Thread(target=writer)
    holder.start()
    assert locked.wait(5)
    started = time.monotonic()
    counts = sync(loaded)
    waited = time.monotonic() - started
    holder.join()
    assert waited >= 0.5
    assert counts == {"vm": 2, "ksc": 2, "ad": 3, "users": 17, "groups": 5}
    assert loaded.execute(select(func.count()).select_from(AssetObservation)).scalar() == 7
    assert not rerun_flag(loaded)


def test_request_during_sync_runs_one_more_pass(loaded: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    set_settings(loaded, sync_after_import=True)
    real_read = sync_service._read
    reads: list[str] = []
    asked: list[int | None] = []

    def read(db: Session, source: str, data_dir: Path, cache: Any = None) -> Any:
        reads.append(source)
        if len(reads) == 1:
            asked.append(request_sync(loaded, "ksc"))  # импорт KSC закончился посреди синхронизации
        return real_read(db, source, data_dir, cache)

    monkeypatch.setattr(sync_service, "_read", read)
    sync(loaded)
    assert asked == [None]
    assert reads == ["vm", "ksc", "ad"] * 2
    assert not rerun_flag(loaded)
    assert loaded.execute(select(func.count()).select_from(AssetJob)).scalar() == 1


def test_ad_finding_count_matches_whole_computer_name(loaded: Session) -> None:
    from api.modules.ad.models import AdFinding, AdSnapshot

    sync(loaded)
    ws01 = live_assets(loaded)["ws01"]

    def count() -> int:
        return int(asset_detail(loaded, ws01.id)["links"]["ad_finding_count"])

    before = count()
    snap_id = loaded.execute(select(AdSnapshot.id).order_by(AdSnapshot.id.desc())).scalars().first()

    def finding(identity: str = "", target: str = "") -> None:
        loaded.add(AdFinding(snapshot_id=snap_id, key=f"k-{identity}-{target}", check="X", severity="Low", severity_original="Low",
                             identity=identity, target=target))
        loaded.commit()

    finding(identity="CORP\\WS010$")
    finding(target="ws010.corp.local")
    assert count() == before
    finding(identity="CORP\\ws01$")
    finding(target="WS01.corp.local")
    finding(identity="ws01$")
    assert count() == before + 3
    # Принятый риск по умолчанию не учитывается — и в карточке актива тоже.
    from api.platform.findings.models import FindingState

    domain_id = loaded.get(AdSnapshot, snap_id).domain_id  # type: ignore[union-attr]
    loaded.add(FindingState(module="ad", scope_id=domain_id, key="k-ws01$-", status="risk_accepted", reason="норма",
                            present=True, title="", severity="", updated_by="tester"))
    loaded.commit()
    assert count() == before + 2


def test_request_sync_respects_running_job_and_setting(db_session: Session, app_settings: Any) -> None:
    start_job(db_session, AssetJob, "sync", "tester")
    assert request_sync(db_session, "vm") is None
    assert rerun_flag(db_session)  # идущая синхронизация сделает ещё один проход


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
    assert jobs[0].message == "KSC: VM 0 · KSC 1 · AD 0 · пользователи 2 · группы 0"
    assert set(live_assets(db_session)) == {"srv01"}


def test_failing_assets_never_fail_the_import(db_session: Session, app_settings: Any, now: dt.datetime, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(db: Session, source: str) -> int | None:
        raise RuntimeError("assets сломался")

    monkeypatch.setattr(sync_service, "request_sync", boom)
    snap = load_ksc(db_session, Path(app_settings.data_dir), [("SRV01", "10.10.0.11")], now)
    assert snap.id is not None and snap.hosts == 1


# ---- Расписание -------------------------------------------------------------


def test_sync_schedule_routes(db_session: Session, app_settings: Any, client_as: Any) -> None:
    admin = client_as({"assets": "admin"})
    url = "/api/assets/sync/schedule"
    assert admin.get(url).json() is None
    r = admin.put(url, json={"interval_hours": 6, "window_from": "01:00", "window_to": "04:00", "enabled": True})
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["interval_hours"], body["window_from"], body["window_to"], body["enabled"]) == (6, "01:00", "04:00", True)
    assert body["next_run_at"] is not None and body["tz"]
    db_session.expire_all()
    sched = db_session.execute(select(PlatformSchedule)).scalar_one()
    assert (sched.module, sched.kind, sched.target_id) == ("assets", "sync", 0)
    assert admin.get(url).json()["id"] == sched.id
    r = admin.put(url, json={"interval_hours": 12, "window_from": None, "window_to": None, "enabled": False})
    assert r.status_code == 200 and r.json()["id"] == sched.id and r.json()["enabled"] is False
    assert admin.put(url, json={"interval_hours": 12, "window_from": "02:00", "window_to": None, "enabled": True}).status_code == 422
    assert admin.put(url, json={"interval_hours": 0, "window_from": None, "window_to": None, "enabled": True}).status_code == 422
    assert admin.delete(url).status_code == 204
    assert admin.get(url).json() is None
    db_session.expire_all()
    assert db_session.execute(select(PlatformSchedule)).scalars().all() == []


def test_auditor_cannot_change_sync_schedule(db_session: Session, app_settings: Any, client_as: Any) -> None:
    auditor = client_as("auditor")
    url = "/api/assets/sync/schedule"
    assert auditor.get(url).status_code == 200
    assert auditor.put(url, json={"interval_hours": 24, "window_from": None, "window_to": None, "enabled": True}).status_code == 403
    assert auditor.delete(url).status_code == 403


def test_scheduler_tick_runs_sync(loaded: Session, client_as: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sync_service, "spawn", lambda fn: fn())
    r = client_as({"assets": "admin"}).put("/api/assets/sync/schedule", json={"interval_hours": 1, "window_from": None, "window_to": None, "enabled": True})
    assert r.status_code == 200, r.text
    started = tick(loaded, dt.datetime.now(dt.UTC) + dt.timedelta(hours=2))
    assert len(started) == 1
    from api.platform.sync_queue.models import SyncStep
    from api.platform.sync_queue.worker import dispatch
    dispatch(loaded)
    step = loaded.scalar(select(SyncStep).where(SyncStep.run_id == started[0]))
    job = loaded.get(AssetJob, step.job_id)
    assert job is not None
    loaded.refresh(job)
    assert (job.kind, job.status, job.started_by) == ("sync", "done", "расписание"), job.error
    assert loaded.execute(select(func.count()).select_from(AssetObservation)).scalar() == 7


def test_sync_schedule_handler_waits_for_running_sync(db_session: Session, app_settings: Any) -> None:
    start_job(db_session, AssetJob, "sync", "tester")
    sched = PlatformSchedule(module="assets", kind="sync", target_id=0, interval_hours=24, enabled=True)
    assert sync_service.schedule_handler(db_session, sched) is None
    assert db_session.execute(select(func.count()).select_from(AssetJob)).scalar() == 1
