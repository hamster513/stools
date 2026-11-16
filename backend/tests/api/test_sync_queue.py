"""Contracts for the persistent, shared synchronization queue."""
import datetime as dt

import pytest
from sqlalchemy import select

from api.platform.sync_queue import worker
from api.platform.sync_queue.adapters import JobRef
from api.platform.sync_queue.models import SyncJob, SyncRun, SyncStep

URL = "/api/settings/sync-runs"
DEPS = "/api/settings/schedules"
A = {"module": "vm", "kind": "ref_epss", "target_id": 0}
B = {"module": "vm", "kind": "ref_nvd", "target_id": 0}
C = {"module": "assets", "kind": "sync", "target_id": 0}


def key(task):
    return f"{task['module']}/{task['kind']}/{task['target_id']}"


def dependencies(client, task, *needs):
    return client.put(f"{DEPS}/{key(task)}/dependencies", json={"dependencies": [
        {**other, "max_age_minutes": minutes} for other, minutes in needs
    ]})


def enqueue(client, *tasks):
    response = client.post(URL, json={"tasks": list(tasks)})
    assert response.status_code == 202, response.text
    return response.json()


def test_queue_deduplicates_clicks_and_persists_without_starting(auth_client, db_session):
    first = enqueue(auth_client, A, B)
    again = enqueue(auth_client, A, B)
    assert again["id"] == first["id"]
    assert first["status"] == "queued"
    rows = list(db_session.scalars(select(SyncStep).where(SyncStep.run_id == first["id"])))
    assert len(rows) == 2 and all(row.job_id is None for row in rows)
    db_session.expire_all()
    assert auth_client.get(f"{URL}/{first['id']}").json()["status"] == "queued"


def test_dependency_graph_rejects_cycles_unknown_targets_and_hunting(auth_client):
    assert dependencies(auth_client, C, (A, 60)).status_code == 200
    assert dependencies(auth_client, A, (C, 60)).status_code == 422
    assert dependencies(auth_client, A, (A, 60)).status_code == 422
    hunting = {"module": "siem", "kind": "th_nightly", "target_id": 0}
    assert dependencies(auth_client, A, (hunting, 60)).status_code == 404
    assert auth_client.post(URL, json={"tasks": [hunting]}).status_code == 404
    assert dependencies(auth_client, A, (B, 0)).status_code == 422


def test_permissions_include_dependencies_and_history(client_as, auth_client):
    assert dependencies(auth_client, C, (A, 60)).status_code == 200
    analyst = client_as({"assets": "write"})
    assert analyst.post(URL, json={"tasks": [C]}).status_code == 403
    assert dependencies(analyst, C, (A, 60)).status_code == 403
    run = enqueue(auth_client, A)
    assert analyst.get(f"{URL}/{run['id']}").status_code == 404
    assert client_as({"vm": "read"}).post(URL, json={"tasks": [A]}).status_code == 403


def fake_jobs(monkeypatch, db_session):
    launched = []
    stamps = {}
    def start(db, task, actor, options):
        row = SyncJob(kind=task.kind, status="running", started_by=actor)
        db.add(row)
        db.commit()
        launched.append((task.key, row.id))
        return JobRef("platform_sync_job", row.id)
    def observe(db, task):
        return stamps.get(task.key)
    monkeypatch.setattr(worker, "start_task", start)
    monkeypatch.setattr(worker, "observed_at", observe)
    return launched, stamps


def finish(db, job_id, status="done"):
    row = db.get(SyncJob, job_id)
    row.status = status
    row.finished_at = dt.datetime.now(dt.UTC)
    row.error = "Источник недоступен" if status == "failed" else None
    db.commit()


def test_fifo_waits_for_completion_and_skips_fresh_dependencies(auth_client, db_session, monkeypatch):
    launched, stamps = fake_jobs(monkeypatch, db_session)
    stamps[key(A)] = dt.datetime.now(dt.UTC)
    assert dependencies(auth_client, C, (A, 60)).status_code == 200
    run = enqueue(auth_client, C, B)
    worker.dispatch(db_session)
    assert [item[0] for item in launched] == [key(C)]
    worker.dispatch(db_session)
    assert len(launched) == 1
    finish(db_session, launched[0][1])
    worker.dispatch(db_session)
    assert [item[0] for item in launched] == [key(C), key(B)]
    finish(db_session, launched[1][1])
    worker.dispatch(db_session)
    view = auth_client.get(f"{URL}/{run['id']}").json()
    assert view["status"] == "done"
    assert next(s for s in view["steps"] if s["key"] == key(A))["status"] == "fresh"


def test_failed_dependency_blocks_consumer_but_other_root_continues(auth_client, db_session, monkeypatch):
    launched, _ = fake_jobs(monkeypatch, db_session)
    assert dependencies(auth_client, C, (A, 60)).status_code == 200
    run = enqueue(auth_client, C, B)
    worker.dispatch(db_session)
    assert launched[0][0] == key(A)
    finish(db_session, launched[0][1], "failed")
    worker.dispatch(db_session)
    assert [item[0] for item in launched] == [key(A), key(B)]
    finish(db_session, launched[1][1])
    worker.dispatch(db_session)
    view = auth_client.get(f"{URL}/{run['id']}").json()
    assert view["status"] == "partial"
    assert next(s for s in view["steps"] if s["key"] == key(C))["status"] == "blocked"


def test_cancel_waiting_does_not_start_jobs_and_retry_creates_new_run(auth_client, db_session, monkeypatch):
    launched, _ = fake_jobs(monkeypatch, db_session)
    run = enqueue(auth_client, A, B)
    assert auth_client.post(f"{URL}/{run['id']}/cancel").status_code == 200
    worker.dispatch(db_session)
    assert launched == []
    assert auth_client.get(f"{URL}/{run['id']}").json()["status"] == "cancelled"
    retry = auth_client.post(f"{URL}/{run['id']}/retry")
    assert retry.status_code == 202 and retry.json()["id"] != run["id"]


def test_interrupted_started_step_fails_instead_of_repeating(auth_client, db_session, monkeypatch):
    launched, _ = fake_jobs(monkeypatch, db_session)
    run = enqueue(auth_client, A, B)
    row = db_session.scalar(select(SyncStep).where(SyncStep.run_id == run["id"], SyncStep.key == key(A)))
    row.status = "starting"
    db_session.commit()
    worker.dispatch(db_session)
    assert [item[0] for item in launched] == [key(B)]
    assert auth_client.get(f"{URL}/{run['id']}").json()["steps"][0]["status"] == "failed"


def test_stale_dependency_updates_first_and_graph_is_frozen(auth_client, db_session, monkeypatch):
    launched, stamps = fake_jobs(monkeypatch, db_session)
    stamps[key(A)] = dt.datetime.now(dt.UTC) - dt.timedelta(hours=2)
    assert dependencies(auth_client, C, (A, 60)).status_code == 200
    run = enqueue(auth_client, C)
    assert dependencies(auth_client, C, (B, 60)).status_code == 200
    worker.dispatch(db_session)
    assert launched[0][0] == key(A)
    finish(db_session, launched[0][1])
    worker.dispatch(db_session)
    assert launched[1][0] == key(C)
    assert key(B) not in [s["key"] for s in auth_client.get(f"{URL}/{run['id']}").json()["steps"]]


def test_fresh_dependency_does_not_refresh_its_ancestors(auth_client, db_session, monkeypatch):
    launched, stamps = fake_jobs(monkeypatch, db_session)
    assert dependencies(auth_client, A, (B, 60)).status_code == 200
    assert dependencies(auth_client, C, (A, 60)).status_code == 200
    stamps[key(A)] = dt.datetime.now(dt.UTC)
    enqueue(auth_client, C)
    worker.dispatch(db_session)
    assert [item[0] for item in launched] == [key(C)]


def test_revoked_account_cannot_start_waiting_job(auth_client, db_session, monkeypatch):
    from api.db.models import AppUser
    launched, _ = fake_jobs(monkeypatch, db_session)
    run = enqueue(auth_client, A)
    row = db_session.get(SyncRun, run["id"])
    db_session.get(AppUser, row.user_id).is_active = False
    db_session.commit()
    worker.dispatch(db_session)
    worker.dispatch(db_session)
    assert launched == []
    assert db_session.get(SyncRun, run["id"]).status == "failed"


def test_queue_preserves_download_scope_and_requires_cleanup_confirmation(auth_client, db_session, client_as):
    run = enqueue(auth_client, {**B, "options": {"years": [2024], "mode": "full"}})
    row = db_session.scalar(select(SyncStep).where(SyncStep.run_id == run["id"]))
    assert row.options == {"years": [2024], "mode": "full"}
    cleanup = {"module": "platform", "kind": "storage_cleanup", "target_id": 0}
    assert auth_client.post(URL, json={"tasks": [cleanup]}).status_code == 422
    full = {"module": "vm", "kind": "trends_pull", "target_id": 0, "options": {"reset": True}}
    assert client_as({"vm": "write"}).post(URL, json={"tasks": [full]}).status_code == 403


def test_source_auto_sync_joins_queue(auth_client, db_session, monkeypatch):
    from sqlalchemy import func

    from api.modules.assets.services import sync
    fake_jobs(monkeypatch, db_session)
    enqueue(auth_client, A)
    worker.dispatch(db_session)
    direct = []
    monkeypatch.setattr(sync, "load_settings", lambda db: {"sync_after_import": True})
    monkeypatch.setattr(sync, "spawn", direct.append)
    sync.request_sync(db_session, "vm")
    assert direct == []
    assert db_session.scalar(select(func.count()).select_from(SyncRun)) == 2


def test_hunting_handler_keeps_direct_scheduler_path(auth_client, db_session, monkeypatch):
    from api.platform import scheduler
    calls = []
    monkeypatch.setitem(scheduler._handlers, ("siem", "th_dispatch"), lambda db, schedule: calls.append(schedule.kind))
    now = dt.datetime.now(dt.UTC)
    schedule = scheduler.upsert_schedule(db_session, module="siem", kind="th_dispatch", target_id=0,
                                         interval_hours=1, window_from=None, window_to=None, enabled=True)
    schedule.next_run_at = now
    db_session.commit()
    scheduler.tick(db_session, now)
    assert calls == ["th_dispatch"]
    assert list(db_session.scalars(select(SyncRun))) == []


@pytest.mark.parametrize("kind", ["dns", "rt"])
def test_disabled_source_fails_without_stalling_fifo(auth_client, db_session, monkeypatch, kind):
    from api.modules.assets.models import AssetDns, AssetRacktables
    from api.platform.sync_queue import adapters
    source = AssetDns(enabled=False) if kind == "dns" else AssetRacktables(url="https://rt.test", enabled=False)
    db_session.add(source)
    db_session.commit()
    task = {"module": "assets", "kind": kind, "target_id": source.id}
    launched, _ = fake_jobs(monkeypatch, db_session)
    fake_start = worker.start_task
    monkeypatch.setattr(worker, "start_task", lambda db, target, actor, options:
                        adapters.start_task(db, target, actor, options) if target.kind == kind else fake_start(db, target, actor, options))
    run = enqueue(auth_client, task, A)
    worker.dispatch(db_session)
    worker.dispatch(db_session)
    assert [item[0] for item in launched] == [key(A)]
    view = auth_client.get(f"{URL}/{run['id']}").json()
    assert next(s for s in view["steps"] if s["key"] == key(task))["status"] == "failed"


@pytest.mark.parametrize("absent", [False, True])
def test_missing_data_invalidates_historical_success(auth_client, db_session, monkeypatch, absent):
    from api.platform.data_status import _PROVIDERS, DataItem
    from api.platform.sync_queue.adapters import observed_at
    from api.platform.sync_queue.catalog import resolve
    run = enqueue(auth_client, A)
    row = db_session.scalar(select(SyncStep).where(SyncStep.run_id == run["id"]))
    row.status, row.checked_at = "done", dt.datetime.now(dt.UTC)
    db_session.commit()
    item = DataItem("vm", "ref:epss", "EPSS", "reference", None, "missing", None, "", "")
    monkeypatch.setitem(_PROVIDERS, "vm", lambda db: [] if absent else [item])
    assert observed_at(db_session, resolve(db_session, key(A))) is None


def test_deleted_unrelated_root_does_not_fail_remaining_tasks(auth_client, db_session, monkeypatch):
    from api.modules.ad.models import AdConnection
    source = AdConnection(host="dc.test")
    db_session.add(source)
    db_session.commit()
    task = {"module": "ad", "kind": "collect", "target_id": source.id}
    run = enqueue(auth_client, task, A)
    db_session.delete(source)
    db_session.commit()
    launched, _ = fake_jobs(monkeypatch, db_session)
    worker.dispatch(db_session)
    assert [item[0] for item in launched] == [key(A)]
    view = auth_client.get(f"{URL}/{run['id']}").json()
    assert next(s for s in view["steps"] if s["key"] == key(task))["status"] == "failed"


@pytest.mark.parametrize("outcome", ["failed", "partial"])
def test_structured_result_controls_step_and_blocks_consumer(auth_client, db_session, monkeypatch, outcome):
    launched, _ = fake_jobs(monkeypatch, db_session)
    assert dependencies(auth_client, C, (A, 60)).status_code == 200
    run = enqueue(auth_client, C, B)
    worker.dispatch(db_session)
    row = db_session.get(SyncJob, launched[0][1])
    row.result = {"status": outcome, "warnings": ["Источник прочитан не полностью"]}
    finish(db_session, row.id)
    worker.dispatch(db_session)
    view = auth_client.get(f"{URL}/{run['id']}").json()
    steps = {s["key"]: s for s in view["steps"]}
    assert steps[key(A)]["status"] == outcome
    assert steps[key(A)]["checked_at"] is None
    assert steps[key(C)]["status"] == "blocked"
    assert [item[0] for item in launched] == [key(A), key(B)]


def test_assets_partial_result_is_persisted(db_session, monkeypatch):
    from api.jobs import JobHandle
    from api.modules.assets.models import AssetJob
    from api.modules.assets.services import sync
    from api.platform.sync_queue.adapters import job_state
    row = AssetJob(kind="sync", status="done", started_by="test")
    db_session.add(row)
    db_session.commit()
    monkeypatch.setattr(sync, "run_sync", lambda *args: {"ad": 2, "users_failed": 1})
    sync.sync_job(db_session, JobHandle(db_session, row), "test")
    assert job_state(db_session, JobRef("asset_job", row.id)).status == "partial"


def test_harbor_partial_result_is_persisted(db_session, monkeypatch):
    from api.modules.vm.models import VmJob
    from api.modules.vm.services import harbor_sync
    from api.modules.vm.services.jobs import JobHandle
    from api.platform.sync_queue.adapters import job_state
    row = VmJob(kind="harbor_sync", status="done", started_by="test")
    db_session.add(row)
    db_session.commit()
    monkeypatch.setattr(harbor_sync, "run_harbor_sync", lambda *args: harbor_sync.SyncResult(images=2, errors=["unavailable"]))
    harbor_sync.sync_work("test")(db_session, JobHandle(db_session, row))
    assert job_state(db_session, JobRef("vm_job", row.id)).status == "partial"


def test_partial_refresh_cannot_be_reused_by_later_runs(auth_client, db_session, monkeypatch):
    from api.platform.data_status import _PROVIDERS, DataItem
    from api.platform.sync_queue.adapters import observed_at
    from api.platform.sync_queue.catalog import resolve
    run = enqueue(auth_client, A)
    row = db_session.scalar(select(SyncStep).where(SyncStep.run_id == run["id"]))
    now = dt.datetime.now(dt.UTC)
    row.status, row.finished_at, row.job_id = "partial", now, 123
    db_session.commit()
    stamp = now - dt.timedelta(seconds=1)
    monkeypatch.setitem(_PROVIDERS, "vm", lambda db: [DataItem("vm", "ref:epss", "EPSS", "reference", stamp, "ready", None, "", "")])
    assert observed_at(db_session, resolve(db_session, key(A))) is None
    stamp = now + dt.timedelta(seconds=1)
    assert observed_at(db_session, resolve(db_session, key(A))) == stamp


def test_two_dispatchers_cannot_launch_the_same_step(auth_client, db_session, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from api.db.base import get_sessionmaker
    enqueue(auth_client, A, B)
    launched, _ = fake_jobs(monkeypatch, db_session)
    original = worker.start_task
    entered, release = threading.Event(), threading.Event()
    def paused(*args):
        entered.set()
        assert release.wait(5)
        return original(*args)
    monkeypatch.setattr(worker, "start_task", paused)
    def tick():
        with get_sessionmaker()() as db:
            worker.dispatch(db)
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(tick)
        try:
            assert entered.wait(5)
            tick()
            assert not launched
        finally:
            release.set()
        pending.result(timeout=5)
    assert [item[0] for item in launched] == [key(A)]


def test_restarted_dispatcher_monitors_linked_job_without_restarting_it(auth_client, db_session, monkeypatch):
    from api.db.base import get_sessionmaker
    launched, _ = fake_jobs(monkeypatch, db_session)
    enqueue(auth_client, A, B)
    worker.dispatch(db_session)
    with get_sessionmaker()() as db:
        worker.dispatch(db)
    assert len(launched) == 1
    finish(db_session, launched[0][1])
    with get_sessionmaker()() as db:
        worker.dispatch(db)
    assert [item[0] for item in launched] == [key(A), key(B)]


def test_tasks_without_provider_key_keep_their_own_success_timestamp(auth_client, db_session, monkeypatch):
    from api.platform.data_status import _PROVIDERS
    from api.platform.sync_queue.adapters import observed_at
    from api.platform.sync_queue.catalog import resolve
    task = {"module": "vm", "kind": "trends_pull", "target_id": 0}
    run = enqueue(auth_client, task)
    row = db_session.scalar(select(SyncStep).where(SyncStep.run_id == run["id"]))
    stamp = dt.datetime.now(dt.UTC)
    row.status, row.checked_at = "done", stamp
    db_session.commit()
    monkeypatch.setitem(_PROVIDERS, "vm", lambda db: [])
    assert observed_at(db_session, resolve(db_session, key(task))) == stamp
