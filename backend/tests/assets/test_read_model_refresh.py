
from api.modules.assets.services.read_model import ready_generation
from api.platform.read_model_jobs import ensure_queued
from api.platform.sync_queue import worker
from api.platform.sync_queue.models import SyncRun
from api.timeutil import utcnow

TASK = {"module": "platform", "kind": "assets_read_refresh", "target_id": 0}
URL = "/api/settings/sync-runs"


def test_queue_refresh_permissions_validation_dedup_and_execution(auth_client, client_as, db_session, monkeypatch):
    from api import collector_routes
    monkeypatch.setattr(collector_routes, "spawn", lambda fn: fn())
    reader = client_as({"assets": "read", "platform": "read"})
    assert reader.post(URL, json={"tasks": [TASK]}).status_code == 403
    assert auth_client.post(URL, json={"tasks": [TASK | {"options": {"force": True}}]}).status_code == 422
    first = auth_client.post(URL, json={"tasks": [TASK]})
    assert first.status_code == 202
    assert auth_client.post(URL, json={"tasks": [TASK]}).json()["id"] == first.json()["id"]
    assert ensure_queued(db_session) is None
    worker.dispatch(db_session)
    worker.dispatch(db_session)
    db_session.expire_all()
    assert db_session.get(SyncRun, first.json()["id"]).status == "done"
    assert ready_generation(db_session, utcnow())
    assert ensure_queued(db_session) is None


def test_automatic_initial_refresh_is_visible_and_cancellable(db_session, auth_client):
    run_id = ensure_queued(db_session)
    assert run_id
    run = db_session.get(SyncRun, run_id)
    assert run.origin == "maintenance"
    assert ensure_queued(db_session) is None
    response = auth_client.post(f"{URL}/{run_id}/cancel")
    assert response.status_code == 200
    worker.dispatch(db_session)
    db_session.expire_all()
    assert db_session.get(SyncRun, run_id).status == "cancelled"
