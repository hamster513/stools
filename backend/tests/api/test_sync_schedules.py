import datetime as dt

import pytest

from api import collector_routes
from api.modules.assets.models import AssetDns
from api.modules.vm.core.refs import REF_NAMES
from api.modules.vm.models import VmJob
from api.platform.scheduler import next_calendar_run, tick

URL = "/api/settings/schedules"
WEEK = {"interval_hours": 24, "weekdays": [4, 0], "run_time": "03:00"}


def test_catalog_permissions_and_excluded_tasks(client_as):
    client = client_as({"siem": "admin"})
    items = client.get(URL).json()["items"]
    assert [(item["module"], item["kind"]) for item in items] == [("siem", "kb_collect"), ("siem", "logons")]
    for kind in ["th_nightly", "th_dispatch"]:
        assert client.put(f"{URL}/siem/{kind}/0", json=WEEK).status_code == 404
        assert client.delete(f"{URL}/siem/{kind}/0").status_code == 404
    assert client.put(f"{URL}/vm/ref_epss/0", json=WEEK).status_code == 403
    assert client_as({"vm": "read"}).delete(f"{URL}/vm/harbor/0").status_code == 403


def test_existing_schedule_changes_in_place(auth_client, db_session):
    dns = AssetDns(title="DNS")
    db_session.add(dns)
    db_session.commit()
    legacy = f"/api/assets/dns/{dns.id}/schedule"
    url = f"{URL}/assets/dns/{dns.id}"
    old = auth_client.put(legacy, json={"interval_hours": 6}).json()
    items = auth_client.get(URL).json()["items"]
    s = next(i["schedule"] for i in items if i["kind"] == "dns" and i["target_id"] == dns.id)
    assert s["id"] == old["id"] and s["next_run_at"] == old["next_run_at"]
    weekly = auth_client.put(url, json=WEEK).json()
    assert weekly["weekdays"] == [0, 4] and weekly["id"] == old["id"]
    paused = auth_client.put(url, json={**WEEK, "enabled": False}).json()
    assert not paused["enabled"] and paused["run_time"] == "03:00"
    assert auth_client.put(url, json={**WEEK, "run_time": "26:00"}).status_code == 422
    assert auth_client.put(url, json={"interval_hours": 3}).json()["run_time"] is None
    assert auth_client.delete(url).status_code == 204
    db_session.refresh(dns)
    assert dns.schedule_id is None


def test_feeds_run_through_scheduler(auth_client, db_session, monkeypatch):
    items = auth_client.get(URL).json()["items"]
    assert {i["kind"][4:] for i in items if i["kind"].startswith("ref_")} == set(REF_NAMES)
    queued = []
    monkeypatch.setattr(collector_routes, "spawn", queued.append)
    saved = auth_client.put(f"{URL}/vm/ref_epss/0", json=WEEK).json()
    due = dt.datetime.fromisoformat(saved["next_run_at"])
    jobs = tick(db_session, due, tz=saved["tz"])
    job = db_session.get(VmJob, jobs[0])
    assert job.kind == "ref_epss" and job.started_by == collector_routes.SCHEDULE_STARTED_BY
    assert len(queued) == 1
    assert tick(db_session, due, tz=saved["tz"]) == []
    for name in ("epss", "nvd"):
        assert auth_client.post(f"/api/vm/refs/{name}/download").status_code == 409


@pytest.mark.parametrize(("after", "zone", "days", "time", "expected"), [
    ("2026-11-01T23:59", "Europe/Moscow", "04", "03:00", "2026-11-02T00:00"),
    ("2026-11-02T00:00", "Europe/Moscow", "04", "03:00", "2026-11-06T00:00"),
    ("2026-03-28T10:00", "Europe/Berlin", "6", "02:30", "2026-04-05T00:30"),
    ("2026-10-25T00:30", "Europe/Berlin", "6", "02:30", "2026-11-01T01:30"),
])
def test_weekday_in_server_zone(after, zone, days, time, expected):
    def utc(value):
        return dt.datetime.fromisoformat(value).replace(tzinfo=dt.UTC)

    assert next_calendar_run(utc(after), days, time, zone) == utc(expected)
