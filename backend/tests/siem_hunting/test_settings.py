"""Настройки Threat Hunting и ночное расписание (ручки — в задаче 5, здесь сервис напрямую)."""
from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from api.modules.siem.hunting.settings import (
    TH_KEY,
    ThSettings,
    load_th_settings,
    nightly_schedule,
    save_th_settings,
)
from api.platform.scheduler import PlatformSchedule


def test_defaults(db_session):
    s = load_th_settings(db_session)
    assert s == ThSettings()
    assert (s.nightly_enabled, s.window_from) == (True, "01:00")
    assert (s.hunt_pause_s, s.request_timeout_s, s.default_limit) == (30, 300, 5000)
    assert s.retry_minutes == [10, 20, 30, 30, 30, 30, 30]
    assert (s.nightly_deadline_h, s.hot_days, s.slice_hours, s.slice_pause_s) == (20, 7, 3, 5)
    assert (s.default_depth_months, s.retention_days) == (3, 180)
    assert nightly_schedule(db_session) is None
    save_th_settings(db_session, s, "admin")
    sched = nightly_schedule(db_session)
    assert sched is not None and sched.next_run_at is not None


def test_put_upserts_schedule(db_session):
    save_th_settings(db_session, ThSettings(window_from="02:30"), "admin")
    sched = db_session.execute(
        select(PlatformSchedule).where(
            PlatformSchedule.module == "siem", PlatformSchedule.kind == "th_nightly", PlatformSchedule.target_id == 1
        )
    ).scalar_one()
    # Конец окна не задаётся — час после начала.
    assert (sched.window_from, sched.window_to, sched.interval_hours, sched.enabled) == ("02:30", "03:30", 24, True)

    save_th_settings(db_session, ThSettings(nightly_enabled=False), "admin")
    db_session.expire_all()
    sched = nightly_schedule(db_session)
    assert sched is not None and sched.enabled is False
    # Одна строка ночного расписания (правится, а не добавляется) и диспетчер очереди раздела.
    kinds = sorted(s.kind for s in db_session.execute(select(PlatformSchedule)).scalars())
    assert kinds == ["th_dispatch", "th_nightly"]
    assert load_th_settings(db_session).nightly_enabled is False


def test_save_records_author(db_session):
    from api.db.models import AppSetting

    save_th_settings(db_session, ThSettings(hot_days=3), "analyst1")
    row = db_session.get(AppSetting, TH_KEY)
    assert row is not None and row.updated_by == "analyst1"
    assert load_th_settings(db_session).hot_days == 3


@pytest.mark.parametrize(
    "bad",
    [
        {"window_from": "25:00"},
        {"window_from": "1:00"},
        {"window_from": "01:60"},
        {"retry_minutes": []},
        {"retry_minutes": [5] * 21},
        {"retry_minutes": [0]},
        {"retry_minutes": [1441]},
        {"slice_hours": 0},
        {"hunt_pause_s": 0},
        {"default_limit": 100001},
        {"default_limit": 0},
        {"default_depth_months": 37},
        {"retention_days": 0},
    ],
)
def test_validation(bad):
    with pytest.raises(ValidationError):
        ThSettings(**bad)


def test_validation_edges():
    ThSettings(retry_minutes=[1] * 20, default_limit=100000, default_depth_months=36, window_from="23:59")
