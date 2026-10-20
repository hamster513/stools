"""Планировщик Threat Hunting: порядок хантов в очереди, пауза между хантами, окно от времени
старта, первая ночь после установки, перенос старых ключей настроек (в том числе настоящей миграцией)."""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, text

from api.db.models import AppSetting
from api.modules.siem.hunting.library import (
    HuntIn,
    QueryIn,
    create_hunt,
    delete_hunt,
    next_position,
)
from api.modules.siem.hunting.nightly import create_run, queue_for
from api.modules.siem.hunting.settings import (
    TH_KEY,
    ThSettings,
    ensure_th_schedules,
    load_th_settings,
    migrate_legacy_json,
    nightly_schedule,
)
from api.modules.siem.hunting.windows import window_end
from api.platform.scheduler import next_run
from tests.findings.test_migration_siem import (
    scratch,  # noqa: F401 — фикстура пустой базы для alembic
)
from tests.siem_hunting.fake_events import FakeEvents
from tests.siem_hunting.test_nightly import NIGHT, TZ, add_hunt, run

BEFORE = "b8d4f2a6c1e7"
AFTER = "c4e8a2d6f1b3"


def _hunt(code: str) -> HuntIn:
    return HuntIn(code=code, name=code, queries=[QueryIn(query_id="Q1", query="q", fields="time")])


def test_queue_follows_hunt_position(db_session: Any, fake: FakeEvents) -> None:
    a = add_hunt(db_session, "TH-A", [("Q1", "a1"), ("Q2", "a2")])
    b = add_hunt(db_session, "TH-B", [("Q1", "b1")])
    a.position, b.position = 1, 0
    db_session.commit()
    r = create_run(db_session, dt.date(2026, 10, 19), ThSettings(), "UTC")
    assert [(q.hunt_id, q.query_id) for q in queue_for(db_session, r)] == [(b.id, "Q1"), (a.id, "Q1"), (a.id, "Q2")]


def test_new_hunt_goes_last(db_session: Any) -> None:
    assert next_position(db_session) == 0
    first = create_hunt(db_session, _hunt("TH-1"), "u")
    second = create_hunt(db_session, _hunt("TH-2"), "u")
    assert (first.position, second.position) == (0, 1)
    # Восстановленный по коду удалённый хант — тоже в конец, а не на прежнее место.
    delete_hunt(db_session, first, "u")
    revived = create_hunt(db_session, _hunt("TH-1"), "u")
    assert revived.id == first.id and revived.position == 2
    assert next_position(db_session) == 3


def test_pause_only_between_hunts(db_session: Any, fake: FakeEvents) -> None:
    add_hunt(db_session, "TH-A", [("Q1", "a1"), ("Q2", "a2")])
    add_hunt(db_session, "TH-B", [("Q1", "b1")])
    r = create_run(db_session, NIGHT, ThSettings(), TZ)
    sleeper = run(db_session, r.id)
    # Между Q1 и Q2 ханта A паузы нет; между A и B — одна, ровно hunt_pause_s (один кусок по 30 с).
    assert sleeper.calls == [30] and len(fake.calls) == 3


def test_window_end() -> None:
    assert window_end("01:00") == "02:00"
    assert window_end("23:30") == "00:30"
    assert window_end("00:00") == "01:00"


def test_schedule_window_derived_from_start(db_session: Any) -> None:
    ensure_th_schedules(db_session, ThSettings(window_from="23:30"), now=dt.datetime(2026, 10, 20, 9, 45, tzinfo=dt.UTC))
    sched = nightly_schedule(db_session)
    assert sched is not None and (sched.window_from, sched.window_to) == ("23:30", "00:30")


def test_first_run_pulled_to_next_window(db_session: Any) -> None:
    now = dt.datetime(2026, 10, 20, 9, 45, tzinfo=dt.UTC)
    # Платформа считает «+интервал, потом окно» и поставила бы первую ночь на послезавтра.
    assert next_run(now, 24, "01:00", "02:00", "UTC") == dt.datetime(2026, 10, 22, 1, 0, tzinfo=dt.UTC)
    ensure_th_schedules(db_session, ThSettings(), now=now)
    sched = nightly_schedule(db_session)
    assert sched is not None and sched.next_run_at == dt.datetime(2026, 10, 21, 1, 0, tzinfo=dt.UTC)


def test_first_run_not_pulled_when_close(db_session: Any) -> None:
    # Ровно сутки до срока (сохранили настройки внутри окна) — срок не трогается.
    now = dt.datetime(2026, 10, 20, 1, 30, tzinfo=dt.UTC)
    ensure_th_schedules(db_session, ThSettings(), now=now)
    sched = nightly_schedule(db_session)
    assert sched is not None and sched.next_run_at == now + dt.timedelta(hours=24)


def test_disabled_schedule_not_pulled(db_session: Any) -> None:
    now = dt.datetime(2026, 10, 20, 9, 45, tzinfo=dt.UTC)
    ensure_th_schedules(db_session, ThSettings(nightly_enabled=False), now=now)
    sched = nightly_schedule(db_session)
    assert sched is not None and sched.next_run_at == dt.datetime(2026, 10, 22, 1, 0, tzinfo=dt.UTC)


def test_settings_json_migrated_keys(db_session: Any) -> None:
    legacy = '{"query_pause_s": 45, "window_from": "03:00", "window_to": "04:00", "hot_days": 3}'
    db_session.add(AppSetting(key=TH_KEY, value_json=legacy))
    db_session.commit()
    row = db_session.get(AppSetting, TH_KEY)
    row.value_json = migrate_legacy_json(row.value_json)
    db_session.commit()
    assert json.loads(row.value_json) == {"hunt_pause_s": 45, "window_from": "03:00", "hot_days": 3}
    got = load_th_settings(db_session)
    assert (got.hunt_pause_s, got.window_from, got.hot_days) == (45, "03:00", 3)
    assert "window_to" not in ThSettings.model_fields and "query_pause_s" not in ThSettings.model_fields


def test_migrate_legacy_json_leaves_unreadable_as_is() -> None:
    # Испорченный текст — как был: его разберёт pydantic и покажет умолчания, как раньше.
    assert migrate_legacy_json("не json") == "не json"
    assert migrate_legacy_json("[1]") == "[1]"
    assert json.loads(migrate_legacy_json('{"hunt_pause_s": 10}')) == {"hunt_pause_s": 10}


def test_migration_backfills_position_and_settings(scratch: tuple[Engine, Config]) -> None:  # noqa: F811
    engine, cfg = scratch
    command.upgrade(cfg, BEFORE)
    with engine.begin() as conn:
        insert = text("INSERT INTO th_hunt (code, name, created_at, updated_at) VALUES (:code, :code, :created, :created)")
        # Порядок вставки не совпадает с порядком создания: позиции — по created_at, затем id.
        conn.execute(insert, {"code": "TH-LATE", "created": "2026-10-03T00:00:00Z"})
        conn.execute(insert, {"code": "TH-EARLY", "created": "2026-10-01T00:00:00Z"})
        conn.execute(insert, {"code": "TH-MID-1", "created": "2026-10-02T00:00:00Z"})
        conn.execute(insert, {"code": "TH-MID-2", "created": "2026-10-02T00:00:00Z"})
        conn.execute(text("INSERT INTO app_setting (key, value_json, updated_at, updated_by) VALUES "
                          "('siem_th', :v, now(), 't')"),
                     {"v": '{"query_pause_s": 45, "window_from": "03:00", "window_to": "04:00"}'})
    command.upgrade(cfg, AFTER)
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT code, position FROM th_hunt ORDER BY position")).all()
        assert [tuple(r) for r in rows] == [("TH-EARLY", 0), ("TH-MID-1", 1), ("TH-MID-2", 2), ("TH-LATE", 3)]
        default = conn.execute(text(
            "SELECT column_default FROM information_schema.columns WHERE table_name = 'th_hunt' AND column_name = 'position'"
        )).scalar()
        assert default is None
        stored = json.loads(conn.execute(text("SELECT value_json FROM app_setting WHERE key = 'siem_th'")).scalar_one())
    assert stored == {"hunt_pause_s": 45, "window_from": "03:00"}

    command.downgrade(cfg, BEFORE)
    with engine.connect() as conn:
        stored = json.loads(conn.execute(text("SELECT value_json FROM app_setting WHERE key = 'siem_th'")).scalar_one())
        columns = conn.execute(text(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'th_hunt' AND column_name = 'position'"
        )).all()
    assert stored == {"query_pause_s": 45, "window_from": "03:00", "window_to": "02:00"} and columns == []
