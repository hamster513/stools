"""«Мои находки» из всех модулей, счётчик для меню, ежесуточное истечение принятого риска."""
from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.db.models import AppUser
from api.platform.findings import adapters
from api.platform.findings.models import FindingEvent, FindingState
from api.platform.scheduler import PlatformSchedule, register_schedule_kind, tick
from tests.api.conftest import TEST_LOGIN
from tests.findings.conftest import FakeAdapter
from tests.findings.test_api import _as


@pytest.fixture
def second() -> Iterator[FakeAdapter]:
    """Второй модуль: «Мои находки» собирают строки всех модулей."""
    fake = FakeAdapter()
    fake.module = "test2"
    fake.scope_ids = {0}
    fake.link = lambda scope_id, key: f"/test2/{scope_id}/{key}"  # type: ignore[method-assign]
    adapters.register_adapter(fake)
    yield fake
    adapters._ADAPTERS.pop("test2", None)


def _put(client: TestClient, module: str, scope_id: int, key: str, **change: Any) -> None:
    r = client.put("/api/findings/state", json={"module": module, "scope_id": scope_id, "key": key, **change})
    assert r.status_code == 200, r.text


# ---- «Мои находки» -------------------------------------------------------------------


def test_mine_collects_all_modules_overdue_first_then_due_then_severity(
        app_settings: Any, adapter: FakeAdapter, second: FakeAdapter, users: dict[str, AppUser], today: dt.date) -> None:
    analyst = _as("analyst1")
    soon, past = (today + dt.timedelta(days=5)).isoformat(), (today - dt.timedelta(days=1)).isoformat()
    _put(analyst, "test", 1, "a", status="in_work", assignee="analyst1", due_date=soon, title="A", severity="Low")
    _put(analyst, "test", 1, "b", status="in_work", assignee="analyst1", due_date=past, title="B", severity="Low")
    _put(analyst, "test2", 0, "c", assignee="analyst1", due_date=soon, title="C", severity="critical")
    _put(analyst, "test2", 0, "d", status="fixed", assignee="analyst1", title="D", severity="High")
    _put(analyst, "test", 1, "e", status="risk_accepted", assignee="analyst1", comment="мера",
         risk_until=soon, title="E", severity="High")
    _put(analyst, "test", 1, "f", status="in_work", assignee="analyst2", title="F")

    mine = analyst.get("/api/findings/mine").json()
    assert [m["key"] for m in mine] == ["b", "c", "a", "d"]
    first = mine[0]
    assert (first["module"], first["module_title"], first["scope_id"], first["title"], first["severity"]) == (
        "test", "test", 1, "B", "Low")
    assert (first["status"], first["status_title"], first["due_date"], first["overdue"], first["risk_until"]) == (
        "in_work", "В работе", past, True, None)
    assert first["link"] == "/test/1/b" and mine[1]["link"] == "/test2/0/c"
    assert [m["overdue"] for m in mine] == [True, False, False, False]

    assert [m["key"] for m in analyst.get("/api/findings/mine", params={"module": "test2"}).json()] == ["c", "d"]
    accepted = analyst.get("/api/findings/mine", params={"status": "risk_accepted"}).json()
    assert [(m["key"], m["risk_until"]) for m in accepted] == [("e", soon)]
    assert analyst.get("/api/findings/mine", params={"status": "nope"}).status_code == 422


def test_mine_count_for_the_menu_badge(app_settings: Any, adapter: FakeAdapter, users: dict[str, AppUser],
                                       today: dt.date) -> None:
    analyst = _as("analyst1")
    past = (today - dt.timedelta(days=3)).isoformat()
    _put(analyst, "test", 1, "a", status="in_work", assignee="analyst1", due_date=past)
    _put(analyst, "test", 1, "b", assignee="analyst1")
    _put(analyst, "test", 1, "c", status="false_positive", assignee="analyst1", comment="шум", due_date=past)
    _put(analyst, "test", 1, "d", status="in_work", assignee="analyst2", due_date=past)
    assert analyst.get("/api/findings/mine/count").json() == {"open": 2, "overdue": 1}
    assert _as("auditor1").get("/api/findings/mine/count").json() == {"open": 0, "overdue": 0}


def test_mine_siem_titles_never_carry_finding_values(auth_client: TestClient, db_session: Any) -> None:
    """Подпись находки SIEM уходит в «Мои находки»: в ней правило, класс и поле, но не значение."""
    from api.db.models import Finding
    from tests.findings.test_siem import _by_field, _kb, _list, _upload

    snap = _upload(auth_client, _kb("10.20.30.40"))
    ip = _by_field(_list(auth_client, snap), "dst.ip")
    _put(auth_client, "siem", 0, ip["key"], status="in_work", assignee=TEST_LOGIN)
    _upload(auth_client, _kb("10.20.30.40", extra_rule=True))

    r = auth_client.get("/api/findings/mine", params={"module": "siem"})
    mine = r.json()
    assert [(m["key"], m["module_title"]) for m in mine] == [(ip["key"], "SIEM")]
    assert "DEMO_HC_002_030_Other" in mine[0]["title"] and "dst.ip" in mine[0]["title"]
    assert mine[0]["link"].startswith("/siem/hygiene?key=")
    values = {(f.value, f.value_hash) for f in db_session.query(Finding).filter(Finding.snapshot_id == snap)}
    assert values and not any(v in r.text or h in r.text for v, h in values)
    assert "10.20.30.40" not in r.text


# ---- Истечение принятого риска по расписанию -----------------------------------------------


def _accepted(analyst: TestClient, db_session: Any, key: str, until: dt.date) -> None:
    """Принятый риск со сроком `until`: вручную в прошлое срок не поставить — правится строка."""
    far = (until + dt.timedelta(days=400)).isoformat()
    _put(analyst, "test", 1, key, status="risk_accepted", comment="компенсирующая мера", risk_until=far)
    row = db_session.scalars(select(FindingState).where(FindingState.key == key)).one()
    row.risk_until = until
    db_session.commit()


def test_tick_expires_accepted_risks(app_settings: Any, adapter: FakeAdapter, users: dict[str, AppUser],
                                     db_session: Any, today: dt.date) -> None:
    from api.platform.findings.expiry import ensure_risk_expiry_schedule

    analyst = _as("analyst1")
    _accepted(analyst, db_session, "old", today - dt.timedelta(days=1))
    _accepted(analyst, db_session, "edge", today)
    ensure_risk_expiry_schedule(db_session)
    now = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=5)

    assert tick(db_session, now) == []
    db_session.expire_all()
    rows = {r.key: r for r in db_session.scalars(select(FindingState))}
    assert (rows["old"].status, rows["old"].risk_until, rows["old"].updated_by) == ("new", None, "system")
    assert (rows["edge"].status, rows["edge"].risk_until) == ("risk_accepted", today)
    kinds = [(e.kind, e.from_status, e.to_status) for e in db_session.scalars(
        select(FindingEvent).where(FindingEvent.state_id == rows["old"].id).order_by(FindingEvent.id))]
    assert kinds[-1] == ("risk_expired", "risk_accepted", "new")
    assert not db_session.scalars(select(FindingEvent).where(
        FindingEvent.state_id == rows["edge"].id, FindingEvent.kind == "risk_expired")).all()

    sched = db_session.scalars(select(PlatformSchedule).where(PlatformSchedule.module == "platform")).one()
    assert (sched.kind, sched.last_run_at, sched.last_job_id) == ("risk_expiry", now, None)
    assert sched.next_run_at == now + dt.timedelta(hours=24)


def test_risk_expiry_schedule_is_created_once(app_settings: Any, db_session: Any) -> None:
    from api.platform.findings.expiry import ensure_risk_expiry_schedule

    first = ensure_risk_expiry_schedule(db_session)
    assert (first.module, first.kind, first.target_id, first.interval_hours, first.enabled) == (
        "platform", "risk_expiry", 0, 24, True)
    # Первый запуск — на ближайшем тике, а не через сутки после первого старта.
    assert first.next_run_at is not None and first.next_run_at <= dt.datetime.now(dt.UTC)
    planned = dt.datetime.now(dt.UTC) + dt.timedelta(hours=7)
    first.next_run_at = planned
    db_session.commit()

    again = ensure_risk_expiry_schedule(db_session)
    assert again.id == first.id and again.next_run_at == planned
    assert len(db_session.scalars(select(PlatformSchedule)).all()) == 1


def test_lifespan_creates_the_schedule(app_settings: Any, db_session: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    import api.main
    from api.platform.findings import expiry

    # Тесты подменяют заведение расписания при старте (tests/api/conftest.py) — здесь настоящее.
    monkeypatch.setattr(api.main, "ensure_platform_schedules", expiry.ensure_platform_schedules)
    with TestClient(api.main.app):
        pass
    kinds = [(s.module, s.kind) for s in db_session.scalars(select(PlatformSchedule))]
    assert kinds == [("platform", "risk_expiry")]


def test_jobless_handler_runs_once_per_interval(app_settings: Any, db_session: Any) -> None:
    """Обработчик без задачи (истечение риска) отработал — срок на интервал вперёд, а не на тик."""
    from api.platform import scheduler

    calls: list[int] = []
    register_schedule_kind("test", "jobless", lambda db, sched: calls.append(sched.id), jobless=True)
    try:
        now = dt.datetime(2026, 10, 2, 3, 0, tzinfo=dt.UTC)
        db_session.add(PlatformSchedule(module="test", kind="jobless", target_id=0, interval_hours=24,
                                        enabled=True, next_run_at=now - dt.timedelta(minutes=1)))
        db_session.commit()
        assert tick(db_session, now) == []
        assert tick(db_session, now + dt.timedelta(minutes=1)) == []
        assert len(calls) == 1
        sched = db_session.scalars(select(PlatformSchedule)).one()
        assert (sched.last_run_at, sched.next_run_at) == (now, now + dt.timedelta(hours=24))
    finally:
        scheduler._handlers.pop(("test", "jobless"), None)
        scheduler._jobless.discard(("test", "jobless"))


# ---- Подпись сразу после ручной смены ------------------------------------------------------


def _bulk(client: TestClient, module: str, scope_id: int, keys: list[str], **change: Any) -> None:
    r = client.post("/api/findings/bulk", json={"module": module, "scope_id": scope_id, "keys": keys, "change": change})
    assert r.status_code == 200, r.text


def test_mine_has_ad_title_right_after_bulk(auth_client: TestClient) -> None:
    from tests.ad.synthetic import NOW as AD_NOW
    from tests.findings.test_ad_ksc import _ad_latest, _done, build_ad

    _done(auth_client, "ad", build_ad())
    domain_id, snap = _ad_latest(auth_client)
    kerb = auth_client.get(f"/api/ad/snapshots/{snap}/findings?check=Kerberoast").json()["items"][0]
    _bulk(auth_client, "ad", domain_id, [kerb["key"]], status="in_work", assignee=TEST_LOGIN)
    mine = auth_client.get("/api/findings/mine").json()
    assert [(m["key"], m["title"], m["severity"]) for m in mine] == [
        (kerb["key"], f"Кандидаты на Kerberoasting (SPN): {kerb['identity']}", kerb["severity"])]
    assert mine[0]["first_seen_at"].startswith(AD_NOW.date().isoformat())


def test_mine_has_siem_title_right_after_bulk(auth_client: TestClient, db_session: Any) -> None:
    from api.db.models import Finding
    from tests.findings.test_siem import _by_field, _kb, _list, _upload

    snap = _upload(auth_client, _kb("10.20.30.40"))
    ip = _by_field(_list(auth_client, snap), "dst.ip")
    _bulk(auth_client, "siem", 0, [ip["key"]], status="in_work", assignee=TEST_LOGIN)
    r = auth_client.get("/api/findings/mine", params={"module": "siem"})
    (item,) = r.json()
    assert "DEMO_HC_002_030_Other" in item["title"] and "dst.ip" in item["title"] and item["severity"] == ip["severity"]
    values = {(f.value, f.value_hash) for f in db_session.query(Finding).filter(Finding.snapshot_id == snap)}
    assert values and not any(v in r.text or h in r.text for v, h in values)


def test_mine_has_assets_title_right_after_bulk(db_session: Any, app_settings: Any, client_as: Any) -> None:
    from pathlib import Path

    from tests.findings.test_assets import _id, _load, _sync

    _load(db_session, Path(app_settings.data_dir))
    analyst = client_as("analyst")
    _sync(analyst)
    ws01 = _id(analyst, "ws01")
    _bulk(analyst, "assets", 0, [f"{ws01}|no_av"], status="in_work", assignee="user-analyst")
    (item,) = analyst.get("/api/findings/mine").json()
    assert item["title"].endswith(": нет агента антивируса")


def test_mine_falls_back_to_module_and_key_only_without_title(
        app_settings: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    analyst = _as("analyst1")
    adapter.set_keys(1, "known")
    _put(analyst, "test", 1, "known", assignee="analyst1")
    _put(analyst, "test", 1, "0123456789abcdef", assignee="analyst1")
    titles = {m["key"]: m["title"] for m in analyst.get("/api/findings/mine").json()}
    assert titles == {"known": "находка known", "0123456789abcdef": "test: находка 01234567…"}


def test_expired_risk_of_a_vanished_finding_resolves(app_settings: Any, adapter: FakeAdapter, users: dict[str, AppUser],
                                                     db_session: Any, today: dt.date) -> None:
    from api.platform.findings import service as svc

    _accepted(_as("analyst1"), db_session, "gone", today - dt.timedelta(days=1))
    row = db_session.scalars(select(FindingState).where(FindingState.key == "gone")).one()
    row.present = False
    db_session.commit()
    assert svc.expire_risks(db_session, today) == 1
    db_session.expire_all()
    row = db_session.scalars(select(FindingState).where(FindingState.key == "gone")).one()
    assert (row.status, row.risk_until, row.updated_by) == ("resolved", None, "system") and row.resolved_at is not None
    last = db_session.scalars(select(FindingEvent).where(FindingEvent.state_id == row.id).order_by(FindingEvent.id.desc())).first()
    assert (last.kind, last.actor, last.from_status, last.to_status) == ("risk_expired", "system", "risk_accepted", "resolved")
