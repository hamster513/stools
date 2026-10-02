"""Сервис статусов находок: ручные смены, история, автоматика по данным, сводка."""
from __future__ import annotations

import contextlib
import datetime as dt
import threading
import time
from typing import Any

import pytest
from sqlalchemy import func, select, text

import api.db.base as db_base
from api.db.models import AppUser
from api.platform.findings import service as svc
from api.platform.findings.adapters import safe_reconcile
from api.platform.findings.core import FindingSettings, TransitionError
from api.platform.findings.models import FindingEvent, FindingSettingsRow, FindingState
from tests.findings.conftest import FakeAdapter


def _events(db: Any, state: FindingState) -> list[FindingEvent]:
    return list(db.scalars(select(FindingEvent).where(FindingEvent.state_id == state.id).order_by(FindingEvent.id)))


def _row(db: Any, key: str, scope_id: int = 1) -> FindingState | None:
    return svc.state_map(db, "test", scope_id, [key]).get(key)


def _change(db: Any, actor: AppUser, key: str, change: svc.Change, scope_id: int = 1) -> FindingState:
    return svc.change(db, module="test", scope_id=scope_id, key=key, change=change, actor=actor)


def test_change_creates_row_and_event(db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser], today: dt.date) -> None:
    actor = users["analyst1"]
    state = _change(db_session, actor, "k1", svc.Change(status="in_work", assignee="analyst2",
                                                         due_date=today + dt.timedelta(days=5)))
    assert state.status == "in_work" and state.assignee == "analyst2" and state.updated_by == "analyst1"
    kinds = [e.kind for e in _events(db_session, state)]
    assert sorted(kinds) == ["assign", "due", "status"]
    status_event = next(e for e in _events(db_session, state) if e.kind == "status")
    assert (status_event.from_status, status_event.to_status) == ("new", "in_work")
    assign = next(e for e in _events(db_session, state) if e.kind == "assign")
    assert assign.details == {"old": None, "new": "analyst2"}

    # Повтор с теми же значениями — ни одного пустого события.
    _change(db_session, actor, "k1", svc.Change(status="in_work", assignee="analyst2",
                                                due_date=today + dt.timedelta(days=5)))
    assert len(_events(db_session, state)) == 3


def test_change_without_changes_creates_no_row(db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    _change(db_session, users["analyst1"], "k1", svc.Change(status="new"))
    assert _row(db_session, "k1") is None


def test_change_fills_first_seen_from_adapter(db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    seen = dt.datetime(2026, 9, 1, tzinfo=dt.UTC)
    adapter.first["k1"] = seen
    state = _change(db_session, users["analyst1"], "k1", svc.Change(status="in_work"))
    assert state.first_seen_at == seen


def test_assignee_must_be_in_directory(db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    for login in ("auditor1", "blocked1", "nobody"):
        with pytest.raises(TransitionError):
            _change(db_session, users["analyst1"], "k1", svc.Change(assignee=login))
    db_session.rollback()
    state = _change(db_session, users["analyst1"], "k1", svc.Change(assignee="admin1"))
    assert state.assignee == "admin1"
    state = _change(db_session, users["analyst1"], "k1", svc.Change(assignee=None))
    assert state.assignee is None


def test_risk_accepted_needs_comment_and_leaving_clears_risk_until(
    db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser], today: dt.date) -> None:
    actor = users["analyst1"]
    with pytest.raises(TransitionError):
        _change(db_session, actor, "k1", svc.Change(status="risk_accepted"))
    db_session.rollback()
    until = today + dt.timedelta(days=10)
    state = _change(db_session, actor, "k1", svc.Change(status="risk_accepted", risk_until=until, comment="компенсирующая мера"))
    assert state.reason == "компенсирующая мера" and state.risk_until == until
    state = _change(db_session, actor, "k1", svc.Change(status="in_work"))
    assert state.status == "in_work" and state.risk_until is None


def test_comment(db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    event = svc.comment(db_session, module="test", scope_id=1, key="k1", text="посмотрю завтра", actor=users["analyst1"])
    assert event.kind == "comment" and event.comment == "посмотрю завтра" and event.actor == "analyst1"
    state = _row(db_session, "k1")
    assert state is not None and state.status == "new"
    with pytest.raises(TransitionError):
        svc.comment(db_session, module="test", scope_id=1, key="k1", text=" ", actor=users["analyst1"])


def test_reconcile_new_key_with_row_resolves(db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    adapter.set_keys(1, "k1", "k2")
    svc.comment(db_session, module="test", scope_id=1, key="k1", text="заметка", actor=users["analyst1"])
    adapter.set_keys(1, "k2")
    result = svc.reconcile(db_session, "test", 1, ref="снапшот #2")
    assert result == {"resolved": 1, "reopened": 0, "present": 1}
    state = _row(db_session, "k1")
    assert state is not None and state.status == "resolved" and state.present is False
    assert state.resolved_at is not None and state.updated_by == "system"
    auto = _events(db_session, state)[-1]
    assert auto.kind == "auto_resolved" and auto.actor == "system" and auto.details == {"ref": "снапшот #2"}
    # Ключ без строки состояния строки не получает ни при наличии, ни при исчезновении.
    assert _row(db_session, "k2") is None


def test_reconcile_never_creates_rows(db_session: Any, adapter: FakeAdapter) -> None:
    adapter.set_keys(1, "k1")
    svc.reconcile(db_session, "test", 1, ref="импорт 1")
    adapter.set_keys(1)
    svc.reconcile(db_session, "test", 1, ref="импорт 2")
    assert svc.state_map(db_session, "test", 1) == {}


def test_in_work_resolves_then_reopens_keeping_assignee(
    db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser], today: dt.date) -> None:
    adapter.set_keys(1, "k1")
    due = today + dt.timedelta(days=3)
    _change(db_session, users["analyst1"], "k1", svc.Change(status="in_work", assignee="analyst2", due_date=due))
    adapter.set_keys(1)
    svc.reconcile(db_session, "test", 1, ref="импорт 2")
    adapter.set_keys(1, "k1")
    result = svc.reconcile(db_session, "test", 1, ref="импорт 3")
    assert result["reopened"] == 1
    state = _row(db_session, "k1")
    assert state is not None
    assert (state.status, state.assignee, state.due_date, state.present) == ("reopened", "analyst2", due, True)
    assert state.resolved_at is None
    assert [e.kind for e in _events(db_session, state)][-2:] == ["auto_resolved", "auto_reopened"]
    assert state.title == "находка k1" and state.severity == "High"


def test_risk_accepted_keeps_status_when_absent(db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    adapter.set_keys(1, "k1")
    _change(db_session, users["analyst1"], "k1", svc.Change(status="risk_accepted", comment="изолированный стенд"))
    adapter.set_keys(1)
    assert svc.reconcile(db_session, "test", 1, ref="импорт 2")["resolved"] == 0
    state = _row(db_session, "k1")
    assert state is not None and state.status == "risk_accepted" and state.present is False


def test_fixed_stays_fixed_while_present(db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    adapter.set_keys(1, "k1")
    _change(db_session, users["analyst1"], "k1", svc.Change(status="fixed"))
    svc.reconcile(db_session, "test", 1, ref="импорт 2")
    state = _row(db_session, "k1")
    assert state is not None and state.status == "fixed"
    adapter.set_keys(1)
    svc.reconcile(db_session, "test", 1, ref="импорт 3")
    db_session.refresh(state)
    assert state.status == "resolved"


def test_reconcile_fills_first_seen_when_missing(db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    adapter.set_keys(1, "k1")
    _change(db_session, users["analyst1"], "k1", svc.Change(status="in_work"))
    seen = dt.datetime(2026, 8, 1, tzinfo=dt.UTC)
    adapter.first["k1"] = seen
    svc.reconcile(db_session, "test", 1, ref="импорт 2")
    state = _row(db_session, "k1")
    assert state is not None and state.first_seen_at == seen


def test_reconcile_scopes_are_separate(db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    adapter.set_keys(1, "k1")
    adapter.set_keys(2)
    _change(db_session, users["analyst1"], "k1", svc.Change(status="in_work"), scope_id=1)
    svc.reconcile(db_session, "test", 2, ref="импорт области 2")
    state = _row(db_session, "k1")
    assert state is not None and state.status == "in_work"


def test_expire_risks(db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser], today: dt.date) -> None:
    until = today + dt.timedelta(days=1)
    _change(db_session, users["analyst1"], "k1", svc.Change(status="risk_accepted", risk_until=until, comment="до релиза"))
    _change(db_session, users["analyst1"], "k2", svc.Change(status="risk_accepted", comment="бессрочно"))
    assert svc.expire_risks(db_session, until) == 0
    assert svc.expire_risks(db_session, until + dt.timedelta(days=1)) == 1
    state = _row(db_session, "k1")
    assert state is not None and state.status == "new" and state.risk_until is None
    event = _events(db_session, state)[-1]
    assert (event.kind, event.from_status, event.to_status, event.actor) == ("risk_expired", "risk_accepted", "new", "system")
    other = _row(db_session, "k2")
    assert other is not None and other.status == "risk_accepted"


def test_bulk_change_shares_bulk_id(db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    changed = svc.bulk_change(db_session, module="test", scope_id=1, keys=["a", "b", "c"],
                              change=svc.Change(status="in_work"), actor=users["analyst1"])
    assert changed == 3
    events = list(db_session.scalars(select(FindingEvent)))
    assert len(events) == 3
    bulk_ids = {e.details.get("bulk_id") for e in events}
    assert len(bulk_ids) == 1 and None not in bulk_ids
    # Повтор ничего не меняет и событий не добавляет.
    assert svc.bulk_change(db_session, module="test", scope_id=1, keys=["a", "b", "c"],
                           change=svc.Change(status="in_work"), actor=users["analyst1"]) == 0


def test_counted_statuses(db_session: Any) -> None:
    assert svc.counted_statuses(db_session) == frozenset({"new", "in_work", "fixed", "reopened"})
    settings = svc.load_settings(db_session)
    settings.counted["risk_accepted"] = True
    settings.counted["fixed"] = False
    svc.save_settings(db_session, settings)
    assert svc.counted_statuses(db_session) == frozenset({"new", "in_work", "reopened", "risk_accepted"})
    counted = svc.counted_statuses(db_session)
    assert svc.is_counted(None, counted)
    assert svc.effective_status(None) == "new"


def test_settings_roundtrip(db_session: Any) -> None:
    saved = svc.save_settings(db_session, FindingSettings(risk_max_days=90, risk_accept_role="admin"))
    loaded = svc.load_settings(db_session)
    assert loaded == saved and loaded.risk_max_days == 90 and loaded.risk_accept_role == "admin"


def test_summary(db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser], today: dt.date) -> None:
    actor = users["analyst1"]
    adapter.set_keys(1, *[f"k{i}" for i in range(10)])
    past = today - dt.timedelta(days=1)
    _change(db_session, actor, "k1", svc.Change(status="in_work", assignee="analyst1", due_date=past))
    _change(db_session, actor, "k2", svc.Change(status="in_work"))
    _change(db_session, actor, "k3", svc.Change(status="risk_accepted", risk_until=today + dt.timedelta(days=20), comment="до релиза"))
    _change(db_session, actor, "k4", svc.Change(status="risk_accepted", risk_until=today + dt.timedelta(days=60), comment="до квартала"))
    _change(db_session, actor, "k5", svc.Change(status="false_positive", comment="не наш хост"))
    svc.reconcile(db_session, "test", 1, ref="импорт")

    result = svc.summary(db_session, "test", 1, keys_present=10)
    by_status = result["by_status"]
    assert by_status["in_work"] == 2 and by_status["risk_accepted"] == 2 and by_status["false_positive"] == 1
    assert by_status["new"] == 5
    assert result["overdue"] == 1
    assert result["risk_expiring"] == 1
    # Открытые без исполнителя: k2 и пять ключей без строки.
    assert result["unassigned"] == 6


def test_safe_reconcile_swallows_adapter_error(db_session: Any, adapter: FakeAdapter) -> None:
    adapter.fail = True
    safe_reconcile(db_session, "test", 1, "импорт")
    # Сессия после сбоя пригодна для работы.
    assert svc.state_map(db_session, "test", 1) == {}


def test_reconcile_without_data_skips_scope(db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    adapter.set_keys(1, "k1")
    _change(db_session, users["analyst1"], "k1", svc.Change(status="in_work"))
    # Данных области нет (снапшота нет, выгрузка не разобрана) — это не «все находки устранены».
    del adapter.keys[1]
    assert svc.reconcile(db_session, "test", 1, ref="импорт 2") == {"skipped": 1}
    state = _row(db_session, "k1")
    assert state is not None and (state.status, state.present) == ("in_work", True)
    # Данные есть и пусты — вот тогда устранено.
    adapter.set_keys(1)
    assert svc.reconcile(db_session, "test", 1, ref="импорт 3")["resolved"] == 1


def test_fixed_set_on_absent_finding_reopens_when_it_returns(
    db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser]
) -> None:
    adapter.set_keys(1, "k1")
    _change(db_session, users["analyst1"], "k1", svc.Change(status="in_work"))
    adapter.set_keys(1)
    svc.reconcile(db_session, "test", 1, ref="импорт 2")
    # Находки в данных уже нет, а человек отмечает её исправленной.
    _change(db_session, users["analyst1"], "k1", svc.Change(status="fixed"))
    adapter.set_keys(1, "k1")
    assert svc.reconcile(db_session, "test", 1, ref="импорт 3")["reopened"] == 1
    state = _row(db_session, "k1")
    assert state is not None and (state.status, state.present) == ("reopened", True)


def test_reconcile_asks_first_seen_once_for_many_rows(
    db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser]
) -> None:
    keys = [f"k{i}" for i in range(2000)]
    svc.bulk_change(db_session, module="test", scope_id=1, keys=keys, change=svc.Change(status="in_work"),
                    actor=users["analyst1"])
    seen = dt.datetime(2026, 8, 1, tzinfo=dt.UTC)
    adapter.first["k7"] = seen
    adapter.set_keys(1, *keys)
    adapter.first_seen_calls = 0
    svc.reconcile(db_session, "test", 1, ref="импорт")
    assert adapter.first_seen_calls == 1
    state = _row(db_session, "k7")
    assert state is not None and state.first_seen_at == seen
    # Возраст остальных адаптеру неизвестен: следующая сверка снова спрашивает одним вызовом.
    adapter.first_seen_calls = 0
    svc.reconcile(db_session, "test", 1, ref="импорт 2")
    assert adapter.first_seen_calls == 1


def test_safe_reconcile_failure_keeps_callers_pending_work(db_session: Any, adapter: FakeAdapter) -> None:
    db_session.add(AppUser(login="pending1", password_hash="x", role="analyst"))
    adapter.fail = True
    safe_reconcile(db_session, "test", 1, "импорт")
    db_session.commit()
    with db_base.get_sessionmaker()() as other:
        assert other.scalars(select(AppUser).where(AppUser.login == "pending1")).first() is not None


def test_safe_reconcile_commits_platform_changes(db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser]) -> None:
    adapter.set_keys(1, "k1")
    _change(db_session, users["analyst1"], "k1", svc.Change(status="in_work"))
    adapter.set_keys(1)
    safe_reconcile(db_session, "test", 1, "импорт 2")
    with db_base.get_sessionmaker()() as other:
        state = svc.state_map(other, "test", 1, ["k1"])["k1"]
        assert state.status == "resolved"


def test_resaving_risk_accepted_with_new_reason_updates_reason(
    db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser]
) -> None:
    _change(db_session, users["analyst1"], "k1", svc.Change(status="risk_accepted", comment="старое обоснование"))
    state = _change(db_session, users["analyst1"], "k1", svc.Change(status="risk_accepted", comment="новое обоснование"))
    assert state.reason == "новое обоснование"
    last = _events(db_session, state)[-1]
    assert (last.kind, last.from_status, last.to_status, last.comment) == (
        "status", "risk_accepted", "risk_accepted", "новое обоснование")
    # Новое обоснование — снова решение о риске: роль проверяется.
    svc.save_settings(db_session, FindingSettings(risk_accept_role="admin"))
    with pytest.raises(TransitionError):
        _change(db_session, users["analyst1"], "k1", svc.Change(status="risk_accepted", comment="третье"))


def test_bulk_error_names_first_failing_key(
    db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser], today: dt.date
) -> None:
    _change(db_session, users["analyst1"], "a", svc.Change(status="risk_accepted", comment="до релиза"))
    with pytest.raises(TransitionError, match="«b»"):
        svc.bulk_change(db_session, module="test", scope_id=1, keys=["a", "b", "c"],
                        change=svc.Change(risk_until=today + dt.timedelta(days=5)), actor=users["analyst1"])


# ---- Одновременные изменения одной области ----------------------------------------


def _actor(db: Any, login: str) -> AppUser:
    return db.scalars(select(AppUser).where(AppUser.login == login)).one()


def _wait_until_blocked(thread: threading.Thread, timeout: float = 10.0) -> None:
    """Ждём, пока поток встанет в ожидание блокировки в базе (или закончит работу)."""
    deadline = time.monotonic() + timeout
    with db_base.get_engine().connect() as conn:
        while time.monotonic() < deadline and thread.is_alive():
            if conn.execute(text("SELECT count(*) FROM pg_locks WHERE NOT granted")).scalar():
                return
            conn.rollback()
            time.sleep(0.02)


def test_reconcile_waits_for_manual_change_and_rereads(
    db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser], monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter.set_keys(1, "k1")
    _change(db_session, users["analyst1"], "k1", svc.Change(status="in_work"))
    adapter.set_keys(1, "other")
    counts: dict[str, int] = {}

    def run_reconcile() -> None:
        with db_base.get_sessionmaker()() as other:
            counts.update(svc.reconcile(other, "test", 1, ref="импорт 2"))

    worker = threading.Thread(target=run_reconcile)
    commit = db_session.commit

    def commit_while_reconcile_waits() -> None:
        # Принятие риска записано, но не зафиксировано, а сверка той же области уже идёт.
        monkeypatch.setattr(db_session, "commit", commit)
        db_session.flush()
        worker.start()
        _wait_until_blocked(worker)
        commit()

    monkeypatch.setattr(db_session, "commit", commit_while_reconcile_waits)
    _change(db_session, users["analyst1"], "k1", svc.Change(status="risk_accepted", comment="изолированный стенд"))
    worker.join(10)
    assert not worker.is_alive()
    assert counts["resolved"] == 0
    db_session.expire_all()
    state = _row(db_session, "k1")
    assert state is not None and (state.status, state.present) == ("risk_accepted", False)


def test_concurrent_changes_of_new_finding_make_one_row(
    db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser], monkeypatch: pytest.MonkeyPatch
) -> None:
    barrier = threading.Barrier(2)
    plain = adapter.first_seen_many

    def first_seen_together(db: Any, scope_id: int, keys: Any) -> dict[str, dt.datetime]:
        # Без блокировки области оба потока доходят сюда, не видя строки друг друга.
        with contextlib.suppress(threading.BrokenBarrierError):
            barrier.wait(timeout=2)
        return plain(db, scope_id, keys)

    monkeypatch.setattr(adapter, "first_seen_many", first_seen_together)
    errors: list[BaseException] = []

    def run(login: str, change: svc.Change) -> None:
        try:
            with db_base.get_sessionmaker()() as db:
                svc.change(db, module="test", scope_id=1, key="k1", change=change, actor=_actor(db, login))
        except BaseException as exc:  # noqa: BLE001 — ошибку потока проверяет тест
            errors.append(exc)

    threads = [threading.Thread(target=run, args=("analyst1", svc.Change(status="in_work"))),
               threading.Thread(target=run, args=("analyst2", svc.Change(assignee="analyst2")))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(15)
    assert errors == []
    rows = list(db_session.scalars(select(FindingState).where(FindingState.key == "k1")))
    assert len(rows) == 1 and (rows[0].status, rows[0].assignee) == ("in_work", "analyst2")
    assert sorted(e.kind for e in _events(db_session, rows[0])) == ["assign", "status"]


def test_settings_stay_one_row_under_concurrent_saves(db_session: Any) -> None:
    barrier = threading.Barrier(8)
    errors: list[BaseException] = []

    def save(days: int) -> None:
        try:
            with db_base.get_sessionmaker()() as db:
                barrier.wait(timeout=5)
                svc.save_settings(db, FindingSettings(risk_max_days=days))
        except BaseException as exc:  # noqa: BLE001 — ошибку потока проверяет тест
            errors.append(exc)

    threads = [threading.Thread(target=save, args=(10 + i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(15)
    assert errors == []
    assert db_session.scalar(select(func.count()).select_from(FindingSettingsRow)) == 1


def test_new_rows_are_reported_to_the_adapter_once(db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser],
                                                   monkeypatch: pytest.MonkeyPatch) -> None:
    """`on_states_created` — для каждой новой строки, с id, один раз; существующие и строки без
    изменений не сообщаются."""
    seen: list[tuple[int, str]] = []
    monkeypatch.setattr(adapter, "on_states_created", lambda db, rows: seen.extend((r.id, r.key) for r in rows), raising=False)
    actor = users["analyst1"]
    _change(db_session, actor, "k1", svc.Change(status="in_work"))
    _change(db_session, actor, "k1", svc.Change(status="fixed"))
    _change(db_session, actor, "k0", svc.Change())  # ничего не меняет — строки нет
    svc.comment(db_session, module="test", scope_id=1, key="k2", text="заметка", actor=actor)
    svc.bulk_change(db_session, module="test", scope_id=1, keys=["k1", "k3", "k4"], change=svc.Change(status="in_work"),
                    actor=actor)
    assert [k for _, k in seen] == ["k1", "k2", "k3", "k4"] and all(i is not None for i, _ in seen)


def test_reconcile_uses_adapter_lookups_when_offered(db_session: Any, adapter: FakeAdapter, users: dict[str, AppUser],
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    """Адаптер с `present_keys` и `count_current`: `current()` не зовётся, подписи — через `describe`
    только у строк, которые меняются, видны (есть исполнитель) или не подписаны."""
    from api.platform.findings.adapters import CurrentFinding

    actor = users["analyst1"]
    for key in ("k1", "k2", "k3"):
        _change(db_session, actor, key, svc.Change(status="in_work"))
    _change(db_session, actor, "k4", svc.Change(status="in_work", assignee="analyst2"))
    db_session.execute(FindingState.__table__.update().values(title="старая"))
    db_session.commit()
    asked: list[list[str]] = []
    monkeypatch.setattr(adapter, "count_current", lambda db, scope: 3, raising=False)
    monkeypatch.setattr(adapter, "present_keys", lambda db, scope, keys: {k for k in keys if k != "k1"}, raising=False)
    monkeypatch.setattr(adapter, "describe", lambda db, scope, keys: (asked.append(sorted(keys)) or
                        {k: CurrentFinding(k, f"новая {k}", "High") for k in keys}), raising=False)
    adapter.fail = True  # current() сломан: сверка его звать не должна
    assert svc.reconcile(db_session, "test", 1, ref="импорт") == {"resolved": 1, "reopened": 0, "present": 3}
    # k2, k3 — в данных, без исполнителя, подписаны, не меняются: подпись не спрашивается.
    assert asked == [["k4"]]
    assert _row(db_session, "k4").title == "новая k4" and _row(db_session, "k2").title == "старая"  # type: ignore[union-attr]
