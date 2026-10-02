"""Статусы находок: ручные смены, история, сверка с данными, сводка, настройки (спека §1–§5).

Каждое изменение пишет событие истории; изменение, которое ничего не
меняет, не пишет ничего — иначе лента заполнится повторами одного и того же
сохранения. Функции с записью фиксируют транзакцию сами, один раз на вызов
(`reconcile` — если не попросили иначе).

Все записи одной области (`module`, `scope_id`) идут друг за другом: в начале
транзакции берётся транзакционная advisory-блокировка области (`lock_scope`),
а строки читаются заново уже под ней. Так сверка не перетирает ручную смену,
сделанную, пока она шла, а две смены одной новой находки не заводят две строки.
"""
from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from itertools import batched
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from api.db.models import ROLE_ADMIN, ROLE_ANALYST, AppUser
from api.platform.findings.adapters import CurrentFinding, get_adapter
from api.platform.findings.core import (
    NEEDS_REASON,
    OPEN,
    STATUSES,
    FindingSettings,
    TransitionError,
    check_manual,
    on_absent,
    on_present,
)
from api.platform.findings.models import FindingEvent, FindingSettingsRow, FindingState
from api.settings import get_settings

SYSTEM = "system"
#: Строка настроек одна, с постоянным id.
SETTINGS_ID = 1
#: «Риск истекает» на обзоре — столько дней вперёд.
RISK_EXPIRING_DAYS = 30
_CHUNK = 5000


class Unset:
    """«Поле не передано» — в отличие от None, который значит «очистить»."""

    def __repr__(self) -> str:
        return "UNSET"


UNSET = Unset()


@dataclass
class Change:
    status: str | None = None
    assignee: str | None | Unset = UNSET
    due_date: dt.date | None | Unset = UNSET
    risk_until: dt.date | None | Unset = UNSET
    comment: str = ""


def today() -> dt.date:
    """Сроки — даты людей, поэтому «сегодня» в поясе STOOLS_TZ, а не в UTC."""
    return dt.datetime.now(ZoneInfo(get_settings().tz)).date()


def _iso(value: dt.date | None) -> str | None:
    return value.isoformat() if value else None


# ---- Справочник исполнителей --------------------------------------------


def directory(db: Session) -> list[AppUser]:
    """Кому можно назначить находку: активные аналитики и администраторы."""
    return list(db.scalars(
        select(AppUser)
        .where(AppUser.is_active.is_(True), AppUser.role.in_((ROLE_ANALYST, ROLE_ADMIN)))
        .order_by(AppUser.login)
    ))


def _directory_logins(db: Session) -> frozenset[str]:
    return frozenset(u.login for u in directory(db))


# ---- Настройки -----------------------------------------------------------


def load_settings(db: Session) -> FindingSettings:
    row = db.scalars(select(FindingSettingsRow).order_by(FindingSettingsRow.id)).first()
    return FindingSettings.model_validate(row.data if row else {})


def save_settings(db: Session, data: FindingSettings, *, updated_by: str = "") -> FindingSettings:
    """Строка с постоянным id заводится вставкой без конфликта: одновременные
    сохранения пишут в одну строку, а не каждое в свою."""
    db.execute(pg_insert(FindingSettingsRow).values(id=SETTINGS_ID, data={}, updated_by="")
               .on_conflict_do_nothing(index_elements=["id"]))
    row = db.scalars(
        select(FindingSettingsRow).where(FindingSettingsRow.id == SETTINGS_ID).with_for_update()
        .execution_options(populate_existing=True)
    ).one()
    row.data = data.model_dump()
    row.updated_by = updated_by
    db.commit()
    return FindingSettings.model_validate(row.data)


def counted_statuses(db: Session) -> frozenset[str]:
    return frozenset(s for s, on in load_settings(db).counted.items() if on)


# ---- Чтение состояния ------------------------------------------------------


def state_map(
    db: Session, module: str, scope_id: int, keys: Iterable[str] | None = None, *, fresh: bool = False,
) -> dict[str, FindingState]:
    """`fresh` — перечитать строки из базы поверх уже загруженных в сессию: так
    читают под блокировкой области, чтобы не решать по устаревшим значениям."""
    scope = (FindingState.module == module, FindingState.scope_id == scope_id)
    opts = {"populate_existing": True} if fresh else {}
    if keys is None:
        return {r.key: r for r in db.scalars(select(FindingState).where(*scope).execution_options(**opts))}
    found: dict[str, FindingState] = {}
    for chunk in batched(set(keys), _CHUNK):
        found.update((r.key, r) for r in db.scalars(
            select(FindingState).where(*scope, FindingState.key.in_(chunk)).execution_options(**opts)))
    return found


def lock_scope(db: Session, module: str, scope_id: int) -> None:
    """Транзакционная блокировка области: держится до commit или rollback, повторный
    вызов в той же транзакции не ждёт. Два int-а: `hashtext(module)` и `scope_id`."""
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:module), CAST(:scope_id AS integer))"),
               {"module": module, "scope_id": scope_id})


def _first_seen(db: Session, module: str, scope_id: int, key: str) -> dt.datetime | None:
    return get_adapter(module).first_seen_many(db, scope_id, [key]).get(key)


def effective_status(state: FindingState | None) -> str:
    return state.status if state is not None else "new"


def is_counted(state: FindingState | None, counted: frozenset[str]) -> bool:
    return effective_status(state) in counted


def events_of(db: Session, state: FindingState) -> list[FindingEvent]:
    """История одной находки, свежие сверху."""
    return list(db.scalars(
        select(FindingEvent).where(FindingEvent.state_id == state.id).order_by(FindingEvent.at.desc(), FindingEvent.id.desc())
    ))


# ---- Ручные изменения ------------------------------------------------------


def _new_row(module: str, scope_id: int, key: str) -> FindingState:
    return FindingState(module=module, scope_id=scope_id, key=key, status="new", reason="", present=True,
                        title="", severity="", updated_by="")


def _event(row: FindingState, actor: str, kind: str, *, from_status: str | None = None,
           to_status: str | None = None, comment: str = "", details: dict[str, Any] | None = None) -> FindingEvent:
    #: Событие привязано к строке через связь: у новой строки ещё нет id, вставка их упорядочит.
    return FindingEvent(state=row, actor=actor, kind=kind, from_status=from_status, to_status=to_status,
                        comment=comment, details=details or {})


def _apply(row: FindingState, change: Change, *, actor: AppUser, settings: FindingSettings,
           assignable: frozenset[str], on: dt.date, bulk_id: str | None) -> list[FindingEvent]:
    comment = change.comment.strip()
    extra: dict[str, Any] = {"bulk_id": bulk_id} if bulk_id else {}
    events: list[FindingEvent] = []
    # До первой правки строки: отказ не должен оставить её изменённой наполовину.
    if isinstance(change.assignee, str) and change.assignee != row.assignee and change.assignee not in assignable:
        raise TransitionError(f"«{change.assignee}» нет в справочнике исполнителей")

    old = row.status
    target = change.status or old
    risk_until = row.risk_until if isinstance(change.risk_until, Unset) else change.risk_until
    if target != "risk_accepted":
        if not isinstance(change.risk_until, Unset) and change.risk_until is not None:
            raise TransitionError("срок принятия риска задаётся только для статуса «Принят риск»")
        risk_until = None
    # Новое обоснование закрывающего решения — тоже решение: пишется как смена статуса.
    new_reason = target in NEEDS_REASON and target == old and bool(comment) and comment != row.reason
    if target != old or risk_until != row.risk_until or new_reason:
        # Продление принятого риска без нового текста держится на прежнем обосновании.
        reason = comment or (row.reason if target == old else "")
        check_manual(target, reason=reason, role=actor.role, settings=settings, risk_until=risk_until, today=on)
        details = {**extra, "risk_until": _iso(risk_until)} if target == "risk_accepted" else dict(extra)
        events.append(_event(row, actor.login, "status", from_status=old, to_status=target, comment=comment, details=details))
        row.status = target
        row.risk_until = risk_until
        row.resolved_at = None
        if target in NEEDS_REASON:
            row.reason = reason

    if not isinstance(change.assignee, Unset) and change.assignee != row.assignee:
        events.append(_event(row, actor.login, "assign", details={**extra, "old": row.assignee, "new": change.assignee}))
        row.assignee = change.assignee

    if not isinstance(change.due_date, Unset) and change.due_date != row.due_date:
        events.append(_event(row, actor.login, "due", details={**extra, "old": _iso(row.due_date), "new": _iso(change.due_date)}))
        row.due_date = change.due_date

    if comment and not any(e.kind == "status" for e in events):
        events.append(_event(row, actor.login, "comment", comment=comment, details=dict(extra)))
    if events:
        row.updated_by = actor.login
    return events


def change(db: Session, *, module: str, scope_id: int, key: str, change: Change, actor: AppUser,
           title: str = "", severity: str = "") -> FindingState:
    lock_scope(db, module, scope_id)
    row = state_map(db, module, scope_id, [key], fresh=True).get(key)
    if row is None:
        row = _new_row(module, scope_id, key)
        row.first_seen_at = _first_seen(db, module, scope_id, key)
    events = _apply(row, change, actor=actor, settings=load_settings(db), assignable=_directory_logins(db),
                    on=today(), bulk_id=None)
    if events:
        if title:
            row.title = title[:512]
        if severity:
            row.severity = severity[:16]
        db.add_all(events)
    # И без изменений: commit отпускает блокировку области.
    db.commit()
    return row


def comment(db: Session, *, module: str, scope_id: int, key: str, text: str, actor: AppUser) -> FindingEvent:
    if not text.strip():
        raise TransitionError("пустой комментарий")
    lock_scope(db, module, scope_id)
    row = state_map(db, module, scope_id, [key], fresh=True).get(key)
    if row is None:
        row = _new_row(module, scope_id, key)
        row.first_seen_at = _first_seen(db, module, scope_id, key)
    event = _event(row, actor.login, "comment", comment=text.strip())
    row.updated_by = actor.login
    db.add(event)
    db.commit()
    return event


def check_change(db: Session, change: Change, *, actor: AppUser) -> None:
    """Проверить смену заранее, на новой находке, — для фоновой задачи, которая применит её
    позже: отказ по правилам §1 (обоснование, роль, срок риска, исполнитель) — до её запуска.
    Ничего не записывает."""
    _apply(_new_row("", 0, ""), change, actor=actor, settings=load_settings(db), assignable=_directory_logins(db),
           on=today(), bulk_id=None)


def bulk_change(db: Session, *, module: str, scope_id: int, keys: Sequence[str], change: Change,
                actor: AppUser, bulk_id: str | None = None) -> int:
    """Одна и та же смена для многих находок; события помечены общим `bulk_id`.
    Возраст новых строк не запрашивается по одной: его допишет ближайшая сверка."""
    bulk_id = bulk_id or uuid.uuid4().hex
    get_adapter(module)
    settings, assignable, on = load_settings(db), _directory_logins(db), today()
    lock_scope(db, module, scope_id)
    existing = state_map(db, module, scope_id, keys, fresh=True)
    changed = 0
    for key in dict.fromkeys(keys):
        row = existing.get(key) or _new_row(module, scope_id, key)
        try:
            events = _apply(row, change, actor=actor, settings=settings, assignable=assignable, on=on, bulk_id=bulk_id)
        except TransitionError as exc:
            # Отказ на одной — отказ всей смены; фиксации не было, вызывающий откатит.
            raise type(exc)(f"находка «{key}»: {exc}") from exc
        if events:
            db.add_all(events)
            changed += 1
    db.commit()
    return changed


# ---- Автоматика -------------------------------------------------------------


def ensure_rows_for_disappeared(db: Session, module: str, scope_id: int, findings: Iterable[CurrentFinding]) -> int:
    """Строки `new` для находок, которые пропали из данных, а решений о них не было.

    `reconcile` строк не заводит, и такая находка исчезла бы бесследно; со
    строкой ближайшая сверка закроет её системой (`resolved`) с событием, а
    вернувшуюся — переоткроет. Транзакцию не фиксирует: это делает `reconcile`."""
    wanted = {f.key: f for f in findings}
    if not wanted:
        return 0
    lock_scope(db, module, scope_id)
    existing = state_map(db, module, scope_id, wanted, fresh=True)
    missing = [key for key in wanted if key not in existing]
    seen = get_adapter(module).first_seen_many(db, scope_id, missing) if missing else {}
    for key in missing:
        f = wanted[key]
        row = _new_row(module, scope_id, key)
        row.title, row.severity, row.updated_by = f.title[:512], f.severity[:16], SYSTEM
        row.first_seen_at = seen.get(key)
        db.add(row)
    made = len(missing)
    db.flush()
    return made



def reconcile(db: Session, module: str, scope_id: int, *, ref: str, now: dt.datetime | None = None,
              commit: bool = True) -> dict[str, int]:
    """Сверка строк состояния области со свежими данными модуля (§1).

    Свежих ключей бывают десятки тысяч, строк состояния — те, о которых
    решали люди: сверка идёт по строкам, а ключи нужны только как множество.
    Строк для ключей без решения не заводит. Нет данных области (адаптер
    вернул None) — область пропускается: `{"skipped": 1}`.

    `commit=False` — только flush: так зовёт `safe_reconcile` внутри точки
    сохранения, транзакцию фиксирует он."""
    now = now or dt.datetime.now(dt.UTC)
    adapter = get_adapter(module)
    lock_scope(db, module, scope_id)
    fresh = adapter.current(db, scope_id)
    if fresh is None:
        _finish(db, commit)
        return {"skipped": 1}
    current = {f.key: f for f in fresh}
    counts = {"resolved": 0, "reopened": 0, "present": len(current)}
    events: list[FindingEvent] = []
    no_age: list[FindingState] = []
    for row in state_map(db, module, scope_id, fresh=True).values():
        found = current.get(row.key)
        if found is None:
            if row.present:
                row.present = False
            target = on_absent(row.status)
            if target is not None:
                events.append(_event(row, SYSTEM, "auto_resolved", from_status=row.status, to_status=target, details={"ref": ref}))
                row.status, row.resolved_at, row.updated_by = target, now, SYSTEM
                counts["resolved"] += 1
            continue
        was_present = row.present
        if not row.present:
            row.present = True
        if found.title and row.title != found.title[:512]:
            row.title = found.title[:512]
        if found.severity and row.severity != found.severity[:16]:
            row.severity = found.severity[:16]
        if row.first_seen_at is None:
            no_age.append(row)
        target = on_present(row.status, was_present)
        if target is not None:
            events.append(_event(row, SYSTEM, "auto_reopened", from_status=row.status, to_status=target, details={"ref": ref}))
            row.status, row.resolved_at, row.updated_by = target, None, SYSTEM
            counts["reopened"] += 1
    # Возраст — одним запросом и только для ключей в данных: о пропавших адаптер
    # нового не скажет, и каждая сверка спрашивала бы о них зря.
    if no_age:
        seen = adapter.first_seen_many(db, scope_id, [r.key for r in no_age])
        for row in no_age:
            row.first_seen_at = seen.get(row.key)
    db.add_all(events)
    _finish(db, commit)
    return counts


def _finish(db: Session, commit: bool) -> None:
    if commit:
        db.commit()
    else:
        db.flush()


def expire_risks(db: Session, today: dt.date) -> int:
    """Принятый риск со сроком в прошлом снова становится новой находкой.
    По областям: каждая под своей блокировкой и своим commit."""
    expired = (FindingState.status == "risk_accepted", FindingState.risk_until < today)
    scopes = db.execute(select(FindingState.module, FindingState.scope_id).where(*expired).distinct()).all()
    total = 0
    for module, scope_id in scopes:
        lock_scope(db, module, scope_id)
        rows = db.scalars(select(FindingState).where(
            FindingState.module == module, FindingState.scope_id == scope_id, *expired,
        ).execution_options(populate_existing=True)).all()
        for row in rows:
            db.add(_event(row, SYSTEM, "risk_expired", from_status=row.status, to_status="new",
                          details={"risk_until": _iso(row.risk_until)}))
            row.status, row.risk_until, row.updated_by = "new", None, SYSTEM
        db.commit()
        total += len(rows)
    return total


# ---- Сводка ------------------------------------------------------------------


def summary(db: Session, module: str, scope_id: int, keys_present: int | None = None) -> dict[str, Any]:
    """Счётчики области. `keys_present` — сколько ключей в свежих данных: находки без
    строки состояния — новые и без исполнителя, и сосчитать их можно только так."""
    scope = (FindingState.module == module, FindingState.scope_id == scope_id)
    by_status = dict.fromkeys(STATUSES, 0)
    present_rows = present_decided = 0
    for status, present, n in db.execute(
        select(FindingState.status, FindingState.present, func.count()).where(*scope)
        .group_by(FindingState.status, FindingState.present)
    ):
        by_status[status] = by_status.get(status, 0) + n
        if present:
            present_rows += n
            if status != "new":
                present_decided += n
    on = today()
    is_open = FindingState.status.in_(OPEN)
    overdue, expiring, unassigned = db.execute(select(
        func.count().filter(is_open, FindingState.due_date < on),
        func.count().filter(FindingState.status == "risk_accepted",
                            FindingState.risk_until <= on + dt.timedelta(days=RISK_EXPIRING_DAYS)),
        func.count().filter(is_open, FindingState.assignee.is_(None)),
    ).where(*scope)).one()
    if keys_present is not None:
        by_status["new"] = max(keys_present - present_decided, 0)
        unassigned += max(keys_present - present_rows, 0)
    return {"by_status": by_status, "overdue": overdue, "risk_expiring": expiring, "unassigned": unassigned}
