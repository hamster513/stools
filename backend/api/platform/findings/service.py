"""Статусы находок: ручные смены, история, сверка с данными, сводка, настройки (спека §1–§5).

Каждое изменение пишет событие истории; изменение, которое ничего не
меняет, не пишет ничего — иначе лента заполнится повторами одного и того же
сохранения. Функции с записью фиксируют транзакцию сами, один раз на вызов.
"""
from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from itertools import batched
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db.models import ROLE_ADMIN, ROLE_ANALYST, AppUser
from api.platform.findings.adapters import get_adapter
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
    row = db.scalars(
        select(FindingSettingsRow).order_by(FindingSettingsRow.id).with_for_update()
    ).first()
    if row is None:
        row = FindingSettingsRow(data={})
        db.add(row)
    row.data = data.model_dump()
    row.updated_by = updated_by
    db.commit()
    return FindingSettings.model_validate(row.data)


def counted_statuses(db: Session) -> frozenset[str]:
    return frozenset(s for s, on in load_settings(db).counted.items() if on)


# ---- Чтение состояния ------------------------------------------------------


def state_map(
    db: Session, module: str, scope_id: int, keys: Iterable[str] | None = None,
) -> dict[str, FindingState]:
    scope = (FindingState.module == module, FindingState.scope_id == scope_id)
    if keys is None:
        return {r.key: r for r in db.scalars(select(FindingState).where(*scope))}
    found: dict[str, FindingState] = {}
    for chunk in batched(set(keys), _CHUNK):
        found.update((r.key, r) for r in db.scalars(select(FindingState).where(*scope, FindingState.key.in_(chunk))))
    return found


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
    if target != old or risk_until != row.risk_until:
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
    row = state_map(db, module, scope_id, [key]).get(key)
    if row is None:
        row = _new_row(module, scope_id, key)
        row.first_seen_at = get_adapter(module).first_seen(db, scope_id, key)
    events = _apply(row, change, actor=actor, settings=load_settings(db), assignable=_directory_logins(db),
                    on=today(), bulk_id=None)
    if events:
        if title:
            row.title = title[:512]
        if severity:
            row.severity = severity[:16]
        db.add_all(events)
        db.commit()
    return row


def comment(db: Session, *, module: str, scope_id: int, key: str, text: str, actor: AppUser) -> FindingEvent:
    if not text.strip():
        raise TransitionError("пустой комментарий")
    row = state_map(db, module, scope_id, [key]).get(key)
    if row is None:
        row = _new_row(module, scope_id, key)
        row.first_seen_at = get_adapter(module).first_seen(db, scope_id, key)
    event = _event(row, actor.login, "comment", comment=text.strip())
    row.updated_by = actor.login
    db.add(event)
    db.commit()
    return event


def bulk_change(db: Session, *, module: str, scope_id: int, keys: Sequence[str], change: Change,
                actor: AppUser, bulk_id: str | None = None) -> int:
    """Одна и та же смена для многих находок; события помечены общим `bulk_id`.
    Возраст новых строк не запрашивается по одной: его допишет ближайшая сверка."""
    bulk_id = bulk_id or uuid.uuid4().hex
    get_adapter(module)
    settings, assignable, on = load_settings(db), _directory_logins(db), today()
    existing = state_map(db, module, scope_id, keys)
    changed = 0
    for key in dict.fromkeys(keys):
        row = existing.get(key) or _new_row(module, scope_id, key)
        events = _apply(row, change, actor=actor, settings=settings, assignable=assignable, on=on, bulk_id=bulk_id)
        if events:
            db.add_all(events)
            changed += 1
    db.commit()
    return changed


# ---- Автоматика -------------------------------------------------------------


def reconcile(db: Session, module: str, scope_id: int, *, ref: str, now: dt.datetime | None = None) -> dict[str, int]:
    """Сверка строк состояния области со свежими данными модуля (§1).

    Свежих ключей бывают десятки тысяч, строк состояния — те, о которых
    решали люди: сверка идёт по строкам, а ключи нужны только как множество.
    Строк для ключей без решения не заводит."""
    now = now or dt.datetime.now(dt.UTC)
    adapter = get_adapter(module)
    current = {f.key: f for f in adapter.current(db, scope_id)}
    counts = {"resolved": 0, "reopened": 0, "present": len(current)}
    events: list[FindingEvent] = []
    for row in state_map(db, module, scope_id).values():
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
        if not row.present:
            row.present = True
        if found.title and row.title != found.title[:512]:
            row.title = found.title[:512]
        if found.severity and row.severity != found.severity[:16]:
            row.severity = found.severity[:16]
        if row.first_seen_at is None:
            row.first_seen_at = adapter.first_seen(db, scope_id, row.key)
        target = on_present(row.status)
        if target is not None:
            events.append(_event(row, SYSTEM, "auto_reopened", from_status=row.status, to_status=target, details={"ref": ref}))
            row.status, row.resolved_at, row.updated_by = target, None, SYSTEM
            counts["reopened"] += 1
    db.add_all(events)
    db.commit()
    return counts


def expire_risks(db: Session, today: dt.date) -> int:
    """Принятый риск со сроком в прошлом снова становится новой находкой."""
    rows = db.scalars(select(FindingState).where(
        FindingState.status == "risk_accepted", FindingState.risk_until < today,
    )).all()
    for row in rows:
        db.add(_event(row, SYSTEM, "risk_expired", from_status=row.status, to_status="new",
                      details={"risk_until": _iso(row.risk_until)}))
        row.status, row.risk_until, row.updated_by = "new", None, SYSTEM
    db.commit()
    return len(rows)


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
