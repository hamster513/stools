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
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from itertools import batched
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from api.db.models import ROLE_ADMIN, ROLE_ANALYST, AppUser
from api.platform.findings.adapters import CurrentFinding, FindingAdapter, get_adapter
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


def _describe(db: Session, module: str, scope_id: int, rows: Sequence[FindingState]) -> None:
    """Подпись и тяжесть строкам без подписи — сразу, по данным модуля: иначе «Мои находки»
    до ближайшей сверки показали бы ключ. Адаптер с `describe` отвечает по ключам, остальные
    отдают свежие находки целиком (`current`) — у AD, KSC, SIEM и Assets это посильно."""
    untitled = {r.key: r for r in rows if not r.title}
    if not untitled:
        return
    adapter = get_adapter(module)
    describe: Describe | None = getattr(adapter, "describe", None)
    if describe is not None:
        found = describe(db, scope_id, list(untitled))
    else:
        found = {f.key: f for f in adapter.current(db, scope_id) or () if f.key in untitled}
    for key, f in found.items():
        if (row := untitled.get(key)) is not None:
            row.title = f.title[:512]
            row.severity = row.severity or f.severity[:16]


def _created(db: Session, module: str, rows: Sequence[FindingState]) -> None:
    """Новые строки области записаны (flush) — модуль может завести к ним свои подсказки
    (`on_states_created`, VM: хост и CVE пары для быстрого списка) в той же транзакции."""
    hook = getattr(get_adapter(module), "on_states_created", None)
    if rows and hook is not None:
        db.flush()
        hook(db, rows)


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
        _describe(db, module, scope_id, [row])
        db.add_all(events)
        if row.id is None:
            _created(db, module, [row])
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
    _describe(db, module, scope_id, [row])
    db.add(event)
    if row.id is None:
        _created(db, module, [row])
    db.commit()
    return event


def rekey(db: Session, module: str, scope_id: int, old_key: str, new_key: str, *, actor: str = SYSTEM) -> bool:
    """Перенести решение с одного ключа находки на другой (Assets: объединение активов меняет
    id актива в ключе). Строка и история остаются, событие `rekeyed` от `actor` (кто объединил)
    пишет, откуда и куда.
    Ключ уже занят или строки нет — ничего не делает, False. Транзакцию не фиксирует: её
    фиксирует вызывающий вместе со своей правкой."""
    lock_scope(db, module, scope_id)
    rows = state_map(db, module, scope_id, [old_key, new_key], fresh=True)
    row = rows.get(old_key)
    if row is None or new_key in rows:
        return False
    row.key = new_key
    db.add(_event(row, actor, "rekeyed", details={"old": old_key, "new": new_key}))
    db.flush()
    return True


def check_change(db: Session, change: Change, *, actor: AppUser) -> None:
    """Проверить смену заранее — для фоновой задачи, которая применит её позже кусками: отказ
    по правилам §1, не зависящим от строки (статус и обоснование к нему, роль, срок риска,
    исполнитель), — до её запуска. Зависящее от строки (продление срока у непринятой
    находки) проверяет `bulk_change` на каждом куске. Ничего не записывает."""
    if isinstance(change.assignee, str) and change.assignee not in _directory_logins(db):
        raise TransitionError(f"«{change.assignee}» нет в справочнике исполнителей")
    risk_until = None if isinstance(change.risk_until, Unset) else change.risk_until
    # Без статуса срок риска задаётся принятым находкам: их и проверяем.
    target = change.status or ("risk_accepted" if risk_until is not None else None)
    if target is None:
        return
    if target != "risk_accepted" and risk_until is not None:
        raise TransitionError("срок принятия риска задаётся только для статуса «Принят риск»")
    # Продление срока без статуса держится на прежнем обосновании строки.
    reason = change.comment if change.status else "прежнее"
    check_manual(target, reason=reason, role=actor.role, settings=load_settings(db), risk_until=risk_until, today=today())


def bulk_change(db: Session, *, module: str, scope_id: int, keys: Sequence[str], change: Change,
                actor: AppUser, bulk_id: str | None = None) -> int:
    """Одна и та же смена для многих находок; события помечены общим `bulk_id`.
    Новым строкам подпись, тяжесть и возраст — сразу, одним запросом к адаптеру на вызов."""
    bulk_id = bulk_id or uuid.uuid4().hex
    get_adapter(module)
    settings, assignable, on = load_settings(db), _directory_logins(db), today()
    lock_scope(db, module, scope_id)
    existing = state_map(db, module, scope_id, keys, fresh=True)
    changed = 0
    made: list[FindingState] = []
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
            if key not in existing:
                made.append(row)
    touched = [r for r in existing.values() if not r.title] + made
    _describe(db, module, scope_id, touched)
    if made:
        seen = get_adapter(module).first_seen_many(db, scope_id, [r.key for r in made])
        for row in made:
            row.first_seen_at = seen.get(row.key)
    _created(db, module, made)
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
    made: list[FindingState] = []
    for key in missing:
        f = wanted[key]
        row = _new_row(module, scope_id, key)
        row.title, row.severity, row.updated_by = f.title[:512], f.severity[:16], SYSTEM
        row.first_seen_at = seen.get(key)
        db.add(row)
        made.append(row)
    db.flush()
    _created(db, module, made)
    return len(made)



PresentKeys = Callable[[Session, int, Sequence[str]], "set[str] | None"]
Describe = Callable[[Session, int, Sequence[str]], dict[str, CurrentFinding]]


def _sources(db: Session, adapter: FindingAdapter, scope_id: int) -> tuple[int | None, PresentKeys, Describe, bool]:
    """Что сверке нужно от данных модуля: сколько находок, какие из ключей есть, подписи.

    Адаптер с `present_keys` и `count_current` (VM: пар сотни тысяч) отвечает запросом
    к своим таблицам — все находки в память не собираются; подписи (`describe`, если есть)
    берутся только для строк, которые меняются или видны людям. Остальные адаптеры отдают
    находки целиком (`current`), и подписи обновляются у всех строк в данных.
    Последний элемент — «обновлять подписи всех строк в данных»."""
    present_keys = getattr(adapter, "present_keys", None)
    count_current = getattr(adapter, "count_current", None)
    if present_keys is not None and count_current is not None:
        describe: Describe = getattr(adapter, "describe", None) or (lambda _db, _scope, _keys: {})
        return count_current(db, scope_id), present_keys, describe, False
    fresh = adapter.current(db, scope_id)
    current = {} if fresh is None else {f.key: f for f in fresh}

    def known(_db: Session, _scope: int, keys: Sequence[str]) -> set[str]:
        return {k for k in keys if k in current}

    def described(_db: Session, _scope: int, keys: Sequence[str]) -> dict[str, CurrentFinding]:
        return {k: current[k] for k in keys if k in current}

    return (None if fresh is None else len(current)), known, described, True


def reconcile(db: Session, module: str, scope_id: int, *, ref: str, now: dt.datetime | None = None,
              commit: bool = True) -> dict[str, int]:
    """Сверка строк состояния области со свежими данными модуля (§1).

    Свежих ключей бывают сотни тысяч, строк состояния — те, о которых решали
    люди: сверка идёт по строкам кусками по `_CHUNK` и спрашивает адаптер, какие
    из ключей куска есть в данных (`_sources`). Решение принимается по колонкам
    строки; объекты ORM читаются только для строк, которые меняются. Строк для
    ключей без решения не заводит. Нет данных области (адаптер вернул None) —
    область пропускается: `{"skipped": 1}`. Ключи, которые адаптер называет в
    `frozen_keys` (AD, KSC: находки проверок, не проверявшихся в последнем снапшоте),
    сверка пропускает: не «устраняет» и не меняет `present`.

    `commit=False` — только flush: так зовёт `safe_reconcile` внутри точки
    сохранения, транзакцию фиксирует он."""
    now = now or dt.datetime.now(dt.UTC)
    adapter = get_adapter(module)
    lock_scope(db, module, scope_id)
    total, present_keys, describe, refresh_all = _sources(db, adapter, scope_id)
    if total is None:
        _finish(db, commit)
        return {"skipped": 1}
    counts = {"resolved": 0, "reopened": 0, "present": total}
    frozen_keys: Callable[[Session, int, Sequence[str]], set[str]] | None = getattr(adapter, "frozen_keys", None)
    s = FindingState
    cols = (s.id, s.key, s.status, s.present, s.assignee, s.title, s.severity, s.first_seen_at)
    last_id = 0
    while True:
        batch = db.execute(select(*cols).where(s.module == module, s.scope_id == scope_id, s.id > last_id)
                           .order_by(s.id).limit(_CHUNK)).all()
        if not batch:
            break
        last_id = batch[-1].id
        here = present_keys(db, scope_id, [r.key for r in batch])
        if here is None:
            # Данные области пропали посреди сверки: «всё устранено» было бы ложью.
            raise RuntimeError("данные области пропали во время сверки")
        if frozen_keys is not None:
            # Находки проверок, для которых данных в этот раз не собрано: строки не трогаем.
            frozen = frozen_keys(db, scope_id, [r.key for r in batch if r.key not in here])
            batch = [r for r in batch if r.key not in frozen]
        _reconcile_batch(db, adapter, scope_id, batch, here, describe, refresh_all, ref, now, counts)
    _finish(db, commit)
    return counts


def _reconcile_batch(db: Session, adapter: FindingAdapter, scope_id: int, batch: Sequence[Any], here: set[str],
                     describe: Describe, refresh_all: bool, ref: str, now: dt.datetime, counts: dict[str, int]) -> None:
    present = [r for r in batch if r.key in here]
    # Подписи — у строк, которые сверка тронет, у видимых людям (есть исполнитель —
    # строка в «Моих находках») и у ещё не подписанных.
    wanted = [r.key for r in present
              if refresh_all or not r.present or on_present(r.status, r.present) or r.assignee or not r.title]
    found = describe(db, scope_id, wanted) if wanted else {}
    # Возраст — только для ключей в данных: о пропавших адаптер нового не скажет.
    no_age = [r.key for r in present if r.first_seen_at is None]
    seen = adapter.first_seen_many(db, scope_id, no_age) if no_age else {}

    def differs(r: Any) -> bool:
        f = found.get(r.key)
        return f is not None and ((bool(f.title) and r.title != f.title[:512])
                                  or (bool(f.severity) and r.severity != f.severity[:16]))

    touched = [r.id for r in batch if (r.key not in here and (r.present or on_absent(r.status)))
               or (r.key in here and (not r.present or on_present(r.status, r.present) or differs(r) or r.key in seen))]
    if not touched:
        return
    events: list[FindingEvent] = []
    for row in db.scalars(select(FindingState).where(FindingState.id.in_(touched))
                          .execution_options(populate_existing=True)):
        if row.key not in here:
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
        if (f := found.get(row.key)) is not None:
            if f.title and row.title != f.title[:512]:
                row.title = f.title[:512]
            if f.severity and row.severity != f.severity[:16]:
                row.severity = f.severity[:16]
        if row.key in seen:
            row.first_seen_at = seen[row.key]
        target = on_present(row.status, was_present)
        if target is not None:
            events.append(_event(row, SYSTEM, "auto_reopened", from_status=row.status, to_status=target, details={"ref": ref}))
            row.status, row.resolved_at, row.updated_by = target, None, SYSTEM
            counts["reopened"] += 1
    db.add_all(events)
    db.flush()


def _finish(db: Session, commit: bool) -> None:
    if commit:
        db.commit()
    else:
        db.flush()


def expire_risks(db: Session, today: dt.date) -> int:
    """Принятый риск со сроком в прошлом снова становится новой находкой, а если находки
    уже нет в данных (`present = False`) — устранённой системой: пропавшая находка открытой
    не возвращается. По областям: каждая под своей блокировкой и своим commit."""
    expired = (FindingState.status == "risk_accepted", FindingState.risk_until < today)
    scopes = db.execute(select(FindingState.module, FindingState.scope_id).where(*expired).distinct()).all()
    total = 0
    for module, scope_id in scopes:
        lock_scope(db, module, scope_id)
        rows = db.scalars(select(FindingState).where(
            FindingState.module == module, FindingState.scope_id == scope_id, *expired,
        ).execution_options(populate_existing=True)).all()
        now = dt.datetime.now(dt.UTC)
        for row in rows:
            target = "new" if row.present else "resolved"
            db.add(_event(row, SYSTEM, "risk_expired", from_status=row.status, to_status=target,
                          details={"risk_until": _iso(row.risk_until)}))
            row.status, row.risk_until, row.updated_by = target, None, SYSTEM
            if target == "resolved":
                row.resolved_at = now
        db.commit()
        total += len(rows)
    return total


# ---- Сводка ------------------------------------------------------------------


def summary(db: Session, module: str, scope_id: int, keys_present: int | None = None, *,
            present_only: bool = False) -> dict[str, Any]:
    """Счётчики области. `keys_present` — сколько ключей в свежих данных: находки без
    строки состояния — новые и без исполнителя, и сосчитать их можно только так.
    `present_only` — только находки, которые есть в данных: так считают плитки обзора,
    ведущие в список (VM: принятый риск пропавшей пары в списке не виден)."""
    scope: tuple[Any, ...] = (FindingState.module == module, FindingState.scope_id == scope_id)
    if present_only:
        scope += (FindingState.present.is_(True),)
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
