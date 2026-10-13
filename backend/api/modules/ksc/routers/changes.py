"""Журнал изменений сервера: записи по всем снапшотам (от новых к старым) со сводом каждого снапшота."""
from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import ColumnElement, Select, func, select
from sqlalchemy.orm import Session

from api.db.base import get_db, get_sessionmaker
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.ksc.models import KscChange, KscServer, KscSnapshot
from api.modules.ksc.routers.policy_objects import EXCLUSION_KIND_TITLES, policy_cell
from api.modules.ksc.services.changes import summary_view
from api.platform.export import Column, export_response
from api.platform.filters import QueryInts, QueryList, multi, multi_int

router = APIRouter(tags=["ksc"])

MAX_LIMIT = 1000


def _snapshots(db: Session, server_id: int) -> list[KscSnapshot]:
    if db.get(KscServer, server_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="сервер не найден")
    return list(
        db.execute(
            select(KscSnapshot).where(KscSnapshot.server_id == server_id).order_by(KscSnapshot.collected_at.desc(), KscSnapshot.id.desc())
        ).scalars()
    )


def _conditions(
    snapshots: list[KscSnapshot], kind: QueryList, action: QueryList, policy_id: QueryInts, snapshot_id: QueryInts,
) -> list[ColumnElement[bool]]:
    kinds, actions, policy_ids, snapshot_ids = multi(kind), multi(action), multi_int(policy_id), multi_int(snapshot_id)
    conditions: list[ColumnElement[bool]] = [KscChange.snapshot_id.in_([s.id for s in snapshots])]
    if kinds is not None:
        conditions.append(KscChange.kind.in_(sorted(kinds)))
    if actions is not None:
        conditions.append(KscChange.action.in_(sorted(actions)))
    if policy_ids is not None:
        conditions.append(KscChange.policy_id.in_(sorted(policy_ids)))
    if snapshot_ids is not None:
        conditions.append(KscChange.snapshot_id.in_(sorted(snapshot_ids)))
    return conditions


def _ordered(conditions: list[ColumnElement[bool]]) -> Select[tuple[KscChange, Any]]:
    """Записи от новых снапшотов к старым — одинаково у списка и выгрузки."""
    return (
        select(KscChange, KscSnapshot.collected_at).join(KscSnapshot, KscSnapshot.id == KscChange.snapshot_id).where(*conditions)
        .order_by(KscSnapshot.collected_at.desc(), KscChange.snapshot_id.desc(), KscChange.id)
    )


@router.get("/servers/{server_id}/changes")
def list_changes(
    server_id: int,
    kind: QueryList = None,
    action: QueryList = None,
    policy_id: QueryInts = None,
    snapshot_id: QueryInts = None,
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Фасеты `kind, action, policy_id, snapshot_id` — повтором ключа, внутри фасета «или»."""
    snapshots = _snapshots(db, server_id)
    conditions = _conditions(snapshots, kind, action, policy_id, snapshot_id)
    total = db.scalar(select(func.count()).select_from(KscChange).where(*conditions)) or 0
    rows = db.execute(_ordered(conditions).limit(limit).offset(offset)).all()
    facets: dict[str, dict[str, int]] | None = None
    if offset == 0:
        facets = {
            name: {value: n for value, n in db.execute(select(column, func.count()).where(*conditions).group_by(column).order_by(column)).all()}
            for name, column in (("kind", KscChange.kind), ("action", KscChange.action))
        }
    return {
        "total": total,
        "items": [
            {"id": c.id, "snapshot_id": c.snapshot_id, "collected_at": collected_at.isoformat(), "kind": c.kind, "action": c.action,
             "policy_id": c.policy_id, "policy_name": c.policy_name, "profile": c.profile, "section": c.section, "path": c.path,
             "before": json.loads(c.before_json or "null"), "after": json.loads(c.after_json or "null")}
            for c, collected_at in rows
        ],
        "facets": facets,
        "snapshots": [{"id": s.id, "collected_at": s.collected_at.isoformat(), **summary_view(s)} for s in snapshots],
    }


#: Подписи — как на экране (CHANGE_KIND_LABELS, CHANGE_ACTION_LABELS, FIELD_LABELS фронтенда).
CHANGE_KIND_TITLES = {"policy": "политика", "scope": "привязка к группе", "profile": "профиль", "setting": "настройка",
                      "net_rule": "сетевое правило", "exclusion": "исключение"}
CHANGE_ACTION_TITLES = {"added": "добавлено", "removed": "удалено", "changed": "изменено"}
FIELD_TITLES = {"name": "название", "active": "активность", "group": "группа", "accept_parent": "принимать родительскую",
                "enabled": "включён", "priority": "приоритет", "condition": "условие"}

EXPORT_COLUMNS = [
    Column("collected", "Сбор"), Column("kind", "Вид"), Column("action", "Действие"), Column("policy", "Политика/профиль"),
    Column("where", "Где"), Column("value", "Значение"),
]


def _where(c: KscChange, before: Any, after: Any) -> str:
    """Колонка «Где» — как на экране: у исключения и сетевого правила — сама запись, у прочего — раздел и путь."""
    record = after if after is not None else before
    if c.kind in ("exclusion", "net_rule") and isinstance(record, dict):
        if c.kind == "exclusion":
            kind = str(record.get("kind"))
            text = f"{EXCLUSION_KIND_TITLES.get(kind, kind)}: {record.get('value') or ''}"
        else:
            text = str(record.get("name") or "")
        return text or "—"
    path = FIELD_TITLES.get(c.path, c.path) if c.kind in ("policy", "profile") else c.path
    return " · ".join(p for p in (c.section, path) if p) or "—"


def _text(value: Any) -> str:
    if value is None:
        return "нет"
    if isinstance(value, bool):
        return "да" if value else "нет"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _value(before: Any, after: Any) -> str:
    """«было → стало» одной строкой: у таблицы на экране свой разбор по видам, файлу хватает сырых сторон."""
    return f"{_text(before)} → {_text(after)}"


@router.get("/servers/{server_id}/changes/export")
def export_changes(
    server_id: int,
    kind: QueryList = None,
    action: QueryList = None,
    policy_id: QueryInts = None,
    snapshot_id: QueryInts = None,
    fmt: str = Query(default="csv", alias="format"),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """Все записи журнала под фильтрами списка, в его порядке; строки читаются пачками — журнал бывает длинным."""
    conditions = _conditions(_snapshots(db, server_id), kind, action, policy_id, snapshot_id)

    def rows() -> Iterator[dict[str, Any]]:
        # CSV читается после выхода из ручки: у потока своя сессия.
        with get_sessionmaker()() as session:
            for c, collected_at in session.execute(_ordered(conditions).execution_options(yield_per=1000)):
                before, after = json.loads(c.before_json or "null"), json.loads(c.after_json or "null")
                yield {"collected": collected_at, "kind": CHANGE_KIND_TITLES.get(c.kind, c.kind),
                       "action": CHANGE_ACTION_TITLES.get(c.action, c.action), "policy": policy_cell(c.policy_name, c.profile),
                       "where": _where(c, before, after), "value": _value(before, after)}

    return export_response(fmt, EXPORT_COLUMNS, rows(), module="ksc", name="changes")
