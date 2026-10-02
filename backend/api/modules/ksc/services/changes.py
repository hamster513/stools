"""Журнал изменений снапшота относительно предыдущего снапшота того же сервера (по времени сбора).

Сравниваются файлы выгрузок (`core/changes.diff_exports`), строки пишутся в `ksc_change`, свод — в
`stats_json["changes"]`. Вызывается из `snapshots`: при импорте (для нового и следующего за ним),
пересчёте и удалении (для следующего за удалённым).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from api.jobs import insert_chunked
from api.modules.ksc.core.changes import KINDS, diff_exports
from api.modules.ksc.core.export import load_export_path
from api.modules.ksc.models import KscChange, KscSnapshot
from api.modules.ksc.services.snapshots import previous_snapshot, snapshot_path, stats


def next_snapshot(db: Session, snapshot: KscSnapshot) -> KscSnapshot | None:
    """Следующий по времени сбора снапшот того же сервера — тот, чей предыдущий `snapshot`."""
    return db.execute(
        select(KscSnapshot).where(KscSnapshot.server_id == snapshot.server_id, KscSnapshot.collected_at > snapshot.collected_at)
        .order_by(KscSnapshot.collected_at, KscSnapshot.id)
    ).scalars().first()


def changes_summary(snapshot: KscSnapshot) -> dict[str, Any]:
    """`stats_json["changes"]`; {} — изменения у снапшота ещё не считались."""
    return dict(stats(snapshot).get("changes") or {})


def set_summary(snapshot: KscSnapshot, summary: dict[str, Any]) -> None:
    """Свод изменений в `stats_json`; остальные ключи не трогаются."""
    data = stats(snapshot)
    data["changes"] = summary
    snapshot.stats_json = json.dumps(data, ensure_ascii=False)


def recompute_changes(db: Session, snapshot: KscSnapshot, data_dir: Path) -> None:
    """Изменения снапшота заново (без фиксации `db`). Нет предыдущего — сравнивать не с чем;
    нет файла предыдущего — все виды «не сравнивались» с причиной."""
    db.execute(delete(KscChange).where(KscChange.snapshot_id == snapshot.id))
    prev = previous_snapshot(db, snapshot)
    if prev is None:
        set_summary(snapshot, {"prev": None, "total": 0, "compared": {}, "truncated": False})
        return
    prev_path = snapshot_path(data_dir, prev.id)
    if not prev_path.exists():
        set_summary(snapshot, {"prev": prev.id, "total": 0, "compared": dict.fromkeys(KINDS, False), "truncated": False,
                               "reason": "файл предыдущего снапшота не найден"})
        return
    diff = diff_exports(load_export_path(prev_path), load_export_path(snapshot_path(data_dir, snapshot.id)))
    rows = (
        {"snapshot_id": snapshot.id, "prev_snapshot_id": prev.id, "kind": c.kind, "action": c.action, "policy_id": c.policy_id,
         "policy_name": c.policy_name[:255], "profile": c.profile[:255], "section": c.section[:255], "path": c.path,
         "before_json": json.dumps(c.before, ensure_ascii=False, default=str), "after_json": json.dumps(c.after, ensure_ascii=False, default=str)}
        for c in diff.changes
    )
    insert_chunked(db, KscChange, rows, len(diff.changes), None, "изменений")
    set_summary(snapshot, {"prev": prev.id, "total": len(diff.changes), "compared": diff.compared, "truncated": diff.truncated})
