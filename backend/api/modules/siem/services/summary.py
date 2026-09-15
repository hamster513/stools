"""Сборка сводки снапшота под форму ответа контракта (docs/api-contract.md)."""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from api.db.models import Snapshot, SnapshotProfile
from kbaudit.profile import Profile


def _profile_confirmed(db: Session, snapshot_id: int) -> bool:
    row = db.get(SnapshotProfile, snapshot_id)
    if row is None or not row.profile_json or row.profile_json == "{}":
        return False
    return Profile.model_validate_json(row.profile_json).is_confirmed


def _previous_snapshot(db: Session, snapshot: Snapshot) -> Snapshot | None:
    return (
        db.query(Snapshot)
        .filter(Snapshot.id < snapshot.id)
        .order_by(Snapshot.id.desc())
        .first()
    )


def _delta(db: Session, snapshot: Snapshot) -> dict[str, int] | None:
    previous = _previous_snapshot(db, snapshot)
    if previous is None:
        return None
    return {
        "finding_count": snapshot.finding_count - previous.finding_count,
        "rule_count": snapshot.rule_count - previous.rule_count,
    }


def build_list_item(snapshot: Snapshot) -> dict[str, Any]:
    """Форма элемента GET /api/snapshots — только то, что перечислено
    в контракте, без полной сводки."""
    return {
        "id": snapshot.id,
        "created_at": snapshot.created_at,
        "filename": snapshot.filename,
        "rule_count": snapshot.rule_count,
        "finding_count": snapshot.finding_count,
        "kb_version": snapshot.kb_version,
    }


def build_summary(db: Session, snapshot: Snapshot) -> dict[str, Any]:
    """Полная сводка GET /api/snapshots/{id}."""
    return {
        "id": snapshot.id,
        "created_at": snapshot.created_at,
        "filename": snapshot.filename,
        "rule_count": snapshot.rule_count,
        "group_count": snapshot.group_count,
        "rules_without_code": snapshot.rules_without_code,
        "unsupported_count": snapshot.unsupported_count,
        "edge_count": snapshot.edge_count,
        "scoped_count": snapshot.scoped_count,
        "finding_count": snapshot.finding_count,
        "findings_by_kind": json.loads(snapshot.findings_by_kind_json),
        "findings_by_polarity": json.loads(snapshot.findings_by_polarity_json),
        "findings_by_object_type": json.loads(snapshot.findings_by_object_type_json),
        "objects_with_findings": snapshot.objects_with_findings,
        "in_table_count": snapshot.in_table_count,
        "divergence_count": snapshot.divergence_count,
        "clone_count": snapshot.clone_count,
        "rules_without_msgid": snapshot.rules_without_msgid,
        "name_scheme_coverage": snapshot.name_scheme_coverage,
        "profile_confirmed": _profile_confirmed(db, snapshot.id),
        "authors": json.loads(snapshot.authors_json),
        "table_ranking": json.loads(snapshot.table_ranking_json),
        "delta": _delta(db, snapshot),
    }
