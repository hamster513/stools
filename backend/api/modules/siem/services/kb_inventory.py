"""Чтение инвентаря базы знаний для списка правил, детали и экрана наборов."""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.models import RuleRow, SiemDeploymentSet, SiemRuleDeployment, Snapshot


def deployment_by_rule(db: Session, snapshot_id: int) -> dict[str, SiemRuleDeployment]:
    rows = db.query(SiemRuleDeployment).filter(SiemRuleDeployment.snapshot_id == snapshot_id).all()
    return {r.rule_uuid.lower(): r for r in rows}


def set_names(db: Session, snapshot_id: int) -> dict[str, str]:
    rows = db.query(SiemDeploymentSet.kb_id, SiemDeploymentSet.name).filter(SiemDeploymentSet.snapshot_id == snapshot_id)
    return {kb_id: name for kb_id, name in rows}


def rule_fields(deployment: SiemRuleDeployment | None) -> dict[str, Any]:
    """Три поля правила: без строки инвентаря — «неизвестно», не «не установлено»."""
    if deployment is None:
        return {"installed": None, "folder_path": None, "deployment_sets": []}
    return {
        "installed": deployment.installed,
        "folder_path": deployment.folder_path or None,
        "deployment_sets": json.loads(deployment.set_ids_json or "[]"),
    }


def deployment_sets_view(db: Session, snapshot: Snapshot) -> dict[str, Any]:
    rows = (
        db.query(SiemDeploymentSet)
        .filter(SiemDeploymentSet.snapshot_id == snapshot.id)
        .order_by(SiemDeploymentSet.name)
        .all()
    )
    deployment = db.query(SiemRuleDeployment).filter(SiemRuleDeployment.snapshot_id == snapshot.id).all()
    # Объекты из списка KB, которых нет в выгрузке, считаются здесь, а не
    # штампуются при сборе: снапшот — источник истины, список всегда ему равен.
    present = {u.lower() for u in db.scalars(select(RuleRow.uuid).where(RuleRow.snapshot_id == snapshot.id))}
    not_exported = sorted(d.name for d in deployment if d.rule_uuid.lower() not in present)
    return {
        "available": snapshot.source_type == "api" and bool(rows or deployment),
        "sets": [
            {
                "kb_id": s.kb_id, "parent_kb_id": s.parent_kb_id, "name": s.name, "system_name": s.system_name,
                "general_status": s.general_status, "compilation_status": s.compilation_status,
                "deployment_statuses": json.loads(s.deployment_statuses_json or "{}"), "rule_count": s.rule_count,
            }
            for s in rows
        ],
        "objects_total": len(deployment),
        "installed": sum(1 for d in deployment if d.installed),
        "kb_not_exported": not_exported,
    }
