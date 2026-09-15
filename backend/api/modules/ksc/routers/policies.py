"""Политики и групповые задачи по дереву групп администрирования снапшота."""
from __future__ import annotations

import datetime as dt
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.ksc.core.checks import CHECK_BY_CODE
from api.modules.ksc.core.export import ExportIndex, _int, _str, load_export_path, unwrap
from api.modules.ksc.models import KscFinding, KscSnapshot
from api.modules.ksc.services.snapshots import snapshot_path
from api.settings import Settings, get_settings

router = APIRouter(tags=["ksc"])

#: Находки, которые относятся к группе (target — её путь), а не к хосту.
GROUP_CHECKS = {"POLICY_NONE", "POLICY_INHERIT_BROKEN", "TASK_NO_UPDATE", "TASK_NO_SCAN"}


class PolicyView(BaseModel):
    id: int
    name: str
    product: str
    active: bool
    inherited: bool
    accept_parent: bool
    modified_at: dt.datetime | None
    modified_group: str


class TaskView(BaseModel):
    id: str
    name: str
    type: str
    product: str
    inherited: bool
    schedule: int


class FindingView(BaseModel):
    key: str
    check: str
    check_title: str
    severity: str


class GroupView(BaseModel):
    id: int
    name: str
    path: str
    level: int
    hosts: int
    policies: list[PolicyView]
    tasks: list[TaskView]
    findings: list[FindingView]


class PoliciesResponse(BaseModel):
    groups: list[GroupView]


def _policy_view(p: dict[str, Any]) -> PolicyView:
    modified = unwrap(p.get("KLPOL_MODIFIED"))
    return PolicyView(
        id=_int(p.get("KLPOL_ID")),
        name=_str(p.get("KLPOL_DN")),
        product=_str(p.get("KLPOL_PRODUCT")),
        active=bool(unwrap(p.get("KLPOL_ACTIVE"))),
        inherited=bool(unwrap(p.get("KLPOL_INHERITED"))),
        accept_parent=bool(unwrap(p.get("KLPOL_ACCEPT_PARENT"))),
        modified_at=modified if isinstance(modified, dt.datetime) else None,
        modified_group=_str(p.get("KLPOL_GROUP_NAME")),
    )


def _ancestors(idx: ExportIndex, group_id: int) -> set[int]:
    """Предки группы, без самой группы; обрывается на корне или цикле."""
    out: set[int] = set()
    seen = {group_id}
    cur = idx.groups_by_id.get(group_id)
    while cur is not None:
        parent_id = _int(cur.get("parentId"))
        if parent_id < 0 or parent_id in seen:
            break
        out.add(parent_id)
        seen.add(parent_id)
        cur = idx.groups_by_id.get(parent_id)
    return out


def _group_tasks(idx: ExportIndex, group_id: int, ancestors: set[int]) -> list[TaskView]:
    out: list[TaskView] = []
    for t in idx.export.tasks:
        info: dict[str, Any] = unwrap(t.get("TASK_INFO_PARAMS")) or {}
        gid_raw = info.get("PRTS_TASK_GROUPID")
        try:
            task_group_id = int(gid_raw) if gid_raw is not None else -1
        except (TypeError, ValueError):
            continue
        if task_group_id == group_id:
            inherited = False
        elif task_group_id in ancestors and not info.get("PRTS_TASK_PROHIBITED_FOR_SUBGROUPS"):
            inherited = True
        else:
            continue
        out.append(
            TaskView(
                id=_str(t.get("TASK_UNIQUE_ID")),
                name=_str(info.get("DisplayName")) or _str(t.get("TASK_NAME")),
                type=_str(t.get("TASK_NAME")),
                product=_str(t.get("TASKID_PRODUCT_NAME")),
                inherited=inherited,
                schedule=_int(info.get("TASKSCH_TYPE")),
            )
        )
    return out


def _walk(idx: ExportIndex, group_id: int, level: int, findings_by_target: dict[str, list[KscFinding]], out: list[GroupView]) -> None:
    g = idx.groups_by_id[group_id]
    path = idx.group_path(group_id)
    out.append(
        GroupView(
            id=group_id,
            name=_str(g.get("name")),
            path=path,
            level=level,
            hosts=len(idx.hosts_by_group.get(group_id, [])),
            policies=[_policy_view(p) for p in idx.export.effective_policies.get(str(group_id), [])],
            tasks=_group_tasks(idx, group_id, _ancestors(idx, group_id)),
            findings=[
                FindingView(key=f.key, check=f.check, check_title=CHECK_BY_CODE[f.check].title if f.check in CHECK_BY_CODE else f.check, severity=f.severity)
                for f in findings_by_target.get(path, [])
            ],
        )
    )
    for child in idx.children(group_id):
        _walk(idx, child, level + 1, findings_by_target, out)


@router.get("/snapshots/{snapshot_id}/policies", response_model=PoliciesResponse)
def get_policies(
    snapshot_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> PoliciesResponse:
    snap = db.get(KscSnapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    path = snapshot_path(settings.data_dir, snap.id)
    if not path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="файл выгрузки не найден")
    idx = ExportIndex(load_export_path(path))
    rows = db.execute(select(KscFinding).where(KscFinding.snapshot_id == snapshot_id, KscFinding.check.in_(GROUP_CHECKS))).scalars()
    findings_by_target: dict[str, list[KscFinding]] = {}
    for f in rows:
        findings_by_target.setdefault(f.target, []).append(f)
    roots = sorted(gid for gid, g in idx.groups_by_id.items() if _int(g.get("parentId")) < 0)
    out: list[GroupView] = []
    for r in roots:
        _walk(idx, r, 0, findings_by_target, out)
    return PoliciesResponse(groups=out)
