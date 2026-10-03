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
from api.modules.ksc.core.export import (
    ExportIndex,
    _dt,
    _int,
    _str,
    load_export_path,
    parent_id,
    unwrap,
)
from api.modules.ksc.core.policy_contents import lock_summary, walk_settings
from api.modules.ksc.models import KscFinding, KscSnapshot
from api.modules.ksc.services.snapshots import snapshot_path
from api.settings import Settings, get_settings

router = APIRouter(tags=["ksc"])

#: Находки, которые относятся к группе (target — её путь), а не к хосту.
GROUP_CHECKS = {"POLICY_NONE", "POLICY_INHERIT_BROKEN", "TASK_NO_UPDATE", "TASK_NO_SCAN"}


class LockCountView(BaseModel):
    total: int
    locked: int
    #: Настройки с признаком замка; 0 — замки в политике не распознаны.
    with_lock_flag: int


class PolicyView(BaseModel):
    id: int
    name: str
    product: str
    active: bool
    inherited: bool
    accept_parent: bool
    modified_at: dt.datetime | None = None
    modified_group: str
    #: Замки содержимого политики (`policy_lock_share`/`POLICY_*`); `None` — содержимого нет в выгрузке.
    locks: LockCountView | None = None
    has_contents: bool


class TaskView(BaseModel):
    id: str
    name: str
    type: str
    product: str
    inherited: bool
    schedule: int
    last_run_at: dt.datetime | None = None
    ok: int
    warning: int
    failed: int


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


def _policy_view(p: dict[str, Any], policy_contents: dict[str, dict[str, Any]], locks_cache: dict[str, LockCountView]) -> PolicyView:
    """`locks_cache` — свод замков по `KLPOL_ID` на один запрос: политика действует во многих
    группах, дерево её настроек обходится один раз."""
    modified = unwrap(p.get("KLPOL_MODIFIED"))
    policy_id = _str(p.get("KLPOL_ID"))
    content = policy_contents.get(policy_id)
    locks = None
    if content is not None:
        if policy_id not in locks_cache:
            summary = lock_summary(walk_settings(content.get("sections", {})))
            locks_cache[policy_id] = LockCountView(total=summary.total, locked=summary.locked, with_lock_flag=summary.with_lock_flag)
        locks = locks_cache[policy_id]
    return PolicyView(
        id=_int(p.get("KLPOL_ID")),
        name=_str(p.get("KLPOL_DN")),
        product=_str(p.get("KLPOL_PRODUCT")),
        active=bool(unwrap(p.get("KLPOL_ACTIVE"))),
        inherited=bool(unwrap(p.get("KLPOL_INHERITED"))),
        accept_parent=bool(unwrap(p.get("KLPOL_ACCEPT_PARENT"))),
        modified_at=modified if isinstance(modified, dt.datetime) else None,
        modified_group=_str(p.get("KLPOL_GROUP_NAME")),
        locks=locks,
        has_contents=content is not None,
    )


def _ancestors(idx: ExportIndex, group_id: int) -> set[int]:
    """Предки группы, без самой группы; обрывается на корне или цикле."""
    out: set[int] = set()
    seen = {group_id}
    cur = idx.groups_by_id.get(group_id)
    while cur is not None:
        pid = parent_id(cur)
        if pid < 0 or pid in seen:
            break
        out.add(pid)
        seen.add(pid)
        cur = idx.groups_by_id.get(pid)
    return out


def task_fields(t: dict[str, Any], info: dict[str, Any]) -> dict[str, Any]:
    """Общие поля задачи (имя, тип, расписание, итоги последнего запуска) — для задач группы и плоского списка задач."""
    stats: dict[str, Any] = unwrap(t.get("statistics")) or {}
    return {
        "id": _str(t.get("TASK_UNIQUE_ID")),
        "name": _str(info.get("DisplayName")) or _str(t.get("TASK_NAME")),
        "type": _str(t.get("TASK_NAME")),
        "product": _str(t.get("TASKID_PRODUCT_NAME")),
        "schedule": _int(info.get("TASKSCH_TYPE")),
        "last_run_at": _dt(t.get("TASK_LAST_EXEC_TIME")),
        "ok": _int(stats.get("4")),
        "warning": _int(stats.get("8")),
        "failed": _int(stats.get("16")),
    }


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
        out.append(TaskView(**task_fields(t, info), inherited=inherited))
    return out


def _is_orphan(idx: ExportIndex, g: dict[str, Any]) -> bool:
    """Группа с `parentId`, указывающим на id, отсутствующий в выгрузке (частичный/битый экспорт)."""
    pid = parent_id(g)
    return pid >= 0 and pid not in idx.groups_by_id


def _walk(idx: ExportIndex, group_id: int, level: int, findings_by_target: dict[str, list[KscFinding]], out: list[GroupView], locks_cache: dict[str, LockCountView]) -> None:
    g = idx.groups_by_id[group_id]
    path = idx.group_path(group_id)
    out.append(
        GroupView(
            id=group_id,
            name=_str(g.get("name")),
            path=path,
            level=level,
            hosts=len(idx.hosts_by_group.get(group_id, [])),
            policies=[_policy_view(p, idx.export.policy_contents, locks_cache) for p in idx.export.effective_policies.get(str(group_id), [])],
            tasks=_group_tasks(idx, group_id, _ancestors(idx, group_id)),
            findings=[
                FindingView(key=f.key, check=f.check, check_title=CHECK_BY_CODE[f.check].title if f.check in CHECK_BY_CODE else f.check, severity=f.severity)
                for f in findings_by_target.get(path, [])
            ],
        )
    )
    for child in idx.children(group_id):
        _walk(idx, child, level + 1, findings_by_target, out, locks_cache)


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
    roots = sorted(gid for gid, g in idx.groups_by_id.items() if parent_id(g) < 0)
    # Группы с потерянным родителем (id родителя нет в выгрузке) — тоже корни, иначе их поддерево пропадает.
    orphans = sorted(gid for gid, g in idx.groups_by_id.items() if _is_orphan(idx, g))
    out: list[GroupView] = []
    locks_cache: dict[str, LockCountView] = {}
    for r in roots + orphans:
        _walk(idx, r, 0, findings_by_target, out, locks_cache)
    return PoliciesResponse(groups=out)
