"""Аналитика политик: список с привязкой к группам и хостам, карточка, привязка, профили с отличиями от политики,
плоский список задач выгрузки.

Список, привязка и счётчики — из таблиц `ksc_*` снапшота; замки политик и отличия профилей читаются из сохранённого
файла выгрузки (как у `/policies`).
"""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.ksc.core.export import ExportIndex, _str, load_export_path, unwrap
from api.modules.ksc.core.policy_contents import lock_summary, truncate_value, walk_settings
from api.modules.ksc.models import (
    KscChange,
    KscFinding,
    KscPolicy,
    KscPolicyScope,
    KscProfile,
    KscSnapshot,
)
from api.modules.ksc.routers.policies import task_fields
from api.modules.ksc.services.snapshots import snapshot_path
from api.settings import Settings, get_settings

router = APIRouter(tags=["ksc"])


class PolicyLocksView(BaseModel):
    locked: int
    #: Настройки с признаком замка; 0 — замки в политике не распознаны.
    with_lock_flag: int


class PolicyItem(BaseModel):
    id: int
    name: str
    product: str
    version: str
    #: Группа, в которой политика создана.
    group: str
    active: bool
    accept_parent: bool
    modified_at: dt.datetime | None = None
    has_contents: bool
    #: Для продукта есть извлекатель исключений и сетевых правил.
    described: bool
    #: Групп, где политика действует, и хостов прямо в них.
    groups: int
    hosts: int
    #: None — профили не собраны (старая выгрузка, политика агента/сервера, отказ чтения); 0 — собраны, профилей нет.
    profiles: int | None = None
    exclusions: int
    net_rules: int
    #: None — содержимого нет в выгрузке.
    locks: PolicyLocksView | None = None
    #: Оценка защиты — этап 2; на этапе 1 всегда None, причина — в `grade_reason`.
    grade: None = None
    grade_reason: str
    #: Находки снапшота `POLICY_*` с именем этой политики в `target`.
    findings: int


class PolicyCard(PolicyItem):
    settings_total: int
    settings_known: int
    errors: list[str]
    #: Записей журнала изменений этого снапшота по политике.
    changes: int


class PolicyListResponse(BaseModel):
    items: list[PolicyItem]
    facets: dict[str, dict[str, int]]
    #: Хотя бы у одной политики снапшота профили собраны; иначе профили в выгрузке не собирались.
    profiles_collected: bool


class ScopeGroup(BaseModel):
    group_id: int
    path: str
    #: Политика создана в этой группе; False — унаследована.
    own: bool
    hosts: int


class ScopeResponse(BaseModel):
    groups: list[ScopeGroup]
    hosts: int


class DiffItem(BaseModel):
    section: str
    path: str
    value: str
    #: Значение той же настройки в политике; None — в политике её нет (или содержимого политики нет в выгрузке).
    policy_value: str | None = None
    locked: bool | None = None


class ProfileView(BaseModel):
    name: str
    enabled: bool
    priority: int
    #: Атрибуты профиля как пришли (включённость, условие активации), секреты скрыты при загрузке выгрузки.
    condition: dict[str, Any]
    settings: int
    errors: list[str]
    diff: list[DiffItem]


class ProfilesResponse(BaseModel):
    collected: bool
    errors: list[str]
    profiles: list[ProfileView]


class TaskItem(BaseModel):
    id: str
    name: str
    type: str
    product: str
    #: Путь группы задачи; пусто — задача для набора устройств.
    group: str
    schedule: int
    last_run_at: dt.datetime | None = None
    ok: int
    warning: int
    failed: int


class TasksResponse(BaseModel):
    items: list[TaskItem]
    facets: dict[str, dict[str, int]]


def _snapshot(db: Session, snapshot_id: int) -> KscSnapshot:
    snap = db.get(KscSnapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    return snap


def _policy(db: Session, snapshot_id: int, policy_id: int) -> KscPolicy:
    row = db.execute(select(KscPolicy).where(KscPolicy.snapshot_id == snapshot_id, KscPolicy.policy_id == policy_id)).scalars().first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="политика не найдена")
    return row


def _index(snap: KscSnapshot, settings: Settings) -> ExportIndex:
    path = snapshot_path(settings.data_dir, snap.id)
    if not path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="файл выгрузки не найден")
    return ExportIndex(load_export_path(path))


def _grade_reason(p: KscPolicy) -> str:
    if not p.has_contents:
        return "содержимое не собрано"
    if not p.active:
        return "политика неактивна"
    return "структура продукта не описана"


def _locks(idx: ExportIndex | None, p: KscPolicy) -> PolicyLocksView | None:
    content = idx.export.policy_contents.get(str(p.policy_id)) if idx is not None else None
    if not p.has_contents or content is None:
        return None
    summary = lock_summary(walk_settings(content.get("sections") or {}))
    return PolicyLocksView(locked=summary.locked, with_lock_flag=summary.with_lock_flag)


def _item(p: KscPolicy, idx: ExportIndex | None, findings: int) -> PolicyItem:
    return PolicyItem(
        id=p.policy_id, name=p.name, product=p.product, version=p.version, group=p.group_path, active=p.active, accept_parent=p.accept_parent,
        modified_at=p.modified_at, has_contents=p.has_contents, described=p.described, groups=p.groups, hosts=p.hosts, profiles=p.profiles,
        exclusions=p.exclusions, net_rules=p.net_rules, locks=_locks(idx, p), grade_reason=_grade_reason(p), findings=findings,
    )


def _findings_by_policy(db: Session, snapshot_id: int) -> dict[str, int]:
    rows = db.execute(
        select(KscFinding.target, func.count()).where(KscFinding.snapshot_id == snapshot_id, KscFinding.check.like("POLICY\\_%", escape="\\")).group_by(KscFinding.target)
    ).all()
    return {target: n for target, n in rows}


@router.get("/snapshots/{snapshot_id}/policy-list", response_model=PolicyListResponse)
def get_policy_list(
    snapshot_id: int,
    q: str = "",
    product: str = "",
    active: bool | None = None,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> PolicyListResponse:
    snap = _snapshot(db, snapshot_id)
    rows = list(db.execute(select(KscPolicy).where(KscPolicy.snapshot_id == snapshot_id)).scalars())
    # Файл выгрузки нужен только ради замков; без содержимого у политик его не открываем.
    idx = _index(snap, settings) if any(p.has_contents for p in rows) else None
    needle = q.strip().lower()
    kept = [
        p for p in rows
        if (not needle or needle in p.name.lower())
        and (not product or p.product == product)
        and (active is None or p.active == active)
    ]
    kept.sort(key=lambda p: (not p.active, p.name.lower(), p.policy_id))
    counts = _findings_by_policy(db, snapshot_id)
    facets: dict[str, dict[str, int]] = {"product": {}, "active": {"true": 0, "false": 0}}
    for p in kept:
        facets["product"][p.product] = facets["product"].get(p.product, 0) + 1
        facets["active"]["true" if p.active else "false"] += 1
    # Профили собраны, если хотя бы у одной политики снапшота они не NULL (по таблице, без чтения файла).
    collected = any(p.profiles is not None for p in rows)
    return PolicyListResponse(items=[_item(p, idx, counts.get(p.name, 0)) for p in kept], facets=facets, profiles_collected=collected)


def _policy_errors(idx: ExportIndex, policy_id: int) -> list[str]:
    """Ошибки сбора политики: содержимого и чтения профилей."""
    content = idx.export.policy_contents.get(str(policy_id)) or {}
    entry = (idx.export.policy_profiles or {}).get(str(policy_id)) or {}
    return [str(e) for e in (content.get("errors") or [])] + [str(e) for e in (entry.get("errors") or [])]


@router.get("/snapshots/{snapshot_id}/policies/{policy_id}", response_model=PolicyCard)
def get_policy_card(
    snapshot_id: int,
    policy_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> PolicyCard:
    snap = _snapshot(db, snapshot_id)
    p = _policy(db, snapshot_id, policy_id)
    idx = _index(snap, settings)
    findings = _findings_by_policy(db, snapshot_id).get(p.name, 0)
    changes = db.scalar(select(func.count()).select_from(KscChange).where(KscChange.snapshot_id == snapshot_id, KscChange.policy_id == policy_id)) or 0
    return PolicyCard(
        **_item(p, idx, findings).model_dump(), settings_total=p.settings_total, settings_known=p.settings_known,
        errors=_policy_errors(idx, policy_id), changes=changes,
    )


@router.get("/snapshots/{snapshot_id}/policies/{policy_id}/scope", response_model=ScopeResponse)
def get_policy_scope(
    snapshot_id: int,
    policy_id: int,
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> ScopeResponse:
    _snapshot(db, snapshot_id)
    p = _policy(db, snapshot_id, policy_id)
    rows = db.execute(
        select(KscPolicyScope).where(KscPolicyScope.snapshot_id == snapshot_id, KscPolicyScope.policy_id == policy_id)
        .order_by(KscPolicyScope.group_path, KscPolicyScope.group_id)
    ).scalars()
    return ScopeResponse(groups=[ScopeGroup(group_id=s.group_id, path=s.group_path, own=s.own, hosts=s.hosts) for s in rows], hosts=p.hosts)


def _diff(profile: dict[str, Any], policy_values: dict[tuple[str, str], Any]) -> list[DiffItem]:
    return [
        DiffItem(
            section=s.section, path=s.path, value=truncate_value(s.value), locked=s.locked,
            policy_value=truncate_value(policy_values[(s.section, s.path)]) if (s.section, s.path) in policy_values else None,
        )
        for s in walk_settings(profile.get("sections") or {})
    ]


@router.get("/snapshots/{snapshot_id}/policies/{policy_id}/profiles", response_model=ProfilesResponse)
def get_policy_profiles(
    snapshot_id: int,
    policy_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> ProfilesResponse:
    snap = _snapshot(db, snapshot_id)
    p = _policy(db, snapshot_id, policy_id)
    rows = list(
        db.execute(
            select(KscProfile).where(KscProfile.snapshot_id == snapshot_id, KscProfile.policy_id == policy_id).order_by(KscProfile.priority, KscProfile.id)
        ).scalars()
    )
    idx = _index(snap, settings)
    entry = (idx.export.policy_profiles or {}).get(str(policy_id)) or {}
    if p.profiles is None and not rows:
        # Не собраны: в таблице профилей нет, причина (если была) — ошибки чтения политики в файле.
        return ProfilesResponse(collected=False, errors=[str(e) for e in entry.get("errors") or []], profiles=[])
    exported: dict[str, dict[str, Any]] = {}
    for pr in entry.get("profiles") or []:
        exported.setdefault(_str(pr.get("name")), pr)
    content = idx.export.policy_contents.get(str(policy_id)) or {}
    policy_values = {(s.section, s.path): s.value for s in walk_settings(content.get("sections") or {})}
    return ProfilesResponse(
        collected=p.profiles is not None,
        errors=[str(e) for e in entry.get("errors") or []],
        profiles=[
            ProfileView(
                name=r.name, enabled=r.enabled, priority=r.priority, condition=json.loads(r.condition_json or "{}"), settings=r.settings,
                errors=json.loads(r.errors_json or "[]"), diff=_diff(exported.get(r.name, {}), policy_values),
            )
            for r in rows
        ],
    )


@router.get("/snapshots/{snapshot_id}/tasks", response_model=TasksResponse)
def get_tasks(
    snapshot_id: int,
    q: str = "",
    type: str = "",
    failed: bool = False,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> TasksResponse:
    idx = _index(_snapshot(db, snapshot_id), settings)
    items: list[TaskItem] = []
    for t in idx.export.tasks:
        info: dict[str, Any] = unwrap(t.get("TASK_INFO_PARAMS")) or {}
        gid_raw = info.get("PRTS_TASK_GROUPID")
        try:
            group = idx.group_path(int(gid_raw)) if gid_raw is not None else ""
        except (TypeError, ValueError):
            group = ""
        items.append(TaskItem(**task_fields(t, info), group=group))
    needle = q.strip().lower()
    kept = [
        i for i in items
        if (not needle or needle in i.name.lower())
        and (not type or i.type == type)
        and (not failed or i.failed > 0)
    ]
    kept.sort(key=lambda i: (i.group.lower(), i.name.lower(), i.id))
    facets: dict[str, dict[str, int]] = {"type": {}}
    for i in kept:
        facets["type"][i.type] = facets["type"].get(i.type, 0) + 1
    return TasksResponse(items=kept, facets=facets)
