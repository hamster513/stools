"""Запись политик снапшота в таблицы: политики, привязка к группам, профили, исключения, сетевые правила.

Вызывается из `snapshots._store` — при импорте и при пересчёте: строки снапшота удаляются и пишутся заново.
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Any

from sqlalchemy import delete
from sqlalchemy.orm import Session

from api.modules.ksc.core.export import ExportIndex
from api.modules.ksc.core.policy_contents import walk_settings
from api.modules.ksc.core.policy_index import policy_objects, policy_rows, profile_rows, scope_rows
from api.modules.ksc.core.policy_model import exclusion_key, net_rule_key
from api.modules.ksc.models import (
    KscExclusion,
    KscNetRule,
    KscPolicy,
    KscPolicyScope,
    KscProfile,
    KscSnapshot,
)

TABLES = (KscPolicy, KscPolicyScope, KscProfile, KscExclusion, KscNetRule)


def _insert(db: Session, model: type[Any], rows: list[dict[str, Any]]) -> None:
    if rows:
        db.execute(model.__table__.insert(), rows)


def store_policies(db: Session, snapshot: KscSnapshot, idx: ExportIndex) -> None:
    for model in TABLES:
        db.execute(delete(model).where(model.snapshot_id == snapshot.id))
    export, sid = idx.export, snapshot.id

    scopes = scope_rows(idx)
    groups: Counter[int] = Counter()
    hosts: Counter[int] = Counter()
    for s in scopes:
        groups[s.policy_id] += 1
        hosts[s.policy_id] += s.hosts
    _insert(db, KscPolicyScope, [
        {"snapshot_id": sid, "policy_id": s.policy_id, "group_id": s.group_id, "group_path": s.group_path[:1024], "own": s.own, "hosts": s.hosts}
        for s in scopes
    ])

    profiles = profile_rows(export)
    _insert(db, KscProfile, [
        {"snapshot_id": sid, "policy_id": p.policy_id, "name": p.name[:255], "enabled": p.enabled, "priority": p.priority,
         "condition_json": json.dumps(p.condition, ensure_ascii=False, default=str), "settings": p.settings,
         "errors_json": json.dumps(p.errors, ensure_ascii=False)}
        for p in profiles or []
    ])

    policies: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    net_rules: list[dict[str, Any]] = []
    for p in policy_rows(idx):
        objs, described = policy_objects(export, str(p.policy_id))
        content = export.policy_contents.get(str(p.policy_id)) or {}
        entry = export.policy_profiles.get(str(p.policy_id)) if export.policy_profiles is not None else None
        policies.append({
            "snapshot_id": sid, "policy_id": p.policy_id, "name": p.name[:255], "product": p.product[:64], "version": p.version[:64],
            "group_id": p.group_id, "group_path": p.group_path[:1024], "active": p.active, "accept_parent": p.accept_parent,
            "modified_at": p.modified_at, "has_contents": p.has_contents, "described": described,
            "groups": groups[p.policy_id], "hosts": hosts[p.policy_id],
            "profiles": _profiles_count(entry), "exclusions": len(objs.exclusions), "net_rules": len(objs.net_rules),
            "settings_total": len(walk_settings(content.get("sections") or {})), "settings_known": 0,
        })
        exclusions.extend(
            {"snapshot_id": sid, "policy_id": p.policy_id, "profile": e.profile[:255], "kind": e.kind[:32], "value": e.value,
             "components_json": json.dumps(list(e.components), ensure_ascii=False), "enabled": e.enabled, "comment": e.comment,
             "risks_json": "[]", "key": exclusion_key(e)}
            for e in objs.exclusions
        )
        net_rules.extend(
            {"snapshot_id": sid, "policy_id": p.policy_id, "profile": r.profile[:255], "layer": r.layer[:16], "position": r.position,
             "name": r.name[:255], "action": r.action[:16], "direction": r.direction[:16], "protocol": r.protocol[:32],
             "local_ports": r.local_ports[:255], "remote_ports": r.remote_ports[:255], "addresses": r.addresses, "enabled": r.enabled,
             "key": net_rule_key(r)}
            for r in objs.net_rules
        )
    _insert(db, KscPolicy, policies)
    _insert(db, KscExclusion, exclusions)
    _insert(db, KscNetRule, net_rules)


def _profiles_count(entry: dict[str, Any] | None) -> int | None:
    """Число профилей политики; None — не собраны: секции нет, политики в ней нет (профили читаются только у
    политик продуктов защиты) или чтение списка профилей отказало (ошибка у политики и ни одного профиля)."""
    if entry is None:
        return None
    profiles = entry.get("profiles") or []
    if not profiles and entry.get("errors"):
        return None
    return len(profiles)
