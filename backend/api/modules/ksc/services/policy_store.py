"""Запись политик снапшота в таблицы: политики, привязка к группам, профили, исключения, сетевые правила.

Вызывается из `snapshots._store` — при импорте и при пересчёте: строки снапшота удаляются и пишутся заново.
Снапшоты, импортированные до появления таблиц, заполняются при первом чтении (`ensure_policy_tables`).
"""
from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.dictionary import describe
from api.modules.ksc.core.exclusion_risks import exclusion_risks
from api.modules.ksc.core.export import ExportFormatError, ExportIndex, load_export_path
from api.modules.ksc.core.policy_contents import flat_settings
from api.modules.ksc.core.policy_index import policy_objects, policy_rows, profile_rows, scope_rows
from api.modules.ksc.core.policy_model import exclusion_key, net_rule_key
from api.modules.ksc.models import (
    KscExclusion,
    KscHost,
    KscNetRule,
    KscPolicy,
    KscPolicyScope,
    KscProfile,
    KscSnapshot,
)
from api.modules.ksc.services.settings import load_config

log = logging.getLogger(__name__)

TABLES = (KscPolicy, KscPolicyScope, KscProfile, KscExclusion, KscNetRule)
#: Первый ключ блокировки дозаполнения (второй — id снапшота): свой у модуля, чтобы не пересечься с чужими.
BACKFILL_LOCK = 0x4B5343  # "KSC"


def _insert(db: Session, model: type[Any], rows: list[dict[str, Any]]) -> None:
    if rows:
        db.execute(model.__table__.insert(), rows)


def store_policies(db: Session, snapshot: KscSnapshot, idx: ExportIndex, cfg: KscConfig) -> None:
    """`cfg` — списки правил рисков исключений (`risks_json`)."""
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
        sections = content.get("sections") or {}
        described_settings = describe(p.product, sections)
        entry = export.policy_profiles.get(str(p.policy_id)) if export.policy_profiles is not None else None
        policies.append({
            "snapshot_id": sid, "policy_id": p.policy_id, "name": p.name[:255], "product": p.product[:64], "version": p.version[:64],
            "group_id": p.group_id, "group_path": p.group_path[:1024], "active": p.active, "accept_parent": p.accept_parent,
            "modified_at": p.modified_at, "has_contents": p.has_contents, "described": described,
            "groups": groups[p.policy_id], "hosts": hosts[p.policy_id],
            "profiles": _profiles_count(entry), "exclusions": len(objs.exclusions), "net_rules": len(objs.net_rules),
            "settings_total": len(flat_settings(sections)), "settings_known": len(described_settings[0]) if described_settings else 0,
        })
        exclusions.extend(
            {"snapshot_id": sid, "policy_id": p.policy_id, "profile": e.profile[:255], "kind": e.kind[:32], "value": e.value,
             "components_json": json.dumps(list(e.components), ensure_ascii=False), "enabled": e.enabled, "comment": e.comment,
             "risks_json": json.dumps(exclusion_risks(e, cfg)), "key": exclusion_key(e)}
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


def _has_policies(db: Session, snapshot_id: int) -> bool:
    return db.scalar(select(KscPolicy.id).where(KscPolicy.snapshot_id == snapshot_id).limit(1)) is not None


def ensure_policy_tables(db: Session, snapshot: KscSnapshot, data_dir: Path) -> bool:
    """Таблицы политик снапшота, импортированного до их появления: пишутся из файла выгрузки при первом чтении,
    вместе с группой у хостов. Находки, сводка и журнал изменений не трогаются. True — дозаполнено сейчас;
    False — строки уже были, файла нет или он не разобран/не записан (тогда экраны остаются пустыми, как раньше,
    причина — в журнале API: чтение не должно падать из-за дозаполнения)."""
    from api.modules.ksc.services.snapshots import snapshot_path

    if _has_policies(db, snapshot.id):
        return False
    path = snapshot_path(data_dir, snapshot.id)
    if not path.exists():
        return False
    # Два одновременных первых чтения: второй ждёт первого и находит строки уже записанными.
    db.execute(text("SELECT pg_advisory_xact_lock(CAST(:ns AS integer), CAST(:sid AS integer))"), {"ns": BACKFILL_LOCK, "sid": snapshot.id})
    if _has_policies(db, snapshot.id):
        db.commit()
        return False
    try:
        idx = ExportIndex(load_export_path(path))
        store_policies(db, snapshot, idx, load_config(db))
        groups: dict[int, list[str]] = {}
        for h in idx.hosts:
            groups.setdefault(h.group_id, []).append(h.host_id[:64])
        for group_id, host_ids in groups.items():
            db.execute(update(KscHost).where(KscHost.snapshot_id == snapshot.id, KscHost.host_id.in_(host_ids)).values(group_id=group_id))
        db.commit()
    except (ExportFormatError, OSError, SQLAlchemyError):
        db.rollback()
        log.exception("таблицы политик снапшота KSC #%s не дозаполнены", snapshot.id)
        return False
    return True
