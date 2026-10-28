"""Что действует на хост снапшота: политики его группы и активация их профилей по тегам хоста.

Общая часть карточки хоста (`routers/hosts`), фильтра записей по хосту (`routers/policy_objects`) и движка сетевых
правил (`services/firewall`).
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.ksc.core.profile_activation import (
    REASON_DISABLED,
    Activation,
    evaluate,
    parse_condition,
)
from api.modules.ksc.models import KscHost, KscPolicy, KscPolicyScope, KscProfile


def host_tags(h: KscHost, collected: bool) -> list[str] | None:
    """Теги хоста; None — сборщик секцию тегов не присылал (не собрано, а не «без тегов»)."""
    if not collected:
        return None
    return list(json.loads(h.extra_json or "{}").get("tags", []))


def tags_collected_db(db: Session, snapshot_id: int) -> bool:
    """Секция тегов была в выгрузке, если ключ `tags` есть хотя бы у одного хоста снапшота (поиск по тексту, без разбора JSON всех хостов)."""
    has_tags = select(KscHost.id).where(KscHost.snapshot_id == snapshot_id, KscHost.extra_json.like('%"tags"%')).limit(1)
    return db.scalar(has_tags) is not None


def scope_policies(db: Session, snapshot_id: int, h: KscHost) -> list[tuple[KscPolicy, bool]]:
    """Политики, действующие на группу хоста, по имени; bool — политика создана в этой группе, а не унаследована."""
    if h.group_id is None:
        return []
    rows = db.execute(
        select(KscPolicy, KscPolicyScope.own)
        .join(KscPolicyScope, (KscPolicyScope.snapshot_id == KscPolicy.snapshot_id) & (KscPolicyScope.policy_id == KscPolicy.policy_id))
        .where(KscPolicy.snapshot_id == snapshot_id, KscPolicyScope.group_id == h.group_id)
    ).all()
    return sorted(((p, own) for p, own in rows), key=lambda r: (r[0].name.lower(), r[0].policy_id))


def find_host(db: Session, snapshot_id: int, host_id: str) -> KscHost:
    """404 — хоста нет в снапшоте."""
    h = db.execute(select(KscHost).where(KscHost.snapshot_id == snapshot_id, KscHost.host_id == host_id)).scalars().first()
    if h is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="хост не найден")
    return h


@dataclass(frozen=True)
class HostScope:
    """Что действует на хост: политики его группы и активация каждого их профиля по тегам хоста."""

    host: KscHost
    #: None — теги не собраны.
    tags: list[str] | None
    policies: list[tuple[KscPolicy, bool]]
    #: По политикам в порядке `policies`, внутри — по приоритету; выключенный профиль — не активен, «профиль выключен».
    profiles: list[tuple[KscProfile, Activation]]


def host_scope(db: Session, snapshot_id: int, host_id: str) -> HostScope:
    """404 — хоста нет в снапшоте. Таблицы политик снапшота должны быть заполнены (`ensure_policy_tables`)."""
    h = find_host(db, snapshot_id, host_id)
    tags = host_tags(h, tags_collected_db(db, snapshot_id))
    policies = scope_policies(db, snapshot_id, h)
    order = {p.policy_id: n for n, (p, _) in enumerate(policies)}
    rows: list[KscProfile] = []
    if order:
        rows = list(db.execute(select(KscProfile).where(KscProfile.snapshot_id == snapshot_id, KscProfile.policy_id.in_(list(order)))).scalars())
    profiles: list[tuple[KscProfile, Activation]] = []
    for r in sorted(rows, key=lambda r: (order[r.policy_id], r.priority, r.id)):
        groups = parse_condition(json.loads(r.condition_json or "{}"))
        a = evaluate(groups, tags) if r.enabled else Activation(False, (), groups, REASON_DISABLED)
        profiles.append((r, a))
    return HostScope(h, tags, policies, profiles)
