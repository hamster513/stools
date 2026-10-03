"""Исключения и сетевые правила снапшота: поиск, фильтры, дубли и перекрытия, фасеты, сводка по политикам.

Записи строятся при импорте извлекателем продукта; пока извлекателя нет (`undescribed`), список пуст — это «не описан»,
а не «исключений нет». Числа дублей и перекрытий считаются в памяти по строкам снапшота (их сотни или тысячи).
"""
from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.ksc.core.policy_model import Exclusion, covered_by
from api.modules.ksc.models import KscExclusion, KscNetRule, KscPolicy, KscSnapshot

router = APIRouter(tags=["ksc"])

MAX_LIMIT = 1000
DUP = ("multi", "single", "covered")


def _snapshot(db: Session, snapshot_id: int) -> KscSnapshot:
    snap = db.get(KscSnapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    return snap


def _policies(db: Session, snapshot_id: int) -> dict[int, KscPolicy]:
    return {p.policy_id: p for p in db.execute(select(KscPolicy).where(KscPolicy.snapshot_id == snapshot_id)).scalars()}


def _undescribed(policies: dict[int, KscPolicy]) -> list[str]:
    """Продукты политик с содержимым, для которых нет извлекателя."""
    return sorted({p.product for p in policies.values() if p.has_contents and not p.described})


def _count(facet: dict[str, int], value: str) -> None:
    facet[value] = facet.get(value, 0) + 1


def _name(policies: dict[int, KscPolicy], policy_id: int) -> str:
    p = policies.get(policy_id)
    return p.name if p is not None else ""


def _order(policies: dict[int, KscPolicy], policy_id: int) -> tuple[str, int]:
    return (_name(policies, policy_id).lower(), policy_id)


def _covered(rows: list[KscExclusion]) -> dict[int, str | None]:
    """Строка → значение более широкого исключения той же политики и профиля (None — не перекрыто)."""
    groups: dict[tuple[int, str], list[tuple[KscExclusion, Exclusion]]] = defaultdict(list)
    for r in rows:
        groups[(r.policy_id, r.profile)].append((r, Exclusion(r.kind, r.value, enabled=r.enabled)))
    out: dict[int, str | None] = {}
    for members in groups.values():
        others = [e for _, e in members]
        for r, e in members:
            wider = covered_by(e, others)
            out[r.id] = wider.value if wider is not None else None
    return out


def _exclusion_item(r: KscExclusion, name: str, policies: int, covered: str | None) -> dict[str, Any]:
    return {
        "id": r.id, "policy_id": r.policy_id, "policy_name": name, "profile": r.profile, "kind": r.kind, "value": r.value,
        "components": json.loads(r.components_json or "[]"), "enabled": r.enabled, "comment": r.comment, "risks": json.loads(r.risks_json or "[]"),
        "key": r.key, "policies": policies, "covered_by": covered,
    }


@router.get("/snapshots/{snapshot_id}/exclusions")
def list_exclusions(
    snapshot_id: int,
    q: str = "",
    policy_id: int | None = None,
    profile: str | None = None,
    kind: str = "",
    enabled: bool | None = None,
    dup: str = "",
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    _snapshot(db, snapshot_id)
    if dup and dup not in DUP:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"неизвестное значение фильтра «{dup}»")
    policies = _policies(db, snapshot_id)
    rows = list(db.execute(select(KscExclusion).where(KscExclusion.snapshot_id == snapshot_id)).scalars())
    # В скольких политиках встречается ключ и чем перекрыто исключение — по всем строкам снапшота, а не по отфильтрованным.
    owners: dict[str, set[int]] = defaultdict(set)
    for r in rows:
        owners[r.key].add(r.policy_id)
    covered = _covered(rows)
    needle = q.strip().lower()

    def keep(r: KscExclusion) -> bool:
        if policy_id is not None and r.policy_id != policy_id:
            return False
        if profile is not None and r.profile != profile:
            return False
        if kind and r.kind != kind:
            return False
        if enabled is not None and r.enabled != enabled:
            return False
        n = len(owners[r.key])
        if (dup == "multi" and n < 2) or (dup == "single" and n != 1) or (dup == "covered" and covered[r.id] is None):
            return False
        return not needle or needle in r.value.lower() or needle in r.comment.lower() or needle in _name(policies, r.policy_id).lower()

    kept = sorted((r for r in rows if keep(r)), key=lambda r: (*_order(policies, r.policy_id), r.profile, r.value.lower(), r.id))
    facets: dict[str, dict[str, int]] | None = None
    summary: list[dict[str, Any]] | None = None
    if offset == 0:
        facets = {"policy": {}, "kind": {}, "enabled": {"true": 0, "false": 0}, "dup": dict.fromkeys(DUP, 0)}
        for r in kept:
            _count(facets["policy"], str(r.policy_id))
            _count(facets["kind"], r.kind)
            facets["enabled"]["true" if r.enabled else "false"] += 1
            facets["dup"]["multi" if len(owners[r.key]) > 1 else "single"] += 1
            if covered[r.id] is not None:
                facets["dup"]["covered"] += 1
        # Сводка — без фильтров, по политикам с описанным продуктом и собранным содержимым (иначе «ноль» значил бы «не собрано»).
        by_policy: dict[int, dict[str, int]] = {p.policy_id: {} for p in policies.values() if p.described and p.has_contents}
        for r in rows:
            _count(by_policy.setdefault(r.policy_id, {}), r.kind)
        summary = [
            {"policy_id": pid, "policy_name": _name(policies, pid), "hosts": policies[pid].hosts if pid in policies else 0,
             "total": sum(kinds.values()), "by_kind": kinds}
            for pid, kinds in sorted(by_policy.items(), key=lambda kv: _order(policies, kv[0]))
        ]
    page = kept[offset : offset + limit]
    return {
        "total": len(kept), "items": [_exclusion_item(r, _name(policies, r.policy_id), len(owners[r.key]), covered[r.id]) for r in page],
        "facets": facets, "summary": summary, "undescribed": _undescribed(policies),
    }


def _net_rule_item(r: KscNetRule, name: str) -> dict[str, Any]:
    return {
        "id": r.id, "policy_id": r.policy_id, "policy_name": name, "profile": r.profile, "layer": r.layer, "position": r.position, "name": r.name,
        "action": r.action, "direction": r.direction, "protocol": r.protocol, "local_ports": r.local_ports, "remote_ports": r.remote_ports,
        "addresses": r.addresses, "enabled": r.enabled, "key": r.key,
    }


@router.get("/snapshots/{snapshot_id}/net-rules")
def list_net_rules(
    snapshot_id: int,
    q: str = "",
    policy_id: int | None = None,
    profile: str | None = None,
    action: str = "",
    direction: str = "",
    enabled: bool | None = None,
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    _snapshot(db, snapshot_id)
    policies = _policies(db, snapshot_id)
    rows = list(db.execute(select(KscNetRule).where(KscNetRule.snapshot_id == snapshot_id)).scalars())
    needle = q.strip().lower()

    def keep(r: KscNetRule) -> bool:
        if policy_id is not None and r.policy_id != policy_id:
            return False
        if profile is not None and r.profile != profile:
            return False
        if (action and r.action != action) or (direction and r.direction != direction) or (enabled is not None and r.enabled != enabled):
            return False
        return not needle or any(needle in f.lower() for f in (r.name, r.addresses, r.local_ports, r.remote_ports))

    kept = sorted((r for r in rows if keep(r)), key=lambda r: (*_order(policies, r.policy_id), r.profile, r.layer, r.position, r.id))
    facets: dict[str, dict[str, int]] | None = None
    if offset == 0:
        facets = {"policy": {}, "action": {}, "direction": {}, "layer": {}, "enabled": {"true": 0, "false": 0}}
        for r in kept:
            _count(facets["policy"], str(r.policy_id))
            _count(facets["action"], r.action)
            _count(facets["direction"], r.direction)
            _count(facets["layer"], r.layer)
            facets["enabled"]["true" if r.enabled else "false"] += 1
    page = kept[offset : offset + limit]
    return {
        "total": len(kept), "items": [_net_rule_item(r, _name(policies, r.policy_id)) for r in page], "facets": facets,
        "undescribed": _undescribed(policies),
    }
