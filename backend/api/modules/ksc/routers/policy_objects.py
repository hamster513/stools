"""Исключения и сетевые правила снапшота: поиск, фильтры, дубли и перекрытия, фасеты, сводка по политикам, карточки.

Записи строятся при импорте извлекателем продукта; пока извлекателя нет (`undescribed`), список пуст — это «не описан»,
а не «исключений нет». Числа дублей и перекрытий считаются в памяти по строкам снапшота (их сотни или тысячи).
"""
from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.ksc.core.exclusion_risks import RISKS
from api.modules.ksc.core.policy_model import Exclusion, covered_by
from api.modules.ksc.models import KscExclusion, KscNetRule, KscPolicy, KscSnapshot
from api.modules.ksc.routers.hosts import host_scope
from api.modules.ksc.services.policy_store import ensure_policy_tables
from api.settings import Settings, get_settings

router = APIRouter(tags=["ksc"])

MAX_LIMIT = 1000
DUP = ("multi", "single", "covered")


class _HostFilter:
    """Фильтр `host_id`: записи политик группы хоста — самой политики и профилей, активных на хосте по тегам. Профиль,
    активацию которого не определить (условие не по тегам, теги не собраны), не исключается, а перечисляется в `undetermined`,
    чтобы интерфейс пометил его записи как «возможно»."""

    def __init__(self, db: Session, snapshot_id: int, host_id: str) -> None:
        scope = host_scope(db, snapshot_id, host_id)
        names = {p.policy_id: p.name for p, _ in scope.policies}
        self.policy_ids = set(names)
        self.active = {(r.policy_id, r.name): a.active for r, a in scope.profiles}
        self.undetermined = [
            {"policy_id": r.policy_id, "policy_name": names[r.policy_id], "profile": r.name} for r, a in scope.profiles if a.active is None
        ]

    def keep(self, policy_id: int, profile: str) -> bool:
        if policy_id not in self.policy_ids:
            return False
        # Профиля нет в таблице профилей (не должно случаться) — как «не определить»: запись остаётся.
        return not profile or self.active.get((policy_id, profile)) is not False


def _snapshot(db: Session, snapshot_id: int, settings: Settings) -> KscSnapshot:
    """Снапшот с заполненными таблицами политик (старый дозаполняется из файла при первом чтении)."""
    snap = db.get(KscSnapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    ensure_policy_tables(db, snap, settings.data_dir)
    return snap


def _policies(db: Session, snapshot_id: int) -> dict[int, KscPolicy]:
    return {p.policy_id: p for p in db.execute(select(KscPolicy).where(KscPolicy.snapshot_id == snapshot_id)).scalars()}


def _undescribed(policies: dict[int, KscPolicy]) -> list[str]:
    """Продукты политик с содержимым, для которых нет извлекателя."""
    return sorted({p.product for p in policies.values() if p.has_contents and not p.described})


def _partial(policies: dict[int, KscPolicy]) -> list[int]:
    """Политики описанного продукта, содержимое которых собрано не полностью: их записи могут быть неполными."""
    return sorted(p.policy_id for p in policies.values() if p.described and p.contents_partial)


def _count(facet: dict[str, int], value: str) -> None:
    facet[value] = facet.get(value, 0) + 1


def _name(policies: dict[int, KscPolicy], policy_id: int) -> str:
    p = policies.get(policy_id)
    return p.name if p is not None else ""


def _order(policies: dict[int, KscPolicy], policy_id: int) -> tuple[str, int]:
    return (_name(policies, policy_id).lower(), policy_id)


def _covered(rows: list[KscExclusion]) -> Callable[[KscExclusion], str | None]:
    """Строка → значение более широкого исключения той же политики и профиля (None — не перекрыто). Перекрытия группы
    (политика, профиль) считаются при первом обращении к её строке: странице без фильтра `dup` и фасетов — только свои группы."""
    groups: dict[tuple[int, str], list[KscExclusion]] = defaultdict(list)
    for r in rows:
        groups[(r.policy_id, r.profile)].append(r)
    done: dict[int, str | None] = {}

    def of(r: KscExclusion) -> str | None:
        if r.id not in done:
            members = [(m, Exclusion(m.kind, m.value, tuple(json.loads(m.components_json or "[]")), enabled=m.enabled))
                       for m in groups[(r.policy_id, r.profile)]]
            others = [e for _, e in members]
            for m, e in members:
                wider = covered_by(e, others)
                done[m.id] = wider.value if wider is not None else None
        return done[r.id]

    return of


def _risks(r: KscExclusion) -> list[str]:
    return list(json.loads(r.risks_json or "[]"))


def _row[R: (KscExclusion, KscNetRule)](db: Session, model: type[R], snapshot_id: int, row_id: int, what: str) -> R:
    """Строка снапшота по id; строки нет или она из другого снапшота — 404."""
    row = db.get(model, row_id)
    if row is None or row.snapshot_id != snapshot_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"{what} не найдено")
    return row


def _same_in[R: (KscExclusion, KscNetRule)](rows: list[R], row: R, policies: dict[int, KscPolicy]) -> list[dict[str, Any]]:
    """Другие строки снапшота с тем же `key` — та же запись в других политиках и профилях (без самой строки), по имени политики."""
    same = sorted((r for r in rows if r.key == row.key and r.id != row.id), key=lambda r: (*_order(policies, r.policy_id), r.profile, r.id))
    return [{"row_id": r.id, "policy_id": r.policy_id, "policy_name": _name(policies, r.policy_id), "profile": r.profile, "enabled": r.enabled}
            for r in same]


def _policy_fields(policies: dict[int, KscPolicy], policy_id: int) -> dict[str, Any]:
    """`policy_hosts` — хостов под политикой записи, `policy_partial` — её содержимое собрано не полностью."""
    p = policies.get(policy_id)
    return {"policy_hosts": p.hosts if p is not None else 0, "policy_partial": p is not None and p.contents_partial}


def _risk_details(codes: list[str]) -> list[dict[str, Any]]:
    """Код, которого уже нет в правилах, — заглушка с кодом вместо заголовка."""
    return [
        {"code": c, "severity": RISKS[c].severity, "title": RISKS[c].title, "detail": RISKS[c].detail, "recommendations": list(RISKS[c].recommendations)}
        if c in RISKS else {"code": c, "severity": "", "title": c, "detail": "", "recommendations": []}
        for c in codes
    ]


def _exclusion_item(r: KscExclusion, name: str, policies: int, covered: str | None) -> dict[str, Any]:
    risks = _risks(r)
    return {
        "id": r.id, "policy_id": r.policy_id, "policy_name": name, "profile": r.profile, "kind": r.kind, "value": r.value,
        "components": json.loads(r.components_json or "[]"), "enabled": r.enabled, "comment": r.comment, "risks": risks,
        # Код, которого уже нет в правилах (снапшот посчитан прежней версией), показывается как есть.
        "risk_titles": [RISKS[c].title if c in RISKS else c for c in risks], "key": r.key, "policies": policies, "covered_by": covered,
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
    risky: bool | None = None,
    host_id: str | None = None,
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    _snapshot(db, snapshot_id, settings)
    if dup and dup not in DUP:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"неизвестное значение фильтра «{dup}»")
    host = _HostFilter(db, snapshot_id, host_id) if host_id else None  # пустая строка — фильтра нет, как у q/kind
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
        if host is not None and not host.keep(r.policy_id, r.profile):
            return False
        if kind and r.kind != kind:
            return False
        if enabled is not None and r.enabled != enabled:
            return False
        if risky is not None and bool(_risks(r)) != risky:
            return False
        n = len(owners[r.key])
        if (dup == "multi" and n < 2) or (dup == "single" and n != 1) or (dup == "covered" and covered(r) is None):
            return False
        return not needle or needle in r.value.lower() or needle in r.comment.lower() or needle in _name(policies, r.policy_id).lower()

    kept = sorted((r for r in rows if keep(r)), key=lambda r: (*_order(policies, r.policy_id), r.profile, r.value.lower(), r.id))
    facets: dict[str, dict[str, int]] | None = None
    summary: list[dict[str, Any]] | None = None
    if offset == 0:
        facets = {"policy": {}, "kind": {}, "enabled": {"true": 0, "false": 0}, "dup": dict.fromkeys(DUP, 0), "risky": {"true": 0, "false": 0}}
        for r in kept:
            _count(facets["policy"], str(r.policy_id))
            _count(facets["kind"], r.kind)
            facets["enabled"]["true" if r.enabled else "false"] += 1
            facets["risky"]["true" if _risks(r) else "false"] += 1
            facets["dup"]["multi" if len(owners[r.key]) > 1 else "single"] += 1
            if covered(r) is not None:
                facets["dup"]["covered"] += 1
        # Сводка — без фильтров, по политикам с описанным продуктом и собранным содержимым (иначе «ноль» значил бы «не собрано»).
        # `partial` — содержимое собрано не полностью: список может быть неполным; `risky` — исключений с рисками.
        by_policy: dict[int, dict[str, int]] = {p.policy_id: {} for p in policies.values() if p.described and p.has_contents}
        risky_by: dict[int, int] = defaultdict(int)
        for r in rows:
            _count(by_policy.setdefault(r.policy_id, {}), r.kind)
            risky_by[r.policy_id] += bool(_risks(r))
        summary = [
            {"policy_id": pid, "policy_name": _name(policies, pid), "hosts": policies[pid].hosts if pid in policies else 0,
             "total": sum(kinds.values()), "by_kind": kinds, "risky": risky_by[pid], "partial": pid in policies and policies[pid].contents_partial}
            for pid, kinds in sorted(by_policy.items(), key=lambda kv: _order(policies, kv[0]))
        ]
    page = kept[offset : offset + limit]
    return {
        "total": len(kept), "items": [_exclusion_item(r, _name(policies, r.policy_id), len(owners[r.key]), covered(r)) for r in page],
        "facets": facets, "summary": summary, "undescribed": _undescribed(policies),
        **({"undetermined": host.undetermined} if host is not None else {}),
    }


@router.get("/snapshots/{snapshot_id}/exclusions/{row_id}")
def get_exclusion(
    snapshot_id: int,
    row_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Карточка исключения: элемент списка, подробности рисков, та же запись в других политиках, хосты политики."""
    _snapshot(db, snapshot_id, settings)
    row = _row(db, KscExclusion, snapshot_id, row_id, "исключение")
    policies = _policies(db, snapshot_id)
    rows = list(db.execute(select(KscExclusion).where(KscExclusion.snapshot_id == snapshot_id)).scalars())
    owners = len({r.policy_id for r in rows if r.key == row.key})
    item = _exclusion_item(row, _name(policies, row.policy_id), owners, _covered(rows)(row))
    return {**item, "risk_details": _risk_details(item["risks"]), "same_in": _same_in(rows, row, policies), **_policy_fields(policies, row.policy_id)}


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
    host_id: str | None = None,
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    _snapshot(db, snapshot_id, settings)
    host = _HostFilter(db, snapshot_id, host_id) if host_id else None  # пустая строка — фильтра нет, как у q/kind
    policies = _policies(db, snapshot_id)
    rows = list(db.execute(select(KscNetRule).where(KscNetRule.snapshot_id == snapshot_id)).scalars())
    needle = q.strip().lower()

    def keep(r: KscNetRule) -> bool:
        if policy_id is not None and r.policy_id != policy_id:
            return False
        if profile is not None and r.profile != profile:
            return False
        if host is not None and not host.keep(r.policy_id, r.profile):
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
        "undescribed": _undescribed(policies), "partial": _partial(policies),
        **({"undetermined": host.undetermined} if host is not None else {}),
    }


@router.get("/snapshots/{snapshot_id}/net-rules/{row_id}")
def get_net_rule(
    snapshot_id: int,
    row_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Карточка сетевого правила: элемент списка, то же правило в других политиках, хосты политики."""
    _snapshot(db, snapshot_id, settings)
    row = _row(db, KscNetRule, snapshot_id, row_id, "правило")
    policies = _policies(db, snapshot_id)
    rows = list(db.execute(select(KscNetRule).where(KscNetRule.snapshot_id == snapshot_id)).scalars())
    return {**_net_rule_item(row, _name(policies, row.policy_id)), "same_in": _same_in(rows, row, policies), **_policy_fields(policies, row.policy_id)}
