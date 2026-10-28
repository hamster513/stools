"""Сетевой экран хоста из таблиц снапшота: политика KES хоста, её профили с активацией, правила и строки сетевого экрана.

Сборка — `core/firewall/view`. Таблицы политик снапшота должны быть заполнены (`ensure_policy_tables`) — это делает маршрут.
"""
from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.ksc.core.firewall.model import HostFirewall, RuleView
from api.modules.ksc.core.firewall.view import (
    NOTE_INACTIVE_POLICY,
    NOTE_NO_POLICY,
    NOTE_NO_SCOPE,
    Source,
    host_firewall,
)
from api.modules.ksc.core.policy_model import (
    FirewallSettings,
    Scope,
    app_groups_from_json,
    locks_from_json,
    scope_from_json,
    zones_from_json,
)
from api.modules.ksc.models import KscNetRule, KscPolicy, KscPolicyFirewall
from api.modules.ksc.services.host_scope import HostScope, host_scope


def rule_view(r: KscNetRule) -> RuleView:
    """Правило с разобранной структурой; без `scope_json` (строка до дозаполнения) — пустая структура."""
    return RuleView(
        row_id=r.id, policy_id=r.policy_id, profile=r.profile, layer=r.layer, position=r.position, name=r.name, action=r.action,
        enabled=r.enabled, scope=scope_from_json(r.scope_json) or Scope(), direction_text=r.direction, protocol_text=r.protocol,
        local_ports_text=r.local_ports, remote_ports_text=r.remote_ports, addresses_text=r.addresses,
    )


def _settings(row: KscPolicyFirewall) -> FirewallSettings:
    return FirewallSettings(
        enabled=row.enabled, notify_only=row.notify_only, hips_enabled=row.hips_enabled, hips_notify_only=row.hips_notify_only,
        zones=zones_from_json(row.zones_json), app_groups=app_groups_from_json(row.app_groups_json), locks=locks_from_json(row.locks_json),
        component_enabled=row.component_enabled, hips_component_enabled=row.hips_component_enabled, default_app_group=row.default_app_group,
    )


def _host_policy(scope: HostScope) -> tuple[KscPolicy | None, list[str]]:
    """Активная политика KES группы хоста: своя, иначе первая по имени. Неактивная политика KES (в том числе для автономных
    пользователей — тип не различается) не проверяется, о ней оговорка."""
    kes = [(p, own) for p, own in scope.policies if p.product == "KES"]
    active = [(p, own) for p, own in kes if p.active]
    notes = [] if active else [NOTE_NO_POLICY]
    if any(not p.active for p, _ in kes):
        notes.append(NOTE_INACTIVE_POLICY)
    policy = next((p for p, own in active if own), active[0][0] if active else None)
    return policy, notes


def load_host_firewall(db: Session, snapshot_id: int, host_id: str) -> HostFirewall:
    """404 — хоста нет в снапшоте."""
    scope = host_scope(db, snapshot_id, host_id)
    h = scope.host
    components = [(str(name), code) for name, code in json.loads(h.components_json or "[]")]
    policy, notes = _host_policy(scope)
    if policy is None:
        return host_firewall(h.host_id, h.name, h.ip, None, "", None, (), components, notes)
    pid = policy.policy_id
    firewall = {
        f.profile: _settings(f)
        for f in db.execute(select(KscPolicyFirewall).where(KscPolicyFirewall.snapshot_id == snapshot_id, KscPolicyFirewall.policy_id == pid)).scalars()
    }
    rows = list(db.execute(
        select(KscNetRule).where(KscNetRule.snapshot_id == snapshot_id, KscNetRule.policy_id == pid).order_by(KscNetRule.position, KscNetRule.id)
    ).scalars())
    if any(r.scope_json is None for r in rows):
        notes.append(NOTE_NO_SCOPE)
    rules = [rule_view(r) for r in rows]

    def source(profile: str, priority: int | None, active: bool | None) -> Source:
        return Source(profile, priority, active, firewall.get(profile),
                      tuple(r for r in rules if r.profile == profile and r.layer == "packet"),
                      tuple(r for r in rules if r.profile == profile and r.layer == "app"))

    profiles = [source(r.name, r.priority, a.active) for r, a in scope.profiles if r.policy_id == pid]
    return host_firewall(h.host_id, h.name, h.ip, pid, policy.name, source("", None, True), profiles, components, notes)
