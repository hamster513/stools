"""Сетевой экран хоста из таблиц снапшота: политика KES хоста, её профили с активацией, правила и строки сетевого экрана.

Сборка — `core/firewall/view`. Таблицы политик снапшота должны быть заполнены (`ensure_policy_tables`) — это делает маршрут.
Строки сетевого экрана и правила сопоставляются с профилем по имени: в KSC имя профиля уникально внутри политики.
"""
from __future__ import annotations

import json
import threading
from collections import OrderedDict, defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.ksc.core.firewall.evaluate import source_sets
from api.modules.ksc.core.firewall.model import HostFirewall, RuleView
from api.modules.ksc.core.firewall.shadow import Shadow, shadows
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
    rules = [rule_view(r) for r in rows]

    def source(profile: str, priority: int | None, active: bool | None) -> Source:
        return Source(profile, priority, active, firewall.get(profile),
                      tuple(r for r in rules if r.profile == profile and r.layer == "packet"),
                      tuple(r for r in rules if r.profile == profile and r.layer == "app"))

    profiles = [source(r.name, r.priority, a.active) for r, a in scope.profiles if r.policy_id == pid]
    fw = host_firewall(h.host_id, h.name, h.ip, pid, policy.name, source("", None, True), profiles, components, notes)
    # Оговорка — только о правилах, которые движок будет проверять (в действующих и неопределённых списках).
    unread = {r.id for r in rows if r.scope_json is None}
    sets = [fw.packet, fw.app, *fw.packet_profiles, *fw.packet_undetermined, *fw.app_profiles, *fw.app_undetermined]
    if unread and any(r.row_id in unread for s in sets if s is not None for r in s.rules):
        fw = replace(fw, notes=(*fw.notes, NOTE_NO_SCOPE))
    return fw


#: Тень наборов между запросами: ключ — `id` строк набора по порядку и хеш всего, что читает `shadows` (одинаковые `id` в
#: разных базах не должны подменять друг друга), значение — результат `shadows`. Расчёт квадратичный по длине набора, сводка
#: секций считает все наборы снапшота; набор остаётся в кэше, пока не вытеснен более новыми (по числу наборов).
_SHADOW_CACHE_SETS = 4096
_shadow_cache: OrderedDict[tuple[tuple[int, ...], int], dict[int, Shadow]] = OrderedDict()
_shadow_lock = threading.Lock()


def _cached_shadows(members: Sequence[KscNetRule]) -> dict[int, Shadow]:
    key = (tuple(m.id for m in members),
           hash(tuple((m.policy_id, m.profile, m.layer, m.position, m.name, m.action, m.enabled, m.scope_json) for m in members)))
    with _shadow_lock:
        if (hit := _shadow_cache.get(key)) is not None:
            _shadow_cache.move_to_end(key)
            return hit
    found = shadows([rule_view(m) for m in members])
    with _shadow_lock:
        _shadow_cache[key] = found
        while len(_shadow_cache) > _SHADOW_CACHE_SETS:
            _shadow_cache.popitem(last=False)
    return found


def shadow_lookup(rows: Sequence[KscNetRule]) -> Callable[[KscNetRule], Shadow | None]:
    """Строка → более раннее правило её набора (политика, профиль, слой), покрывающее её (спека §4.6). Набор считается по
    всем своим строкам при первом обращении к его строке — фильтры списка тень не меняют. Строки без `scope_json` (снапшот
    до структуры, файла для дозаполнения нет) не покрывают и не покрываются: пустая структура значила бы «любой пакет»."""
    groups: dict[tuple[int, str, str], list[KscNetRule]] = defaultdict(list)
    for r in rows:
        if r.scope_json is not None:
            groups[(r.policy_id, r.profile, r.layer)].append(r)
    done: dict[tuple[int, str, str], dict[int, Shadow]] = {}

    def of(r: KscNetRule) -> Shadow | None:
        if r.scope_json is None:
            return None
        key = (r.policy_id, r.profile, r.layer)
        if key not in done:
            done[key] = _cached_shadows(sorted(groups[key], key=lambda m: (m.position, m.id)))
        return done[key].get(r.id)

    return of


@dataclass(frozen=True)
class HostEffective:
    """Какие наборы правил действуют у хоста по слоям при режиме наложения `mode` (`KscConfig.firewall_profile_mode`).

    `packet`/`app` — профили действующих источников слоя по порядку применения ("" — политика): `merge` — политика и активные
    профили с замком списка, `replace` — профиль с наивысшим приоритетом (с правилами), иначе политика; `auto` — объединение
    обоих, то есть как `merge`. Профили с неопределённой активацией сюда не входят и перекрытыми не считаются. Набор не
    действует у хоста — `reason`."""
    mode: str
    #: Действующая политика KES хоста; None — её нет.
    policy_id: int | None
    packet: tuple[str, ...]
    app: tuple[str, ...]
    #: Чьи зоны сетей действуют (профиль с замком зон или ""); None — политики нет.
    networks: str | None
    #: Профили с неопределённой активацией, по слою.
    undetermined: dict[str, frozenset[str]]
    #: Профили с замком и правилами, которые накладываются на список политики (активные и неопределённые), по слою.
    overlays: dict[str, tuple[str, ...]]
    #: Активные профили с замком списка, по слою.
    locked: dict[str, tuple[str, ...]]

    def _effective(self, layer: str) -> tuple[str, ...]:
        return self.packet if layer == "packet" else self.app

    def reason(self, policy_id: int, profile: str, layer: str) -> str:
        """Почему набор у хоста не действует: `replaced` — в режиме `replace` его вытеснил профиль; `unlocked` — у активного
        профиля список без замка (копия политики, движок его не применяет); `inactive` — набор не действующей политики KES
        хоста (неактивная или другая политика группы; у хоста без политики KES — любая); "" — действует или не определено
        (профиль с неопределённой активацией)."""
        if policy_id != self.policy_id:
            return "inactive"
        if profile in self.undetermined.get(layer, frozenset()) or profile in self._effective(layer):
            return ""
        if not profile or profile in self.locked.get(layer, ()):
            return "replaced"
        return "unlocked"

    def overridden(self, policy_id: int, profile: str, layer: str) -> bool:
        return self.reason(policy_id, profile, layer) != ""

    def overridden_by(self, policy_id: int, profile: str, layer: str) -> str:
        """Профиль, который действует вместо набора (только при `replaced`), иначе ""."""
        if self.reason(policy_id, profile, layer) != "replaced":
            return ""
        best = self._effective(layer)[:1]
        return best[0] if best and best[0] != profile else ""

    def json(self) -> dict[str, object]:
        def sets(names: tuple[str, ...]) -> list[dict[str, object]]:
            return [{"policy_id": self.policy_id, "profile": p} for p in names]

        networks = {"policy_id": self.policy_id, "profile": self.networks} if self.networks is not None else None
        return {"packet": sets(self.packet), "app": sets(self.app), "networks": networks, "mode": self.mode}


def host_effective(fw: HostFirewall, mode: str) -> HostEffective:
    model = "merge" if mode == "auto" else mode
    if fw.policy_id is None:
        return HostEffective(mode, None, (), (), None, {}, {}, {})
    return HostEffective(
        mode=mode, policy_id=fw.policy_id,
        packet=tuple(s.profile for s in source_sets(fw, model, layer="packet")),
        app=tuple(s.profile for s in source_sets(fw, model, layer="app")),
        networks=fw.zones_profile,
        undetermined={"packet": frozenset(s.profile for s in fw.packet_undetermined), "app": frozenset(s.profile for s in fw.app_undetermined)},
        overlays={"packet": tuple(s.profile for s in (*fw.packet_profiles, *fw.packet_undetermined) if s.rules),
                  "app": tuple(s.profile for s in (*fw.app_profiles, *fw.app_undetermined) if s.rules)},
        locked={"packet": tuple(s.profile for s in fw.packet_profiles), "app": tuple(s.profile for s in fw.app_profiles)},
    )
