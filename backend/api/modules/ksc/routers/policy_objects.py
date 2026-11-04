"""Исключения и сетевые правила снапшота: поиск, фильтры, дубли и перекрытия, фасеты, сводка по политикам, карточки.

Записи строятся при импорте извлекателем продукта; пока извлекателя нет (`undescribed`), список пуст — это «не описан»,
а не «исключений нет». Числа дублей и перекрытий считаются в памяти по строкам снапшота (их сотни или тысячи).
"""
from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Callable

from api.modules.ksc.core.firewall.compare import compare_rules, list_signature
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.ksc.core.exclusion_risks import RISKS
from api.modules.ksc.core.firewall.shadow import Shadow
from api.modules.ksc.core.policy_model import Exclusion, covered_by, locks_from_json
from api.modules.ksc.models import (
    KscExclusion,
    KscNetRule,
    KscPolicy,
    KscPolicyFirewall,
    KscProfile,
    KscSnapshot,
)
from api.modules.ksc.services.firewall import (
    HostEffective,
    host_effective,
    load_host_firewall,
    shadow_lookup,
)
from api.modules.ksc.services.host_scope import host_scope
from api.modules.ksc.services.policy_store import ensure_policy_tables
from api.modules.ksc.services.settings import load_config
from api.platform.export import Column, export_response
from api.platform.filters import QueryInts, QueryList, matches, multi, multi_int
from api.settings import Settings, get_settings

router = APIRouter(tags=["ksc"])

MAX_LIMIT = 1000
DUP = ("multi", "single", "covered")
#: Выгрузке нужен весь отбор: страница списка ограничена `MAX_LIMIT`, здесь — нет.
EXPORT_ALL = 10**9
#: Подписи видов исключений — как на экране (EXCLUSION_KIND_LABELS фронтенда); неизвестный код — как есть.
EXCLUSION_KIND_TITLES = {"path": "путь", "mask": "маска", "hash": "хеш", "threat": "угроза", "trusted_app": "доверенная программа"}


def policy_cell(name: str, profile: str) -> str:
    """Колонка «Политика / профиль» одной строкой: имя политики и профиль либо «сама политика»."""
    return f"{name or '—'} / {f'профиль {profile}' if profile else 'сама политика'}"


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
    policy_id: QueryInts = None,
    profile: str | None = None,
    kind: QueryList = None,
    enabled: bool | None = None,
    dup: QueryList = None,
    risky: bool | None = None,
    host_id: str | None = None,
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Фасеты `policy_id, kind, dup` — повтором ключа, внутри фасета «или»."""
    _snapshot(db, snapshot_id, settings)
    policy_ids, kinds, dups = multi_int(policy_id), multi(kind), multi(dup)
    for d in sorted(dups or ()):
        if d not in DUP:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"неизвестное значение фильтра «{d}»")
    host = _HostFilter(db, snapshot_id, host_id) if host_id else None  # пустая строка — фильтра нет, как у q/kind
    policies = _policies(db, snapshot_id)
    rows = list(db.execute(select(KscExclusion).where(KscExclusion.snapshot_id == snapshot_id)).scalars())
    # В скольких политиках встречается ключ и чем перекрыто исключение — по всем строкам снапшота, а не по отфильтрованным.
    owners: dict[str, set[int]] = defaultdict(set)
    for r in rows:
        owners[r.key].add(r.policy_id)
    covered = _covered(rows)
    needle = q.strip().lower()

    def is_dup(r: KscExclusion, d: str) -> bool:
        n = len(owners[r.key])
        return n > 1 if d == "multi" else n == 1 if d == "single" else covered(r) is not None

    def keep(r: KscExclusion) -> bool:
        if policy_ids is not None and r.policy_id not in policy_ids:
            return False
        if profile is not None and r.profile != profile:
            return False
        if host is not None and not host.keep(r.policy_id, r.profile):
            return False
        if not matches(r.kind, kinds):
            return False
        if enabled is not None and r.enabled != enabled:
            return False
        if risky is not None and bool(_risks(r)) != risky:
            return False
        if dups and not any(is_dup(r, d) for d in dups):
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


EXCLUSION_COLUMNS = [
    Column("value", "Значение"), Column("risk", "Риск"), Column("kind", "Вид"), Column("policy", "Политика/профиль"),
    Column("components", "Компоненты"), Column("enabled", "Включено"), Column("comment", "Комментарий"), Column("policies", "Политик"),
    Column("covered", "Перекрыто"),
]


@router.get("/snapshots/{snapshot_id}/exclusions/export")
def export_exclusions(
    snapshot_id: int,
    q: str = "",
    policy_id: QueryInts = None,
    profile: str | None = None,
    kind: QueryList = None,
    enabled: bool | None = None,
    dup: QueryList = None,
    risky: bool | None = None,
    host_id: str | None = None,
    fmt: str = Query(default="csv", alias="format"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """Исключения под фильтрами списка, в его порядке — тот же отбор (`list_exclusions`) без страницы.
    Риски — их заголовками из правил, а не короткими ярлыками экрана: ярлыков на сервере нет."""
    page = list_exclusions(snapshot_id, q, policy_id, profile, kind, enabled, dup, risky, host_id, limit=EXPORT_ALL, offset=0,
                           db=db, settings=settings, _user=user)
    rows = [
        {"value": e["value"], "risk": "; ".join(e["risk_titles"]), "kind": EXCLUSION_KIND_TITLES.get(e["kind"], e["kind"]),
         "policy": policy_cell(e["policy_name"], e["profile"]), "components": ", ".join(e["components"]),
         "enabled": "да" if e["enabled"] else "нет", "comment": e["comment"], "policies": e["policies"], "covered": e["covered_by"]}
        for e in page["items"]
    ]
    return export_response(fmt, EXCLUSION_COLUMNS, rows, module="ksc", name="exclusions")


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


def _net_rule_item(r: KscNetRule, name: str, shadow: Shadow | None) -> dict[str, Any]:
    return {
        "id": r.id, "policy_id": r.policy_id, "policy_name": name, "profile": r.profile, "layer": r.layer, "position": r.position, "name": r.name,
        "action": r.action, "direction": r.direction, "protocol": r.protocol, "local_ports": r.local_ports, "remote_ports": r.remote_ports,
        "addresses": r.addresses, "enabled": r.enabled, "key": r.key,
        "scope": json.loads(r.scope_json) if r.scope_json else None,
        "shadowed_by": {"row_id": shadow.by_row_id, "position": shadow.by_position, "name": shadow.by_name, "same_action": shadow.same_action}
        if shadow is not None else None,
    }


#: Фильтр слоя сетевых правил; пустая строка — без фильтра, как у `q`.
NetLayer = Literal["packet", "app", ""] | None


class _NetRules:
    """Отбор сетевых правил под фильтрами списка (общий для списка, выгрузки и сводки секций)."""

    def __init__(self, db: Session, snapshot_id: int, q: str, policy_id: QueryInts, profile: str | None, action: QueryList,
                 direction: QueryList, enabled: bool | None, host_id: str | None, layer: NetLayer) -> None:
        policy_ids, actions, directions = multi_int(policy_id), multi(action), multi(direction)
        layer = layer or None
        self.host = _HostFilter(db, snapshot_id, host_id) if host_id else None  # пустая строка — фильтра нет, как у q/kind
        self.policies = _policies(db, snapshot_id)
        self.rows = list(db.execute(select(KscNetRule).where(KscNetRule.snapshot_id == snapshot_id)).scalars())
        needle = q.strip().lower()
        host = self.host

        def keep(r: KscNetRule) -> bool:
            if policy_ids is not None and r.policy_id not in policy_ids:
                return False
            if (profile is not None and r.profile != profile) or (layer is not None and r.layer != layer):
                return False
            if host is not None and not host.keep(r.policy_id, r.profile):
                return False
            if not matches(r.action, actions) or not matches(r.direction, directions) or (enabled is not None and r.enabled != enabled):
                return False
            return not needle or any(needle in f.lower() for f in (r.name, r.addresses, r.local_ports, r.remote_ports))

        self.matches = keep
        self.kept = sorted((r for r in self.rows if keep(r)), key=lambda r: (*_order(self.policies, r.policy_id), r.profile, r.layer, r.position, r.id))
        #: Тень — по всем строкам набора, не по отобранным.
        self.shadow = shadow_lookup(self.rows)


def _effective(db: Session, snapshot_id: int, host_id: str) -> HostEffective:
    """Действующие наборы правил хоста при режиме наложения из настроек модуля."""
    return host_effective(load_host_firewall(db, snapshot_id, host_id), load_config(db).firewall_profile_mode)


@router.get("/snapshots/{snapshot_id}/net-rules")
def list_net_rules(
    snapshot_id: int,
    q: str = "",
    policy_id: QueryInts = None,
    profile: str | None = None,
    action: QueryList = None,
    direction: QueryList = None,
    enabled: bool | None = None,
    host_id: str | None = None,
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    layer: NetLayer = None,
    changes: bool = False,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Фасеты `policy_id, action, direction` — повтором ключа, внутри фасета «или». С `host_id` — действующие у хоста наборы
    (`effective`) и у элемента `overridden`, `overridden_reason`."""
    _snapshot(db, snapshot_id, settings)
    if changes:
        ids = multi_int(policy_id)
        if not profile or ids is None or len(ids) != 1 or layer not in ('packet', 'app'):
            raise HTTPException(422, detail='Для сравнения нужны одна политика, профиль и слой')
        sel = _NetRules(db, snapshot_id, q, policy_id, None, action, direction, enabled, host_id, layer)
        pid = next(iter(ids))
        source = sorted((r for r in sel.rows if r.policy_id == pid and r.layer == layer), key=lambda r: (r.position, r.id))
        compared = compare_rules([r for r in source if not r.profile], [r for r in source if r.profile == profile])
        deltas = [d for d in compared.deltas if sel.matches(d.row) or (d.previous is not None and sel.matches(d.previous))]
        effective = _effective(db, snapshot_id, host_id) if host_id else None
        items = []
        for d in deltas[offset:offset + limit]:
            item = _net_rule_item(d.row, _name(sel.policies, pid), sel.shadow(d.row))
            item['change'] = {'kind': d.kind, 'fields': d.fields, 'moved': d.moved,
                              'previous': _net_rule_item(d.previous, _name(sel.policies, pid), sel.shadow(d.previous)) if d.previous else None}
            if effective is not None:
                item['overridden_reason'] = effective.reason(pid, d.row.profile, layer)
                item['overridden'] = item['overridden_reason'] != ''
            items.append(item)
        return {'total': len(deltas), 'items': items, 'facets': None, 'undescribed': _undescribed(sel.policies), 'partial': _partial(sel.policies)}
    sel = _NetRules(db, snapshot_id, q, policy_id, profile, action, direction, enabled, host_id, layer)
    host, policies, kept = sel.host, sel.policies, sel.kept
    effective = _effective(db, snapshot_id, host_id) if host_id else None
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
    items = [_net_rule_item(r, _name(policies, r.policy_id), sel.shadow(r)) for r in page]
    if effective is not None:
        for item in items:
            item["overridden_reason"] = effective.reason(item["policy_id"], item["profile"], item["layer"])
            item["overridden"] = item["overridden_reason"] != ""
    return {
        "total": len(kept), "items": items, "facets": facets, "undescribed": _undescribed(policies), "partial": _partial(policies),
        **({"undetermined": host.undetermined} if host is not None else {}),
        **({"effective": effective.json()} if effective is not None else {}),
    }


NET_RULE_COLUMNS = [
    Column("name", "Название"), Column("index", "№"), Column("action", "Действие"), Column("direction", "Направление"),
    Column("protocol", "Протокол"), Column("local_ports", "Локальные порты"), Column("remote_ports", "Удалённые порты"),
    Column("addresses", "Адреса"), Column("enabled", "Включено"), Column("policy", "Политика/профиль"),
]


@router.get("/snapshots/{snapshot_id}/net-rules/export")
def export_net_rules(
    snapshot_id: int,
    q: str = "",
    policy_id: QueryInts = None,
    profile: str | None = None,
    action: QueryList = None,
    direction: QueryList = None,
    enabled: bool | None = None,
    host_id: str | None = None,
    layer: NetLayer = None,
    fmt: str = Query(default="csv", alias="format"),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> StreamingResponse:
    """Сетевые правила под фильтрами списка, в его порядке — тот же отбор (`_NetRules`) без страницы; тень и действующие у
    хоста наборы в выгрузку не идут и не считаются."""
    _snapshot(db, snapshot_id, settings)
    sel = _NetRules(db, snapshot_id, q, policy_id, profile, action, direction, enabled, host_id, layer)
    rows = [
        {"name": r.name, "index": r.position, "action": r.action, "direction": r.direction, "protocol": r.protocol,
         "local_ports": r.local_ports, "remote_ports": r.remote_ports, "addresses": r.addresses,
         "enabled": "да" if r.enabled else "нет", "policy": policy_cell(_name(sel.policies, r.policy_id), r.profile)}
        for r in sel.kept
    ]
    return export_response(fmt, NET_RULE_COLUMNS, rows, module="ksc", name="net-rules")


_LAYERS = {"packet": 0, "app": 1}


@router.get("/snapshots/{snapshot_id}/net-rules/sections")
def net_rule_sections(
    snapshot_id: int,
    q: str = "",
    policy_id: QueryInts = None,
    profile: str | None = None,
    action: QueryList = None,
    direction: QueryList = None,
    enabled: bool | None = None,
    host_id: str | None = None,
    layer: NetLayer = None,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """Сводка секций (слой, политика, профиль) под фильтрами списка, без строк: слой (пакетные, затем программ), политика по
    имени, сама политика, затем профили по приоритету. Секция сохраняется также при совпадении фильтра с отсутствующим или прежним правилом политики. `hosts` — хостов под
    политикой (`hosts_kind` "policy"), и у профиля тоже; `shadowed` — отобранные правила в тени (тень — по всему набору).
    С `host_id`: `overridden` — набор у хоста не действует, причина — `overridden_reason` (`HostEffective.reason`), `overlay` — у списка политики,
    на который накладываются профили хоста с замком, — режим наложения из настроек, иначе null."""
    _snapshot(db, snapshot_id, settings)
    sel = _NetRules(db, snapshot_id, q, policy_id, profile, action, direction, enabled, host_id, layer)
    effective = _effective(db, snapshot_id, host_id) if host_id else None
    groups: dict[tuple[str, int, str], list[KscNetRule]] = defaultdict(list)
    for r in sorted(sel.rows, key=lambda r: (r.position, r.id)):
        groups[(r.layer, r.policy_id, r.profile)].append(r)
    profiles = {(p.policy_id, p.name): p.priority for p in db.execute(select(KscProfile).where(KscProfile.snapshot_id == snapshot_id)).scalars()}
    locks = {(f.policy_id, f.profile): locks_from_json(f.locks_json)
             for f in db.execute(select(KscPolicyFirewall).where(KscPolicyFirewall.snapshot_id == snapshot_id)).scalars()}

    for (pid, prof), lock in locks.items():
        if prof:
            for lay in ('packet', 'app'):
                if getattr(lock, lay) is True and (lay, pid, '') in groups:
                    groups.setdefault((lay, pid, prof), [])

    def order(key: tuple[str, int, str]) -> tuple[Any, ...]:
        lay, pid, prof = key
        priority = profiles.get((pid, prof))
        # Профиль без приоритета — последним, как в `evaluate._sources`.
        rank = priority if priority is not None else 1 << 31
        return (_LAYERS.get(lay, len(_LAYERS)), lay, *_order(sel.policies, pid), prof != "", rank, prof.lower(), prof)

    out: list[dict[str, Any]] = []
    for key in sorted(groups, key=order):
        lay, pid, prof = key
        all_rows = groups[key]
        rows = [r for r in all_rows if sel.matches(r)]
        base = groups.get((lay, pid, ''), [])
        comparison = compare_rules(base, all_rows) if prof else None
        differences = sum(sel.matches(d.row) or (d.previous is not None and sel.matches(d.previous)) for d in comparison.deltas) if comparison else 0
        # Ограничения источника действуют и на пустой список профиля.
        ids = multi_int(policy_id)
        if (ids is not None and pid not in ids) or (profile is not None and prof != profile) or (layer and lay != layer):
            continue
        if sel.host is not None and not sel.host.keep(pid, prof):
            continue
        if not rows and not differences:
            continue
        p = sel.policies.get(pid)
        lock = locks.get((pid, prof))
        row: dict[str, Any] = {
            "layer": lay, "policy_id": pid, "policy_name": _name(sel.policies, pid), "profile": prof,
            "content_key": list_signature(all_rows),
            "comparison": {**comparison.summary, "base_rules": len(base), "base_known": bool(base) or (pid, '') in locks,
                           "differences": differences} if comparison else None,
            "priority": profiles.get((pid, prof)) if prof else None, "rules": len(rows), "shadowed": sum(sel.shadow(r) is not None for r in rows),
            "hosts": p.hosts if p is not None else 0, "hosts_kind": "policy",
            "locked": getattr(lock, lay, None) if lock is not None and lay in _LAYERS else None,
            "overridden": False, "overridden_by": "", "overridden_reason": "",
        }
        if effective is not None:
            row["overridden_reason"] = effective.reason(pid, prof, lay)
            row["overridden"] = row["overridden_reason"] != ""
            row["overridden_by"] = effective.overridden_by(pid, prof, lay)
            overlaid = not prof and pid == effective.policy_id and bool(effective.overlays.get(lay))
            row["overlay"] = effective.mode if overlaid else None
        out.append(row)
    return out


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
    item = _net_rule_item(row, _name(policies, row.policy_id), shadow_lookup(rows)(row))
    return {**item, "same_in": _same_in(rows, row, policies), **_policy_fields(policies, row.policy_id)}
