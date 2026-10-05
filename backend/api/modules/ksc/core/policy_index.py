"""Строки таблиц политик из выгрузки: политики, их привязка к группам, профили, записи извлекателя.

Чистые функции над `KscExport`/`ExportIndex`; запись в базу — `services/policy_store`.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, replace
from typing import Any

from api.modules.ksc.core.export import ExportIndex, KscExport, _dt, _int, _str, unwrap
from api.modules.ksc.core.policy_contents import walk_settings
from api.modules.ksc.core.policy_model import PolicyObjects, extract


@dataclass(frozen=True)
class PolicyRow:
    policy_id: int
    name: str
    product: str
    version: str
    group_id: int
    group_path: str
    active: bool
    accept_parent: bool
    modified_at: dt.datetime | None
    has_contents: bool
    #: Содержимое есть, но часть секций не прочиталась (`errors` записи не пуст).
    contents_partial: bool


@dataclass(frozen=True)
class ScopeRow:
    policy_id: int
    group_id: int
    group_path: str
    #: Политика создана в этой группе; False — унаследована от предка.
    own: bool
    #: Хостов прямо в группе (без подгрупп).
    hosts: int


@dataclass(frozen=True)
class ProfileRow:
    policy_id: int
    name: str
    enabled: bool
    #: С 0 по списку приоритетов политики; профили не из списка — в конец по имени.
    priority: int
    #: Атрибуты профиля как пришли (включённость и условие активации `EXPRESSION`), секреты скрыты при загрузке.
    condition: dict[str, Any]
    settings: int
    errors: list[str]
    sections: dict[str, Any]


def policy_rows(idx: ExportIndex) -> list[PolicyRow]:
    """Все политики выгрузки, включая политики агента и сервера."""
    contents = idx.export.policy_contents
    out: list[PolicyRow] = []
    for p in idx.export.policies:
        policy_id = _int(p.get("KLPOL_ID"))
        group_id = _int(p.get("KLPOL_GROUP_ID"))
        content = contents.get(str(policy_id))
        out.append(PolicyRow(
            policy_id=policy_id, name=_str(p.get("KLPOL_DN")), product=_str(p.get("KLPOL_PRODUCT")), version=_str(p.get("KLPOL_VERSION")),
            group_id=group_id, group_path=idx.group_path(group_id), active=bool(unwrap(p.get("KLPOL_ACTIVE"))),
            accept_parent=bool(unwrap(p.get("KLPOL_ACCEPT_PARENT"))), modified_at=_dt(p.get("KLPOL_MODIFIED")),
            has_contents=content is not None and bool(content.get("sections")),
            contents_partial=content is not None and bool(content.get("sections")) and bool(content.get("errors")),
        ))
    return out


def scope_rows(idx: ExportIndex) -> list[ScopeRow]:
    """Где действует политика — по `effective_policies`: строка на (группа, политика)."""
    out: list[ScopeRow] = []
    for key, policies in idx.export.effective_policies.items():
        group_id = _int(key)
        hosts = len(idx.hosts_by_group.get(group_id, []))
        path = idx.group_path(group_id)
        for p in policies:
            out.append(ScopeRow(_int(p.get("KLPOL_ID")), group_id, path, _int(p.get("KLPOL_GROUP_ID")) == group_id, hosts))
    return out


def profile_rows(export: KscExport) -> list[ProfileRow] | None:
    """Профили всех политик; None — секции `policy_profiles` в выгрузке нет (не собрано)."""
    if export.policy_profiles is None:
        return None
    out: list[ProfileRow] = []
    for key, entry in export.policy_profiles.items():
        profiles = entry.get("profiles") or []
        rank = {str(name): i for i, name in enumerate(entry.get("priorities") or [])}
        ordered = sorted(profiles, key=lambda pr: (rank.get(_str(pr.get("name")), len(rank)), _str(pr.get("name"))))
        for priority, pr in enumerate(ordered):
            attrs = pr.get("attrs") or {}
            sections = pr.get("sections") or {}
            out.append(ProfileRow(
                policy_id=_int(key), name=_str(pr.get("name")), enabled=bool(unwrap(attrs.get("KLSSPOL_PRF_ENABLED", True))), priority=priority,
                condition=attrs, settings=len(walk_settings(sections)), errors=[str(e) for e in pr.get("errors") or []], sections=sections,
            ))
    return out


def policy_objects(export: KscExport, policy_id: str) -> tuple[PolicyObjects, bool]:
    """Записи политики и её профилей (у записей профиля `profile` — имя профиля); bool — продукт описан."""
    policy = next((p for p in export.policies if _str(p.get("KLPOL_ID")) == policy_id), {})
    product = _str(policy.get("KLPOL_PRODUCT"))
    objs = extract(product, (export.policy_contents.get(policy_id) or {}).get("sections") or {})
    if objs is None:
        return PolicyObjects(), False
    out = PolicyObjects(list(objs.exclusions), list(objs.net_rules), set(objs.consumed))
    entry = (export.policy_profiles or {}).get(policy_id) or {}
    for pr in entry.get("profiles") or []:
        name = _str(pr.get("name"))
        found = extract(product, pr.get("sections") or {})
        if found is None:
            continue
        out.exclusions.extend(replace(e, profile=name) for e in found.exclusions)
        out.net_rules.extend(replace(r, profile=name) for r in found.net_rules)
        out.consumed |= found.consumed
    return out, True
