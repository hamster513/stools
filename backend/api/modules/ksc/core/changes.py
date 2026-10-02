"""Журнал изменений: разница двух выгрузок одного сервера — политики, привязка к группам, профили,
настройки, исключения и сетевые правила.

Чистые функции над `KscExport`; запись в базу — `services/changes`. Сравнивается только то, что собрано
в обеих выгрузках: `Diff.compared` отличает «сравнивать не с чем» от «изменений нет». Скрытые значения
(`<скрыто>`) равны друг другу — смена секрета в журнал не попадает.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from typing import Any

from api.modules.ksc.core.export import ExportIndex, KscExport, _int
from api.modules.ksc.core.policy_contents import walk_settings
from api.modules.ksc.core.policy_index import (
    PolicyRow,
    ProfileRow,
    policy_objects,
    policy_rows,
    profile_rows,
    scope_rows,
)
from api.modules.ksc.core.policy_model import Exclusion, NetRule, exclusion_key, net_rule_key

KINDS = ("policy", "scope", "profile", "setting", "net_rule", "exclusion")
MAX_CHANGES = 20_000

#: Признак включённости профиля в его атрибутах: сравнивается полем `enabled`, в условии не учитывается.
_ENABLED = "KLSSPOL_PRF_ENABLED"

SettingKey = tuple[str, str, str]


@dataclass(frozen=True)
class Change:
    kind: str
    #: added | removed | changed
    action: str
    policy_id: int | None
    policy_name: str
    profile: str = ""
    section: str = ""
    path: str = ""
    #: Сериализуются в `before_json` / `after_json` как есть.
    before: Any = None
    after: Any = None


@dataclass
class Diff:
    changes: list[Change]
    #: вид → сравнивался ли он; False — в одном из снапшотов не собрано.
    compared: dict[str, bool]
    truncated: bool = False


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def _index(export: KscExport) -> ExportIndex:
    """Индекс без хостов: сравнению нужны только пути групп, а записи хостов большой выгрузки строятся секундами."""
    return ExportIndex(export.model_copy(update={"hosts": []}))


def _brief(p: PolicyRow) -> dict[str, Any]:
    return {"name": p.name, "product": p.product, "group": p.group_path}


def _policies(old: dict[int, PolicyRow], new: dict[int, PolicyRow], out: list[Change]) -> None:
    for pid in sorted(old.keys() | new.keys()):
        a, b = old.get(pid), new.get(pid)
        if a is None and b is not None:
            out.append(Change("policy", "added", pid, b.name, after=_brief(b)))
        elif b is None and a is not None:
            out.append(Change("policy", "removed", pid, a.name, before=_brief(a)))
        elif a is not None and b is not None:
            fields = (("name", a.name, b.name), ("active", a.active, b.active), ("group", a.group_path, b.group_path),
                      ("accept_parent", a.accept_parent, b.accept_parent))
            out.extend(Change("policy", "changed", pid, b.name, path=name, before=x, after=y) for name, x, y in fields if x != y)


def _scope(prev: ExportIndex, cur: ExportIndex, names: dict[int, str], out: list[Change]) -> None:
    old = {(s.policy_id, s.group_id): s.group_path for s in scope_rows(prev)}
    new = {(s.policy_id, s.group_id): s.group_path for s in scope_rows(cur)}
    for key in sorted(old.keys() ^ new.keys()):
        action, path = ("added", new[key]) if key in new else ("removed", old[key])
        out.append(Change("scope", action, key[0], names.get(key[0], ""), path=path))


def _profiles_read(export: KscExport) -> set[int]:
    """Политики, профили которых прочитаны: есть в секции и чтение списка не отказало (ошибка и ни одного профиля)."""
    return {_int(key) for key, entry in (export.policy_profiles or {}).items() if entry.get("profiles") or not entry.get("errors")}


def _profile_view(p: ProfileRow) -> dict[str, Any]:
    return {"enabled": p.enabled, "priority": p.priority, "condition": _condition(p)}


def _condition(p: ProfileRow) -> dict[str, Any]:
    return {k: v for k, v in p.condition.items() if k != _ENABLED}


def _profiles(old: dict[tuple[int, str], ProfileRow], new: dict[tuple[int, str], ProfileRow], names: dict[int, str], out: list[Change]) -> None:
    for key in sorted(old.keys() | new.keys()):
        a, b = old.get(key), new.get(key)
        pid, name = key
        if a is None and b is not None:
            out.append(Change("profile", "added", pid, names.get(pid, ""), profile=name, after=_profile_view(b)))
        elif b is None and a is not None:
            out.append(Change("profile", "removed", pid, names.get(pid, ""), profile=name, before=_profile_view(a)))
        elif a is not None and b is not None:
            fields = (("enabled", a.enabled, b.enabled), ("priority", a.priority, b.priority), ("condition", _condition(a), _condition(b)))
            out.extend(Change("profile", "changed", pid, names.get(pid, ""), profile=name, path=field, before=x, after=y)
                       for field, x, y in fields if _json(x) != _json(y))


def _setting_map(sections: dict[str, Any], profiles: Iterable[ProfileRow]) -> dict[SettingKey, tuple[Any, bool | None]]:
    """(профиль, секция, путь) → (значение, замок); `profile=""` — сама политика."""
    out = {("", s.section, s.path): (s.value, s.locked) for s in walk_settings(sections)}
    for pr in profiles:
        out.update({(pr.name, s.section, s.path): (s.value, s.locked) for s in walk_settings(pr.sections)})
    return out


def _settings(pid: int, name: str, old: dict[SettingKey, tuple[Any, bool | None]], new: dict[SettingKey, tuple[Any, bool | None]],
              skip: set[tuple[str, str]], out: list[Change]) -> None:
    for key in sorted(old.keys() | new.keys()):
        profile, section, path = key
        if (section, path) in skip:
            continue
        if key not in old:
            value, locked = new[key]
            out.append(Change("setting", "added", pid, name, profile, section, path, after={"value": value, "locked": locked}))
            continue
        if key not in new:
            value, locked = old[key]
            out.append(Change("setting", "removed", pid, name, profile, section, path, before={"value": value, "locked": locked}))
            continue
        (ov, ol), (nv, nl) = old[key], new[key]
        if _json(ov) == _json(nv) and ol == nl:
            continue
        before: dict[str, Any]
        after: dict[str, Any]
        if isinstance(ov, list) and isinstance(nv, list):
            ok, nk = {_json(x) for x in ov}, {_json(x) for x in nv}
            before, after = {"removed": [x for x in ov if _json(x) not in nk]}, {"added": [x for x in nv if _json(x) not in ok]}
        else:
            before, after = {"value": ov}, {"value": nv}
        if ol != nl:
            before["locked"], after["locked"] = ol, nl
        out.append(Change("setting", "changed", pid, name, profile, section, path, before=before, after=after))


def _records(kind: str, pid: int, name: str, old: Iterable[Exclusion | NetRule], new: Iterable[Exclusion | NetRule],
             key: Callable[[Any], str], out: list[Change]) -> None:
    """Записи извлекателя по (профиль, ключ); `path` — ключ записи (как `key` в таблице)."""
    a = {(r.profile, key(r)): asdict(r) for r in old}
    b = {(r.profile, key(r)): asdict(r) for r in new}
    for k in sorted(a.keys() | b.keys()):
        x, y = a.get(k), b.get(k)
        if x == y:
            continue
        action = "added" if x is None else "removed" if y is None else "changed"
        out.append(Change(kind, action, pid, name, profile=k[0], path=k[1], before=x, after=y))


def diff_exports(prev: KscExport, cur: KscExport) -> Diff:
    """Что изменилось от `prev` к `cur`; порядок — по видам `KINDS`, внутри вида — по политике и пути."""
    pi, ci = _index(prev), _index(cur)
    old_pol = {p.policy_id: p for p in policy_rows(pi)}
    new_pol = {p.policy_id: p for p in policy_rows(ci)}
    names = {**{k: p.name for k, p in old_pol.items()}, **{k: p.name for k, p in new_pol.items()}}
    contents = bool(prev.policy_contents) and bool(cur.policy_contents)
    compared = {"policy": True, "scope": True, "profile": prev.policy_profiles is not None and cur.policy_profiles is not None,
                "setting": contents, "net_rule": contents, "exclusion": contents}

    out: list[Change] = []
    _policies(old_pol, new_pol, out)
    _scope(pi, ci, names, out)

    # Профили — только у политик, чьи профили прочитаны в обоих снапшотах: иначе отказ чтения выглядел бы удалением.
    profiled = _profiles_read(prev) & _profiles_read(cur) if compared["profile"] else set()
    old_prof = {(p.policy_id, p.name): p for p in profile_rows(prev) or [] if p.policy_id in profiled}
    new_prof = {(p.policy_id, p.name): p for p in profile_rows(cur) or [] if p.policy_id in profiled}
    _profiles(old_prof, new_prof, names, out)

    settings: list[Change] = []
    net_rules: list[Change] = []
    exclusions: list[Change] = []
    if contents:
        for pid in sorted(old_pol.keys() & new_pol.keys()):
            key = str(pid)
            old_sections = (prev.policy_contents.get(key) or {}).get("sections") or {}
            new_sections = (cur.policy_contents.get(key) or {}).get("sections") or {}
            if not old_sections or not new_sections:
                continue
            old_objs, old_described = policy_objects(prev, key)
            new_objs, new_described = policy_objects(cur, key)
            old_map = _setting_map(old_sections, [p for (i, _), p in old_prof.items() if i == pid])
            new_map = _setting_map(new_sections, [p for (i, _), p in new_prof.items() if i == pid])
            _settings(pid, names[pid], old_map, new_map, old_objs.consumed | new_objs.consumed, settings)
            if old_described and new_described:
                # Записи профилей — при том же условии, что настройки профилей.
                with_profiles = pid in profiled
                _records("net_rule", pid, names[pid], [r for r in old_objs.net_rules if with_profiles or not r.profile],
                         [r for r in new_objs.net_rules if with_profiles or not r.profile], net_rule_key, net_rules)
                _records("exclusion", pid, names[pid], [e for e in old_objs.exclusions if with_profiles or not e.profile],
                         [e for e in new_objs.exclusions if with_profiles or not e.profile], exclusion_key, exclusions)
    out.extend(settings)
    out.extend(net_rules)
    out.extend(exclusions)

    if len(out) > MAX_CHANGES:
        return Diff(out[:MAX_CHANGES], compared, truncated=True)
    return Diff(out, compared)
