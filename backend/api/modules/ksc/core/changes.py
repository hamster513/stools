"""Журнал изменений: разница двух выгрузок одного сервера — политики, привязка к группам, профили,
настройки, исключения и сетевые правила.

Чистые функции над `KscExport`; запись в базу — `services/changes`. Сравнивается только то, что собрано
в обеих выгрузках: `Diff.compared` отличает «сравнивать не с чем» от «изменений нет»; секция, не прочитанная
хотя бы в одной (в `errors` политики или профиля), не сравнивается вовсе, как и атрибуты или настройки
профиля, чтение которых отказало. Скрытые значения (`<скрыто>`) равны друг другу — смена секрета в журнал
не попадает.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, replace
from typing import Any

from api.modules.ksc.core.export import ExportIndex, KscExport, _int
from api.modules.ksc.core.policy_contents import flat_settings
from api.modules.ksc.core.policy_index import (
    PolicyRow,
    ProfileRow,
    policy_rows,
    profile_rows,
    scope_rows,
)
from api.modules.ksc.core.policy_model import (
    Exclusion,
    NetRule,
    PolicyObjects,
    exclusion_key,
    extract,
    net_rule_key,
)

KINDS = ("policy", "scope", "profile", "setting", "net_rule", "exclusion")
MAX_CHANGES = 20_000

#: Признак включённости профиля в его атрибутах: сравнивается полем `enabled`, в условии не учитывается.
_ENABLED = "KLSSPOL_PRF_ENABLED"
#: Ошибка политики сверх лимита сборщика: ни содержимое, ни профили не читались.
_LIMIT = "лимит политик"

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


def _priorities_unread(export: KscExport) -> set[int]:
    """Политики, у которых профили есть, а порядок не прочитан (`GetPriorities` отказал): профили встали по имени."""
    return {_int(key) for key, entry in (export.policy_profiles or {}).items()
            if entry.get("profiles") and entry.get("errors") and not entry.get("priorities")}


def _failed_sections(errors: Iterable[Any]) -> set[str]:
    """Секции, которые не прочитаны: ошибка секции — «имя: сообщение»."""
    return {str(e).split(": ", 1)[0] for e in errors if ": " in str(e)}


def _attrs_read(p: ProfileRow) -> bool:
    """Атрибуты пусты и есть ошибка — `GetProfile` отказал: включённость и условие неизвестны."""
    return bool(p.condition) or not p.errors


def _sections_read(p: ProfileRow) -> bool:
    """Настройки пусты и есть ошибка — `GetProfileSettings` отказал: настройки профиля неизвестны."""
    return bool(p.sections) or not p.errors


def _profile_view(p: ProfileRow) -> dict[str, Any]:
    return {"enabled": p.enabled, "priority": p.priority, "condition": _condition(p)}


def _condition(p: ProfileRow) -> dict[str, Any]:
    return {k: v for k, v in p.condition.items() if k != _ENABLED}


def _profiles(old: dict[tuple[int, str], ProfileRow], new: dict[tuple[int, str], ProfileRow], names: dict[int, str],
              no_priority: set[int], out: list[Change]) -> None:
    """`no_priority` — политики, у которых порядок профилей не прочитан хотя бы в одном снапшоте."""
    for key in sorted(old.keys() | new.keys()):
        a, b = old.get(key), new.get(key)
        pid, name = key
        if a is None and b is not None:
            out.append(Change("profile", "added", pid, names.get(pid, ""), profile=name, after=_profile_view(b)))
        elif b is None and a is not None:
            out.append(Change("profile", "removed", pid, names.get(pid, ""), profile=name, before=_profile_view(a)))
        elif a is not None and b is not None:
            attrs = _attrs_read(a) and _attrs_read(b)
            fields = [(field, x, y) for field, x, y, known in (
                ("enabled", a.enabled, b.enabled, attrs), ("priority", a.priority, b.priority, pid not in no_priority),
                ("condition", _condition(a), _condition(b), attrs),
            ) if known]
            out.extend(Change("profile", "changed", pid, names.get(pid, ""), profile=name, path=field, before=x, after=y)
                       for field, x, y in fields if _json(x) != _json(y))


Owners = dict[str, dict[str, Any]]


def _without(sections: dict[str, Any], skip: set[str]) -> dict[str, Any]:
    return {name: value for name, value in sections.items() if name not in skip}


def _comparable(old_content: dict[str, Any], new_content: dict[str, Any], old_profiles: dict[str, ProfileRow],
                new_profiles: dict[str, ProfileRow]) -> tuple[Owners, Owners]:
    """Секции по владельцу («» — сама политика, иначе имя профиля), прочитанные в обоих снапшотах: секция из
    `errors` любого из них убирается с обеих сторон, профиль с отказавшим чтением настроек — целиком."""
    skip = _failed_sections(old_content.get("errors") or []) | _failed_sections(new_content.get("errors") or [])
    old: Owners = {"": _without(old_content.get("sections") or {}, skip)}
    new: Owners = {"": _without(new_content.get("sections") or {}, skip)}
    for name in old_profiles.keys() | new_profiles.keys():
        a, b = old_profiles.get(name), new_profiles.get(name)
        if (a is not None and not _sections_read(a)) or (b is not None and not _sections_read(b)):
            continue
        skip = _failed_sections(a.errors if a else []) | _failed_sections(b.errors if b else [])
        if a is not None:
            old[name] = _without(a.sections, skip)
        if b is not None:
            new[name] = _without(b.sections, skip)
    return old, new


def _setting_map(owners: Owners) -> dict[SettingKey, tuple[Any, bool | None]]:
    """(профиль, секция, путь листа) → (значение, замок); `profile=""` — сама политика. Листья (`flat_settings`) —
    чтобы журнал не зависел от уровня контейнеров `KLPRSS_Val` в выгрузке."""
    return {(owner, s.section, s.path): (s.value, s.locked) for owner, sections in owners.items() for s in flat_settings(sections)}


def _objects(product: str, owners: Owners) -> PolicyObjects | None:
    """Записи извлекателя по тем же секциям, что и настройки; None — продукт не описан."""
    out = PolicyObjects()
    for owner, sections in owners.items():
        found = extract(product, sections)
        if found is None:
            return None
        out.exclusions.extend(replace(e, profile=owner) for e in found.exclusions)
        out.net_rules.extend(replace(r, profile=owner) for r in found.net_rules)
        out.consumed |= found.consumed
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
            if not before["removed"] and not after["added"] and ol == nl:
                continue  # те же элементы в другом порядке — не изменение
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
                "setting": contents, "net_rule": False, "exclusion": False}

    out: list[Change] = []
    _policies(old_pol, new_pol, out)
    _scope(pi, ci, names, out)

    # Профили — только у политик, чьи профили прочитаны в обоих снапшотах: иначе отказ чтения выглядел бы удалением.
    profiled = _profiles_read(prev) & _profiles_read(cur) if compared["profile"] else set()
    old_prof = {(p.policy_id, p.name): p for p in profile_rows(prev) or [] if p.policy_id in profiled}
    new_prof = {(p.policy_id, p.name): p for p in profile_rows(cur) or [] if p.policy_id in profiled}
    _profiles(old_prof, new_prof, names, _priorities_unread(prev) | _priorities_unread(cur), out)

    settings: list[Change] = []
    net_rules: list[Change] = []
    exclusions: list[Change] = []
    #: Хоть у одной политики продукт описан в обоих снапшотах: иначе записи извлекателя «не сравнивались», а не «без изменений».
    described_any = False
    if contents:
        for pid in sorted(old_pol.keys() & new_pol.keys()):
            key = str(pid)
            old_content = prev.policy_contents.get(key) or {}
            new_content = cur.policy_contents.get(key) or {}
            if not old_content.get("sections") or not new_content.get("sections"):
                continue
            if _LIMIT in (old_content.get("errors") or []) or _LIMIT in (new_content.get("errors") or []):
                continue
            # Профили — только прочитанные в обоих снапшотах (`profiled`): записи профилей — при том же условии, что настройки.
            old_owners, new_owners = _comparable(old_content, new_content, {n: p for (i, n), p in old_prof.items() if i == pid},
                                                 {n: p for (i, n), p in new_prof.items() if i == pid})
            old_objs = _objects(old_pol[pid].product, old_owners)
            new_objs = _objects(new_pol[pid].product, new_owners)
            consumed = (old_objs.consumed if old_objs else set()) | (new_objs.consumed if new_objs else set())
            _settings(pid, names[pid], _setting_map(old_owners), _setting_map(new_owners), consumed, settings)
            if old_objs is not None and new_objs is not None:
                described_any = True
                _records("net_rule", pid, names[pid], old_objs.net_rules, new_objs.net_rules, net_rule_key, net_rules)
                _records("exclusion", pid, names[pid], old_objs.exclusions, new_objs.exclusions, exclusion_key, exclusions)
    compared["net_rule"] = compared["exclusion"] = described_any
    out.extend(settings)
    out.extend(net_rules)
    out.extend(exclusions)

    if len(out) > MAX_CHANGES:
        return Diff(out[:MAX_CHANGES], compared, truncated=True)
    return Diff(out, compared)
