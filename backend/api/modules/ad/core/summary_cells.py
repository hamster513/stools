"""Ячейки сводки: состав каждого числа «Сводки» — учётки, которые дали это число.

Состав берётся из тех же списков (`summary.*_sets`), длины которых стали числами сводки,
и с теми же параметрами, с которыми сводка строилась (`params`): число и состав не расходятся.

Идентификатор ячейки — компоненты через «:», последний может сам содержать «:»:
`accounts:<users|computers>:<ключ>`, `<password_age|last_logon>:<all|admins>:<le|over>`,
`groups:<поле>:<SID группы>`, `os:<поле>:<сборка>:<имя ОС>`.
Ключ учётки — `sid or dn`, как `source_key` хоста AD в «Активах».
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import AdObject, ExportIndex
from api.modules.ad.core.summary import (
    ACCOUNT_KEYS,
    AGE_BOUNDS,
    GROUP_FIELDS,
    OS_FIELDS,
    account_sets,
    age_sets,
    group_name,
    group_sets,
    os_sets,
)


@dataclass(frozen=True)
class Cell:
    label: str
    users: frozenset[str]
    computers: frozenset[str]


_ACCOUNT_LABELS = {
    "total": "всего",
    "enabled": "включено",
    "disabled": "выключено",
    "active": "активно",
    "inactive": "неактивно",
    "pwd_never_expires": "пароль не истекает",
    "pwd_not_required": "пароль не требуется",
    "no_preauth": "без предварительной аутентификации Kerberos",
    "sid_history": "с SID History",
    "delegation": "с делегированием",
    "laps": "с LAPS",
}
_KINDS = {"users": "Пользователи", "computers": "Компьютеры"}
_AGE_BLOCKS = {"password_age": ("Возраст пароля", "pwdLastSet"), "last_logon": ("Давность входа", "lastLogonTimestamp")}
_SCOPES = ("all", "admins")
_GROUP_LABELS = {
    "members": "участники",
    "enabled": "включённые пользователи",
    "inactive": "неактивные",
    "pwd_never_expires": "пароль не истекает",
    "delegable": "делегируемые",
    "protected_users": "в Protected Users",
}
_OS_LABELS = {"total": "всего", "enabled": "включено", "active": "активно"}


def _keys(objs: list[AdObject]) -> frozenset[str]:
    return frozenset(o.sid or o.dn for o in objs)


def _cell(label: str, objs: list[AdObject], *, computers: bool) -> Cell:
    keys = _keys(objs)
    return Cell(label, frozenset(), keys) if computers else Cell(label, keys, frozenset())


def _bucket_ids() -> list[str]:
    return [*(str(le) for le in AGE_BOUNDS), "over"]


def _bucket_label(pos: int) -> str:
    """Точный интервал корзины: «181–365 дн.», последняя — «> 1095 дн. или неизвестно»."""
    if pos == len(AGE_BOUNDS):
        return f"> {AGE_BOUNDS[-1]} дн. или неизвестно"
    low = AGE_BOUNDS[pos - 1] + 1 if pos else 0
    return f"{low}–{AGE_BOUNDS[pos]} дн."


def summary_cells(idx: ExportIndex, cfg: AdConfig) -> dict[str, Cell]:
    """Все ячейки снапшота, включая нулевые."""
    cells: dict[str, Cell] = {}
    for kind, objs, days, laps in (
        ("users", idx.objects("user"), cfg.user_inactivity_days, False),
        ("computers", idx.objects("computer"), cfg.computer_inactivity_days, True),
    ):
        for key, members in account_sets(idx, objs, days, laps).items():
            cells[f"accounts:{kind}:{key}"] = _cell(f"{_KINDS[kind]}: {_ACCOUNT_LABELS[key]}", members, computers=kind == "computers")
    for block, (title, attr) in _AGE_BLOCKS.items():
        for scope, bins in age_sets(idx, cfg, attr).items():
            suffix = ", админы" if scope == "admins" else ""
            for pos, (bucket, members) in enumerate(zip(_bucket_ids(), bins, strict=True)):
                cells[f"{block}:{scope}:{bucket}"] = _cell(f"{title} {_bucket_label(pos)}{suffix}", members, computers=False)
    for g, row in group_sets(idx, cfg):
        for field, members in row.items():
            label = f"Группа «{group_name(g)}»: {_GROUP_LABELS[field]}"
            # Участники — и пользователи, и компьютеры; всё, что не пользователь, ищется среди активов.
            users = [m for m in members if m.cls == "user"]
            others = [m for m in members if m.cls != "user"]
            cells[f"groups:{field}:{g.sid or ''}"] = Cell(label, _keys(users), _keys(others))
    for (name, build), os_row in os_sets(idx, idx.objects("computer"), cfg.computer_inactivity_days).items():
        title = f"ОС «{name or 'не указана'}»" + (f" {build}" if build else "")
        for field, members in os_row.items():
            cells[f"os:{field}:{build}:{name}"] = _cell(f"{title}: {_OS_LABELS[field]}", members, computers=True)
    return cells


def cell_count(summary: dict[str, Any], cell_id: str) -> int | None:
    """Число ячейки в JSON сводки; None — такой ячейки в сводке нет."""
    block, _, rest = cell_id.partition(":")
    if block == "accounts":
        kind, _, key = rest.partition(":")
        if kind not in _KINDS or key not in ACCOUNT_KEYS or (kind == "users" and key == "laps"):
            return None
        return int(summary["accounts"][kind][key])
    if block in _AGE_BLOCKS:
        scope, _, bucket = rest.partition(":")
        if scope not in _SCOPES or bucket not in _bucket_ids():
            return None
        le = None if bucket == "over" else int(bucket)
        return next((int(b["n"]) for b in summary[block][scope] if b["le"] == le), None)
    if block == "groups":
        field, _, sid = rest.partition(":")
        if field not in GROUP_FIELDS:
            return None
        return next((int(g[field]) for g in summary["groups"] if g["sid"] == sid), None)
    if block == "os":
        parts = rest.split(":", maxsplit=2)
        if len(parts) != 3 or parts[0] not in OS_FIELDS:
            return None
        field, build, name = parts
        return next((int(r[field]) for r in summary["os"] if r["build"] == build and r["name"] == name), None)
    return None


def summary_params(cfg: AdConfig) -> dict[str, Any]:
    """Параметры для сводки — как их кладёт build_summary."""
    return cfg.model_dump(mode="json")


def params_config(summary: dict[str, Any], fallback: AdConfig) -> AdConfig:
    """Настройки, с которыми построена сводка; у сводки без них (версия 1) — `fallback`."""
    params = summary.get("params")
    if summary.get("version", 1) < 2 or not isinstance(params, dict):
        return fallback
    return AdConfig.model_validate(params)
