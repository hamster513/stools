"""Задачи обновления и поиска: есть ли они для каждой группы с защищёнными хостами.

Тип задачи определяется по TASK_NAME (подстроки): у KES это `Update` и
`Scan…`; на живых данных имена уточняются, список констант ниже.
"""
from __future__ import annotations

from typing import Any

from api.modules.ksc.core.checks.common import date_str, days_since
from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.export import ExportIndex, _dt, _str, unwrap
from api.modules.ksc.core.findings import Finding, finalize

UPDATE_TASK_NAMES = ("update", "doupdate")
#: `ods` (on-demand scan) — так задача поиска называется у KES на живом сервере.
SCAN_TASK_NAMES = ("scan", "ods")


def _task_group_id(t: dict[str, Any]) -> tuple[dict[str, Any], int]:
    info: dict[str, Any] = unwrap(t.get("TASK_INFO_PARAMS")) or {}
    gid_raw = info.get("PRTS_TASK_GROUPID")
    try:
        group_id = int(gid_raw) if gid_raw is not None else -1
    except (TypeError, ValueError):
        group_id = -1  # значение есть, но не число: считаем, что задача группу не покрывает
    return info, group_id


def _task_target(idx: ExportIndex, t: dict[str, Any], info: dict[str, Any], group_id: int) -> str:
    name = _str(info.get("DisplayName")) or _str(t.get("TASK_NAME"))
    return f"{name} ({idx.group_path(group_id)})"


def _task_groups(idx: ExportIndex, names: tuple[str, ...]) -> set[int]:
    """Группы, на которые действует хотя бы одна задача указанного типа (с наследованием вниз)."""
    covered: set[int] = set()
    for t in idx.export.tasks:
        name = str(unwrap(t.get("TASK_NAME")) or "").lower()
        if not any(n in name for n in names):
            continue
        info, group_id = _task_group_id(t)
        if group_id < 0:
            continue
        covered.update([group_id] if info.get("PRTS_TASK_PROHIBITED_FOR_SUBGROUPS") else idx.subtree(group_id))
    return covered


def check_task_failed(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Провалы групповой задачи обновления или поиска: statistics["16"] > 0."""
    out = []
    for t in idx.export.tasks:
        name = str(unwrap(t.get("TASK_NAME")) or "").lower()
        if not any(n in name for n in UPDATE_TASK_NAMES + SCAN_TASK_NAMES):
            continue
        info, group_id = _task_group_id(t)
        if group_id < 0:
            continue
        stats: dict[str, Any] = unwrap(t.get("statistics")) or {}
        failed = int(stats.get("16") or 0)
        if failed <= 0:
            continue
        success = int(stats.get("4") or 0)
        warning = int(stats.get("8") or 0)
        total = failed + success + warning
        share = failed / total if total else 1.0
        severity = "High" if share >= cfg.task_failed_share else "Medium"
        out.append(finalize(Finding(
            "TASK_FAILED", severity, target=_task_target(idx, t, info, group_id),
            details={"failed": failed, "success": success, "warning": warning, "total": total, "share": round(share, 2)},
            key_extra=_str(t.get("TASK_UNIQUE_ID")),
        ), cfg))
    return out


def check_task_stale(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Задача обновления не запускалась дольше `task_stale_days` или никогда (задач поиска не касается)."""
    out = []
    for t in idx.export.tasks:
        name = str(unwrap(t.get("TASK_NAME")) or "").lower()
        if not any(n in name for n in UPDATE_TASK_NAMES):
            continue
        info, group_id = _task_group_id(t)
        if group_id < 0:
            continue
        last_exec = _dt(t.get("TASK_LAST_EXEC_TIME"))
        age = days_since(last_exec, idx.now)
        if age is None or age > cfg.task_stale_days:
            out.append(finalize(Finding(
                "TASK_STALE", "Medium", target=_task_target(idx, t, info, group_id),
                details={"last_exec": date_str(last_exec), "age_days": age, "threshold_days": cfg.task_stale_days},
                key_extra=_str(t.get("TASK_UNIQUE_ID")),
            ), cfg))
    return out


def _groups_with_protection(idx: ExportIndex) -> list[int]:
    return sorted(g for g, hosts in idx.hosts_by_group.items() if g in idx.groups_by_id and any(h.protection_installed for h in hosts))


def check_task_no_update(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    covered = _task_groups(idx, UPDATE_TASK_NAMES)
    return [finalize(Finding("TASK_NO_UPDATE", "Medium", target=idx.group_path(g), details={"hosts": len(idx.hosts_by_group[g])}), cfg) for g in _groups_with_protection(idx) if g not in covered]


def check_task_no_scan(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    covered = _task_groups(idx, SCAN_TASK_NAMES)
    return [finalize(Finding("TASK_NO_SCAN", "Low", target=idx.group_path(g), details={"hosts": len(idx.hosts_by_group[g])}), cfg) for g in _groups_with_protection(idx) if g not in covered]
