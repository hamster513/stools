"""Задачи обновления и поиска: есть ли они для каждой группы с защищёнными хостами.

Тип задачи определяется по TASK_NAME (подстроки): у KES это `Update` и
`Scan…`; на живых данных имена уточняются, список констант ниже.
"""
from __future__ import annotations

from typing import Any

from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.export import ExportIndex, unwrap
from api.modules.ksc.core.findings import Finding, finalize

UPDATE_TASK_NAMES = ("update", "doupdate")
#: `ods` (on-demand scan) — так задача поиска называется у KES на живом сервере.
SCAN_TASK_NAMES = ("scan", "ods")


def _task_groups(idx: ExportIndex, names: tuple[str, ...]) -> set[int]:
    """Группы, на которые действует хотя бы одна задача указанного типа (с наследованием вниз)."""
    covered: set[int] = set()
    for t in idx.export.tasks:
        name = str(unwrap(t.get("TASK_NAME")) or "").lower()
        if not any(n in name for n in names):
            continue
        info: dict[str, Any] = unwrap(t.get("TASK_INFO_PARAMS")) or {}
        gid_raw = info.get("PRTS_TASK_GROUPID")
        try:
            group_id = int(gid_raw) if gid_raw is not None else -1
        except (TypeError, ValueError):
            group_id = -1  # значение есть, но не число: считаем, что задача группу не покрывает
        if group_id < 0:
            continue
        covered.update([group_id] if info.get("PRTS_TASK_PROHIBITED_FOR_SUBGROUPS") else idx.subtree(group_id))
    return covered


def _groups_with_protection(idx: ExportIndex) -> list[int]:
    return sorted(g for g, hosts in idx.hosts_by_group.items() if g in idx.groups_by_id and any(h.protection_installed for h in hosts))


def check_task_no_update(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    covered = _task_groups(idx, UPDATE_TASK_NAMES)
    return [finalize(Finding("TASK_NO_UPDATE", "Medium", target=idx.group_path(g), details={"hosts": len(idx.hosts_by_group[g])}), cfg) for g in _groups_with_protection(idx) if g not in covered]


def check_task_no_scan(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    covered = _task_groups(idx, SCAN_TASK_NAMES)
    return [finalize(Finding("TASK_NO_SCAN", "Low", target=idx.group_path(g), details={"hosts": len(idx.hosts_by_group[g])}), cfg) for g in _groups_with_protection(idx) if g not in covered]
