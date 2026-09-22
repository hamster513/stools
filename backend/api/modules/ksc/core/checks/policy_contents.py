"""Содержимое политик: доля замкнутых настроек и отсутствие собранного содержимого."""
from __future__ import annotations

from typing import Any

from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.export import (
    PRODUCT_AGENT,
    PRODUCT_SERVER,
    ExportIndex,
    _int,
    _str,
    unwrap,
)
from api.modules.ksc.core.findings import Finding, finalize
from api.modules.ksc.core.policy_contents import LockSummary, lock_summary, walk_settings


def _policies_by_id(idx: ExportIndex) -> dict[str, dict[str, Any]]:
    return {_str(p.get("KLPOL_ID")): p for p in idx.export.policies}


def _protection_policies(idx: ExportIndex) -> list[dict[str, Any]]:
    """Активные политики продуктов защиты (не агент, не сервер) — те же, что собирает сборщик."""
    return [
        p for p in idx.export.policies
        if bool(unwrap(p.get("KLPOL_ACTIVE"))) and _str(p.get("KLPOL_PRODUCT")) not in (PRODUCT_AGENT, PRODUCT_SERVER)
    ]


def _target_details(idx: ExportIndex, policy_id: str, policies: dict[str, dict[str, Any]], content: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    policy = policies.get(policy_id, {})
    target = _str(policy.get("KLPOL_DN")) or policy_id
    product = _str(policy.get("KLPOL_PRODUCT")) or str(content.get("product") or "")
    group = idx.group_path(_int(policy.get("KLPOL_GROUP_ID"))) if policy else ""
    return target, {"product": product, "group": group}


def _summary_details(idx: ExportIndex, policy_id: str, policies: dict[str, dict[str, Any]], content: dict[str, Any], summary: LockSummary) -> tuple[str, dict[str, Any]]:
    target, details = _target_details(idx, policy_id, policies, content)
    details.update(total=summary.total, locked=summary.locked, share=summary.share)
    return target, details


def check_policy_no_locks(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Активная политика продукта защиты, в которой ни одна настройка не замкнута:
    любую из них можно переопределить локально на устройстве."""
    out = []
    policies = _policies_by_id(idx)
    for policy_id, content in idx.export.policy_contents.items():
        summary = lock_summary(walk_settings(content.get("sections", {})))
        if summary.total > 0 and summary.locked == 0:
            target, details = _summary_details(idx, policy_id, policies, content, summary)
            out.append(finalize(Finding(check="POLICY_NO_LOCKS", severity="High", target=target, details=details, key_extra=policy_id), cfg))
    return out


def check_policy_weak_locks(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Доля замкнутых настроек политики ниже порога `policy_lock_share`, но не нулевая
    (нулевая доля — это `POLICY_NO_LOCKS`)."""
    out = []
    policies = _policies_by_id(idx)
    for policy_id, content in idx.export.policy_contents.items():
        summary = lock_summary(walk_settings(content.get("sections", {})))
        if summary.total > 0 and summary.locked > 0 and summary.share < cfg.policy_lock_share:
            target, details = _summary_details(idx, policy_id, policies, content, summary)
            out.append(finalize(Finding(check="POLICY_WEAK_LOCKS", severity="Medium", target=target, details=details, key_extra=policy_id), cfg))
    return out


def check_policy_content_missing(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Активная политика продукта защиты, содержимого которой нет в секции `policy_contents`
    (нет прав или ошибка сбора) — справочно, чтобы отсутствие данных не выглядело как
    отсутствие проблем. Молчит целиком на файле без секции (старый сборщик)."""
    if not idx.export.policy_contents:
        return []
    out = []
    policies = _policies_by_id(idx)
    for policy in _protection_policies(idx):
        policy_id = _str(policy.get("KLPOL_ID"))
        if policy_id in idx.export.policy_contents:
            continue
        target, details = _target_details(idx, policy_id, policies, {})
        out.append(finalize(Finding(check="POLICY_CONTENT_MISSING", severity="Info", target=target, details=details, key_extra=policy_id), cfg))
    return out
