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
    details.update(total=summary.total, locked=summary.locked, with_lock_flag=summary.with_lock_flag, share=summary.share)
    return target, details


def check_policy_no_locks(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Активная политика продукта защиты, в которой ни одна настройка не замкнута:
    любую из них можно переопределить локально на устройстве. Считаются только настройки с
    признаком замка (`KLPRSS_Mnd`); политика без единого признака — формат замков не распознан,
    проверка молчит."""
    out = []
    policies = _policies_by_id(idx)
    for policy_id, content in idx.export.policy_contents.items():
        summary = lock_summary(walk_settings(content.get("sections", {})))
        if summary.with_lock_flag > 0 and summary.locked == 0:
            target, details = _summary_details(idx, policy_id, policies, content, summary)
            out.append(finalize(Finding(check="POLICY_NO_LOCKS", severity="High", target=target, details=details, key_extra=policy_id), cfg))
    return out


def check_policy_weak_locks(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Доля замкнутых настроек политики ниже порога `policy_lock_share`, но не нулевая
    (нулевая доля — это `POLICY_NO_LOCKS`). Доля — среди настроек с признаком замка; политика без
    единого признака молчит."""
    out = []
    policies = _policies_by_id(idx)
    for policy_id, content in idx.export.policy_contents.items():
        summary = lock_summary(walk_settings(content.get("sections", {})))
        if summary.with_lock_flag > 0 and summary.locked > 0 and summary.share < cfg.policy_lock_share:
            target, details = _summary_details(idx, policy_id, policies, content, summary)
            out.append(finalize(Finding(check="POLICY_WEAK_LOCKS", severity="Medium", target=target, details=details, key_extra=policy_id), cfg))
    return out


def check_policy_content_missing(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Активная политика продукта защиты, содержимого которой нет в секции `policy_contents`,
    или оно есть, но ни одна секция не прочиталась (все — в `errors`) — оба случая неотличимы
    от «проблем нет», поэтому справочная находка. Молчит целиком на файле без секции (старый
    сборщик) — саму секцию `policy_contents == {}` от «поля не было в JSON» не отличить."""
    if not idx.export.policy_contents:
        return []
    out = []
    policies = _policies_by_id(idx)
    contents = idx.export.policy_contents
    for policy_id, content in contents.items():
        if content.get("sections"):
            continue
        target, details = _target_details(idx, policy_id, policies, content)
        errors = [str(e) for e in (content.get("errors") or [])]
        details.update(case="empty", reason="; ".join(errors[:3]))
        out.append(finalize(Finding(check="POLICY_CONTENT_MISSING", severity="Info", target=target, details=details, key_extra=policy_id), cfg))
    for policy in _protection_policies(idx):
        policy_id = _str(policy.get("KLPOL_ID"))
        if policy_id in contents:
            continue
        target, details = _target_details(idx, policy_id, policies, {})
        details.update(case="missing", reason="")
        out.append(finalize(Finding(check="POLICY_CONTENT_MISSING", severity="Info", target=target, details=details, key_extra=policy_id), cfg))
    return out
