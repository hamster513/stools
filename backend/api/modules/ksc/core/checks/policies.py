"""Политики: действующая политика по продукту в группе и обрыв наследования."""
from __future__ import annotations

from typing import Any

from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.export import PRODUCT_AGENT, PRODUCT_SERVER, ExportIndex, _int, unwrap
from api.modules.ksc.core.findings import Finding, finalize


def _s(v: Any) -> str:
    v = unwrap(v)
    return str(v) if v is not None else ""


def _effective(idx: ExportIndex, group_id: int) -> list[dict[str, Any]]:
    return idx.export.effective_policies.get(str(group_id), [])


def check_policy_none(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """У группы есть хосты с продуктом, а действующей активной политики этого продукта нет."""
    out = []
    for group_id, hosts in idx.hosts_by_group.items():
        if group_id not in idx.groups_by_id:
            continue
        products = {h.product for h in hosts if h.product and h.product not in (PRODUCT_AGENT, PRODUCT_SERVER)}
        acting = {_s(p.get("KLPOL_PRODUCT")) for p in _effective(idx, group_id) if bool(unwrap(p.get("KLPOL_ACTIVE")))}
        for product in sorted(products - acting):
            n = sum(1 for h in hosts if h.product == product)
            out.append(finalize(Finding("POLICY_NONE", "High", target=idx.group_path(group_id), details={"product": product, "hosts": n}, key_extra=product), cfg))
    return out


def check_policy_inherit_broken(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Своя политика в подгруппе с отключённым принятием родительской (KLPOL_ACCEPT_PARENT=false)."""
    out = []
    for p in idx.export.policies:
        group_id = _int(p.get("KLPOL_GROUP_ID"))
        group = idx.groups_by_id.get(group_id)
        if group is None or "parentId" not in group or _int(group.get("parentId")) < 0:
            continue  # корень: наследовать не от кого
        if bool(unwrap(p.get("KLPOL_ACTIVE"))) and not bool(unwrap(p.get("KLPOL_ACCEPT_PARENT"))):
            out.append(finalize(Finding("POLICY_INHERIT_BROKEN", "Low", target=idx.group_path(group_id), details={"policy": _s(p.get("KLPOL_DN")), "product": _s(p.get("KLPOL_PRODUCT"))}, key_extra=_s(p.get("KLPOL_ID"))), cfg))
    return out
