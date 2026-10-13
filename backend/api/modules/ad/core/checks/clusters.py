"""Кластеры Windows (Failover Clustering) по SPN компьютеров: учётка кластера (CNO), роль (VCO), узел.

Признак — только SPN: описание «Failover cluster virtual network name account» есть не у всех.
Роль привязывается к кластеру по ms-DS-CreatorSID (роль создаёт учётка кластера); узлы к
кластеру из AD не привязать — прямой ссылки в каталоге нет (спека 2026-10-13).
"""
from __future__ import annotations

from collections.abc import Iterable

from api.modules.ad.core.checks.common import date_str
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import AdObject, ExportIndex
from api.modules.ad.core.findings import Finding, finalize

CLUSTER, ROLE, NODE = "cluster", "role", "node"
KIND_TITLES = {CLUSTER: "кластер", ROLE: "роль кластера", NODE: "узел кластера"}
UNKNOWN_CLUSTER = "не определён"


def cluster_kind(spns: Iterable[str]) -> str | None:
    """cluster | role | node | None по видам SPN компьютера."""
    kinds = {s.split("/", 1)[0].lower() for s in spns}
    if "msservercluster" in kinds:
        return CLUSTER
    if "msclustervirtualserver" in kinds:
        return ROLE
    if "msserverclustermgmtapi" in kinds:
        return NODE
    return None


def _created(obj: AdObject) -> str:
    return obj.whenCreated.date().isoformat() if obj.whenCreated else ""


def check_clusters(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    """Информационные находки: кластеры с их ролями, роли с кластером, узлы. Allowlist не применяется."""
    kinds = {c.dn: k for c in idx.objects("computer") if (k := cluster_kind(c.spn))}
    roles_of: dict[str, list[AdObject]] = {}
    cluster_of: dict[str, str] = {}
    for c in idx.objects("computer"):
        if kinds.get(c.dn) != ROLE:
            continue
        owner = idx.by_sid.get(c.creatorSid or "")
        if owner is not None and kinds.get(owner.dn) == CLUSTER:
            roles_of.setdefault(owner.dn, []).append(c)
            cluster_of[c.dn] = owner.label
    out = []
    for c in idx.objects("computer"):
        kind = kinds.get(c.dn)
        if kind is None:
            continue
        details: dict[str, object] = {
            "kind": kind, "kind_title": KIND_TITLES[kind], "sam": c.sam or "", "enabled": c.enabled,
            "fqdn": c.dNSHostName or "", "os": c.operatingSystem or "", "os_version": c.operatingSystemVersion or "",
            "created": _created(c), "last_logon": date_str(c.lastLogonTimestamp),
        }
        if kind == CLUSTER:
            roles = roles_of.get(c.dn, [])
            details["roles"] = sorted(r.label for r in roles)
            details["roles_disabled"] = sum(1 for r in roles if not r.enabled)
        elif kind == ROLE:
            details["cluster"] = cluster_of.get(c.dn, UNKNOWN_CLUSTER)
            if not c.enabled:
                details["details"] = "выключена — роль, вероятно, брошена"
        out.append(finalize(Finding(
            check="Clusters", severity="Info", identity=idx.principal_name(c.sid) or c.label, identity_sid=c.sid or "",
            target=c.dn, key_extra=kind, details=details,
        ), cfg, allowlist=False))
    return out
