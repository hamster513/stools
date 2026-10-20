"""Сводка домена (спека гигиены AD, §6): считается при анализе из той же выгрузки
и хранится в снапшоте — странице «Сводка» не нужно разбирать файл выгрузки.

Флаги учётных записей (пароль не истекает, без preauth, делегирование…) считаются
среди включённых: у выключенной учётки они не дают входа и не интересны.
"""
from __future__ import annotations

import re
from typing import Any

from api.modules.ad.core.checks.account_flags import UAC_NOT_DELEGATED, UAC_PASSWD_NOTREQD
from api.modules.ad.core.checks.clusters import CLUSTER, NODE, ROLE, cluster_kind
from api.modules.ad.core.checks.common import days_between
from api.modules.ad.core.checks.domain import PWD_COMPLEX, PWD_STORE_CLEARTEXT
from api.modules.ad.core.checks.groups import privileged_groups
from api.modules.ad.core.checks.principals import admin_dns, protected_users_dns
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import (
    GPO_FLAG_MACHINE_DISABLED,
    TRUST_ATTRIBUTE_WITHIN_FOREST,
    UAC_DONT_EXPIRE_PASSWORD,
    UAC_DONT_REQ_PREAUTH,
    UAC_PARTIAL_SECRETS_ACCOUNT,
    AdObject,
    ExportIndex,
)

SUMMARY_VERSION = 1
#: Границы корзин возраста пароля и давности входа, дней; последняя корзина — «старше».
AGE_BOUNDS = (30, 90, 180, 365, 730, 1095)
GPO_FLAG_USER_DISABLED = 1
_BUILD = re.compile(r"\((\d+)\)")


def _build(version: str | None) -> str:
    """Номер сборки из «10.0 (20348)»; иначе версия как есть."""
    m = _BUILD.search(version or "")
    return m.group(1) if m else (version or "")


def _active(idx: ExportIndex, obj: AdObject, days: int) -> bool:
    idle = days_between(obj.lastLogonTimestamp, idx.export.collected_at)
    return obj.enabled and idle is not None and idle <= days


def _delegation(obj: AdObject) -> bool:
    # Неограниченная делегация — штатный флаг контроллера, как в Delegation; ограниченная у контроллера
    # считается (её разбирает DcDelegation).
    unconstrained = obj.unconstrained_delegation and not ExportIndex.is_dc(obj)
    return unconstrained or bool(obj.allowedToDelegateTo) or obj.protocol_transition


def _counts(idx: ExportIndex, objs: list[AdObject], days: int, laps: bool) -> dict[str, int]:
    enabled = [o for o in objs if o.enabled]
    active = sum(_active(idx, o, days) for o in enabled)

    def flag(mask: int) -> int:
        return sum(bool((o.uac or 0) & mask) for o in enabled)

    return {
        "total": len(objs),
        "enabled": len(enabled),
        "disabled": len(objs) - len(enabled),
        "active": active,
        "inactive": len(enabled) - active,
        "pwd_never_expires": flag(UAC_DONT_EXPIRE_PASSWORD),
        "pwd_not_required": flag(UAC_PASSWD_NOTREQD),
        "no_preauth": flag(UAC_DONT_REQ_PREAUTH),
        "sid_history": sum(bool(o.sIDHistory) for o in enabled),
        "delegation": sum(_delegation(o) for o in enabled),
        "laps": sum(o.lapsExpiry is not None or o.lapsNewExpiry is not None for o in enabled) if laps else 0,
    }


def _buckets(ages: list[int | None]) -> list[dict[str, Any]]:
    """Неизвестный возраст (не входил, пароль не задан) — в последнюю корзину: сумма равна числу учёток."""
    counts = [0] * (len(AGE_BOUNDS) + 1)
    for age in ages:
        pos = len(AGE_BOUNDS) if age is None else next((i for i, le in enumerate(AGE_BOUNDS) if age <= le), len(AGE_BOUNDS))
        counts[pos] += 1
    return [{"le": le, "n": n} for le, n in zip([*AGE_BOUNDS, None], counts, strict=True)]


def _os(idx: ExportIndex, computers: list[AdObject], days: int) -> list[dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for c in computers:
        name, build = c.operatingSystem or "", _build(c.operatingSystemVersion)
        row = rows.setdefault((name, build), {"name": name, "build": build, "total": 0, "enabled": 0, "active": 0})
        row["total"] += 1
        row["enabled"] += c.enabled
        row["active"] += _active(idx, c, days)
    return sorted(rows.values(), key=lambda r: (-r["total"], r["name"], r["build"]))


def _dcs(idx: ExportIndex) -> list[dict[str, Any]]:
    now = idx.export.collected_at
    out = []
    for d in idx.dcs:
        desc = idx.sd_of(d)
        out.append({
            "name": d.name or d.rdn_value,
            "dn": d.dn,
            "dns": d.dNSHostName or "",
            "os": d.operatingSystem or "",
            "build": _build(d.operatingSystemVersion),
            "rodc": bool((d.uac or 0) & UAC_PARTIAL_SECRETS_ACCOUNT),
            "last_logon_days": days_between(d.lastLogonTimestamp, now),
            "pwd_age_days": days_between(d.pwdLastSet, now),
            "owner": idx.principal_name(desc.owner) if desc and desc.owner else "",
        })
    return sorted(out, key=lambda r: r["name"].lower())


def _groups(idx: ExportIndex, cfg: AdConfig) -> list[dict[str, Any]]:
    protected = protected_users_dns(idx)
    out = []
    for g in privileged_groups(idx, cfg):
        members = idx.members_recursive(g)
        users = [m for m in members if m.cls == "user" and m.enabled]
        out.append({
            "name": g.sam or g.name or g.rdn_value,
            "sid": g.sid or "",
            "members": len(members),
            "enabled": len(users),
            "inactive": sum(not _active(idx, u, cfg.user_inactivity_days) for u in users),
            "pwd_never_expires": sum(bool((u.uac or 0) & UAC_DONT_EXPIRE_PASSWORD) for u in users),
            "delegable": sum(not (u.uac or 0) & UAC_NOT_DELEGATED for u in users),
            "protected_users": sum(u.dn.lower() in protected for u in users),
        })
    return out


def _trusts(idx: ExportIndex) -> list[dict[str, Any]]:
    rows = [
        {
            "partner": t.trustPartner or t.name or t.rdn_value,
            "flat_name": t.flatName or "",
            "direction": t.trustDirection,
            "type": t.trustType,
            "within_forest": bool((t.trustAttributes or 0) & TRUST_ATTRIBUTE_WITHIN_FOREST),
            "changed": t.whenChanged.isoformat() if t.whenChanged else None,
        }
        for t in idx.objects("trustedDomain")
    ]
    return sorted(rows, key=lambda r: str(r["partner"]).lower())


def _password_policies(idx: ExportIndex) -> list[dict[str, Any]]:
    d = idx.export.domain
    props = d.pwd_properties
    out: list[dict[str, Any]] = []
    # Выгрузка старого сборщика политику домена не читала — строка из одних пустот не нужна.
    if any(v is not None for v in (d.min_pwd_length, d.lockout_threshold, props)):
        out.append({
            "name": "Политика домена",
            "min_length": d.min_pwd_length,
            "lockout_threshold": d.lockout_threshold,
            "complexity": None if props is None else bool(props & PWD_COMPLEX),
            "reversible": None if props is None else bool(props & PWD_STORE_CLEARTEXT),
            "precedence": None,
        })
    psos = sorted(idx.objects("msDS-PasswordSettings"), key=lambda p: (p.psoPrecedence is None, p.psoPrecedence or 0, p.dn))
    out.extend(
        {
            "name": p.name or p.rdn_value,
            "min_length": p.psoMinLength,
            "lockout_threshold": p.psoLockoutThreshold,
            "complexity": p.psoComplexity,
            "reversible": p.psoReversible,
            "precedence": p.psoPrecedence,
        }
        for p in psos
    )
    return out


def _gpos(idx: ExportIndex) -> list[dict[str, Any]]:
    links = idx.gpo_link_map
    rows = [
        {
            "name": g.displayName or g.rdn_value,
            "dn": g.dn,
            "machine_disabled": bool((g.flags or 0) & GPO_FLAG_MACHINE_DISABLED),
            "user_disabled": bool((g.flags or 0) & GPO_FLAG_USER_DISABLED),
            "links": None if links is None else [
                {"dn": link.container_dn, "enforced": link.enforced, "disabled": link.disabled} for link in links.get(g.dn.lower(), [])
            ],
        }
        for g in idx.objects("groupPolicyContainer")
    ]
    return sorted(rows, key=lambda r: str(r["name"]).lower())


def _site_name(site: str | None) -> str:
    """Подсеть ссылается на сайт его DN — показывается имя сайта."""
    if not site:
        return ""
    first = site.split(",", 1)[0]
    return first.partition("=")[2] if "=" in first else site


def _subnets(idx: ExportIndex) -> list[dict[str, Any]]:
    rows = [{"name": s.name or s.rdn_value, "site": _site_name(s.site)} for s in idx.objects("subnet")]
    return sorted(rows, key=lambda r: r["name"])


def _clusters(idx: ExportIndex) -> dict[str, Any]:
    """Кластеры Windows по тем же правилам, что находки Clusters: роль — к кластеру по creatorSid
    его учётки; узлы к кластеру из AD не привязываются."""
    by_kind: dict[str, list[AdObject]] = {CLUSTER: [], ROLE: [], NODE: []}
    for c in idx.objects("computer"):
        if (kind := cluster_kind(c.spn)) is not None:
            by_kind[kind].append(c)

    def name(o: AdObject) -> str:
        return o.name or o.rdn_value

    def ordered(objs: list[AdObject]) -> list[AdObject]:
        return sorted(objs, key=lambda o: name(o).lower())

    cluster_dns = {c.dn for c in by_kind[CLUSTER]}
    roles_of: dict[str, list[AdObject]] = {}
    orphans = []
    for r in by_kind[ROLE]:
        owner = idx.by_sid.get(r.creatorSid or "")
        if owner is not None and owner.dn in cluster_dns:
            roles_of.setdefault(owner.dn, []).append(r)
        else:
            orphans.append(r)
    return {
        "clusters": [
            {
                "name": name(c), "dn": c.dn, "enabled": c.enabled,
                "roles": [{"name": name(r), "enabled": r.enabled} for r in ordered(roles_of.get(c.dn, []))],
                "roles_disabled": sum(not r.enabled for r in roles_of.get(c.dn, [])),
            }
            for c in ordered(by_kind[CLUSTER])
        ],
        "orphan_roles": [{"name": name(r), "enabled": r.enabled} for r in ordered(orphans)],
        "nodes": [{"name": name(n), "dns": n.dNSHostName or "", "os": n.operatingSystem or ""} for n in ordered(by_kind[NODE])],
    }


def build_summary(idx: ExportIndex, cfg: AdConfig) -> dict[str, Any]:
    users = idx.objects("user")
    computers = idx.objects("computer")
    enabled_users = [u for u in users if u.enabled]
    admins = admin_dns(idx, cfg)
    now = idx.export.collected_at

    def ages(attr: str) -> dict[str, list[dict[str, Any]]]:
        values = [(u.dn.lower() in admins, days_between(getattr(u, attr), now)) for u in enabled_users]
        return {"all": _buckets([v for _, v in values]), "admins": _buckets([v for admin, v in values if admin])}

    return {
        "version": SUMMARY_VERSION,
        "accounts": {
            "users": _counts(idx, users, cfg.user_inactivity_days, laps=False),
            "computers": _counts(idx, computers, cfg.computer_inactivity_days, laps=True),
        },
        "password_age": ages("pwdLastSet"),
        "last_logon": ages("lastLogonTimestamp"),
        "os": _os(idx, computers, cfg.computer_inactivity_days),
        "dcs": _dcs(idx),
        "groups": _groups(idx, cfg),
        "trusts": _trusts(idx),
        "password_policies": _password_policies(idx),
        "gpos": _gpos(idx),
        "subnets": _subnets(idx),
        "clusters": _clusters(idx),
    }
