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

#: 2 — сводка хранит параметры, с которыми построена (`params`).
SUMMARY_VERSION = 2
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


#: Числа блока «Учётные записи». Числа сводки ниже — длины списков учёток из `*_sets`:
#: по тем же спискам строится состав ячеек (summary_cells), и число с составом не расходятся.
ACCOUNT_KEYS = (
    "total", "enabled", "disabled", "active", "inactive", "pwd_never_expires", "pwd_not_required",
    "no_preauth", "sid_history", "delegation", "laps",
)
GROUP_FIELDS = ("members", "enabled", "inactive", "pwd_never_expires", "delegable", "protected_users")
OS_FIELDS = ("total", "enabled", "active")


def account_sets(idx: ExportIndex, objs: list[AdObject], days: int, laps: bool) -> dict[str, list[AdObject]]:
    """Учётки за числами блока «Учётные записи». Без `laps` ключа laps нет (в сводке — 0)."""
    enabled = [o for o in objs if o.enabled]

    def flag(mask: int) -> list[AdObject]:
        return [o for o in enabled if (o.uac or 0) & mask]

    out = {
        "total": objs,
        "enabled": enabled,
        "disabled": [o for o in objs if not o.enabled],
        "active": [o for o in enabled if _active(idx, o, days)],
        "inactive": [o for o in enabled if not _active(idx, o, days)],
        "pwd_never_expires": flag(UAC_DONT_EXPIRE_PASSWORD),
        "pwd_not_required": flag(UAC_PASSWD_NOTREQD),
        "no_preauth": flag(UAC_DONT_REQ_PREAUTH),
        "sid_history": [o for o in enabled if o.sIDHistory],
        "delegation": [o for o in enabled if _delegation(o)],
    }
    if laps:
        out["laps"] = [o for o in enabled if o.lapsExpiry is not None or o.lapsNewExpiry is not None]
    return out


def _counts(sets: dict[str, list[AdObject]]) -> dict[str, int]:
    return {key: len(sets.get(key, ())) for key in ACCOUNT_KEYS}


def bucket_of(age: int | None) -> int:
    """Номер корзины. Неизвестный возраст (не входил, пароль не задан) — в последнюю: сумма равна числу учёток."""
    if age is None:
        return len(AGE_BOUNDS)
    return next((i for i, le in enumerate(AGE_BOUNDS) if age <= le), len(AGE_BOUNDS))


def age_sets(idx: ExportIndex, cfg: AdConfig, attr: str) -> dict[str, list[list[AdObject]]]:
    """Включённые пользователи по корзинам возраста `attr`, все и админы: корзины по AGE_BOUNDS и последняя «старше»."""
    admins = admin_dns(idx, cfg)
    now = idx.export.collected_at
    out: dict[str, list[list[AdObject]]] = {scope: [[] for _ in range(len(AGE_BOUNDS) + 1)] for scope in ("all", "admins")}
    for u in idx.objects("user"):
        if not u.enabled:
            continue
        pos = bucket_of(days_between(getattr(u, attr), now))
        out["all"][pos].append(u)
        if u.dn.lower() in admins:
            out["admins"][pos].append(u)
    return out


def _buckets(bins: list[list[AdObject]]) -> list[dict[str, Any]]:
    return [{"le": le, "n": len(b)} for le, b in zip([*AGE_BOUNDS, None], bins, strict=True)]


def os_sets(idx: ExportIndex, computers: list[AdObject], days: int) -> dict[tuple[str, str], dict[str, list[AdObject]]]:
    """Компьютеры по паре (имя ОС, сборка): всего, включённые, активные."""
    rows: dict[tuple[str, str], dict[str, list[AdObject]]] = {}
    for c in computers:
        row = rows.setdefault((c.operatingSystem or "", _build(c.operatingSystemVersion)), {f: [] for f in OS_FIELDS})
        row["total"].append(c)
        if c.enabled:
            row["enabled"].append(c)
        if _active(idx, c, days):
            row["active"].append(c)
    return rows


def _os(sets: dict[tuple[str, str], dict[str, list[AdObject]]]) -> list[dict[str, Any]]:
    rows = [{"name": name, "build": build, **{f: len(row[f]) for f in OS_FIELDS}} for (name, build), row in sets.items()]
    return sorted(rows, key=lambda r: (-r["total"], r["name"], r["build"]))


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


def group_name(g: AdObject) -> str:
    return g.sam or g.name or g.rdn_value


def group_sets(idx: ExportIndex, cfg: AdConfig) -> list[tuple[AdObject, dict[str, list[AdObject]]]]:
    """Привилегированные группы и учётки за числами их строки: «участники» — все рекурсивные
    члены (и компьютеры), остальные столбцы — среди включённых пользователей."""
    protected = protected_users_dns(idx)
    out = []
    for g in privileged_groups(idx, cfg):
        members = idx.members_recursive(g)
        users = [m for m in members if m.cls == "user" and m.enabled]
        out.append((g, {
            "members": members,
            "enabled": users,
            "inactive": [u for u in users if not _active(idx, u, cfg.user_inactivity_days)],
            "pwd_never_expires": [u for u in users if (u.uac or 0) & UAC_DONT_EXPIRE_PASSWORD],
            "delegable": [u for u in users if not (u.uac or 0) & UAC_NOT_DELEGATED],
            "protected_users": [u for u in users if u.dn.lower() in protected],
        }))
    return out


def _groups(sets: list[tuple[AdObject, dict[str, list[AdObject]]]]) -> list[dict[str, Any]]:
    return [{"name": group_name(g), "sid": g.sid or "", **{f: len(row[f]) for f in GROUP_FIELDS}} for g, row in sets]


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
    """`params` — настройки, с которыми считалась сводка: по ним же считается состав её ячеек."""
    computers = idx.objects("computer")

    def ages(attr: str) -> dict[str, list[dict[str, Any]]]:
        return {scope: _buckets(bins) for scope, bins in age_sets(idx, cfg, attr).items()}

    return {
        "version": SUMMARY_VERSION,
        "params": cfg.model_dump(mode="json"),
        "accounts": {
            "users": _counts(account_sets(idx, idx.objects("user"), cfg.user_inactivity_days, laps=False)),
            "computers": _counts(account_sets(idx, computers, cfg.computer_inactivity_days, laps=True)),
        },
        "password_age": ages("pwdLastSet"),
        "last_logon": ages("lastLogonTimestamp"),
        "os": _os(os_sets(idx, computers, cfg.computer_inactivity_days)),
        "dcs": _dcs(idx),
        "groups": _groups(group_sets(idx, cfg)),
        "trusts": _trusts(idx),
        "password_policies": _password_policies(idx),
        "gpos": _gpos(idx),
        "subnets": _subnets(idx),
        "clusters": _clusters(idx),
    }
