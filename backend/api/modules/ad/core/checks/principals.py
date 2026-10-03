"""Кто есть кто для проверок гигиены: админы, защищённые объекты, безопасные субъекты ACL.

Определения — спека гигиены AD, §0. Списки считаются один раз на выгрузку
и лежат в `ExportIndex.cache`.
"""
from __future__ import annotations

from api.modules.ad.core.checks.adcs_rules import Kind, Writer, requester_kind, unsafe_writers
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import RID_KRBTGT, RID_PROTECTED_USERS, AdObject, ExportIndex
from api.modules.ad.core.sd import SecurityDescriptor

RID_ADMINISTRATOR = 500
#: Группы под AdminSDHolder: Domain Admins, Domain Controllers, Schema Admins, Enterprise Admins,
#: Read-only DCs, Key Admins, Enterprise Key Admins; встроенные Administrators, Account, Server,
#: Print, Backup Operators, Replicator.
PROTECTED_GROUP_RIDS = (512, 516, 518, 519, 521, 526, 527, 544, 548, 549, 550, 551, 552)


def admin_dns(idx: ExportIndex, cfg: AdConfig) -> frozenset[str]:
    """dn.lower() включённых пользователей — рекурсивных членов групп admin_rids — и учётки RID 500, если она включена."""
    key = ("admin_dns", tuple(cfg.admin_rids))
    if key not in idx.cache:
        out: set[str] = set()
        for r in cfg.admin_rids:
            g = idx.group_for_rid(r)
            if g is not None:
                out.update(m.dn.lower() for m in idx.members_recursive(g) if m.cls == "user" and m.enabled)
        builtin = idx.by_sid.get(idx.domain_rid_sid(RID_ADMINISTRATOR))
        if builtin is not None and builtin.enabled:
            out.add(builtin.dn.lower())
        idx.cache[key] = frozenset(out)
    result: frozenset[str] = idx.cache[key]
    return result


def is_admin(idx: ExportIndex, cfg: AdConfig, obj: AdObject) -> bool:
    return obj.dn.lower() in admin_dns(idx, cfg)


def protected_dns(idx: ExportIndex) -> frozenset[str]:
    """dn.lower() защищённых групп, вложенных в них групп, их рекурсивных членов, учёток RID 500 и 502
    и контроллеров домена: в Domain Controllers они входят через primaryGroupID, которого в выгрузке нет."""
    key = "protected_dns"
    if key not in idx.cache:
        out: set[str] = set()
        stack = [g for g in map(idx.group_for_rid, PROTECTED_GROUP_RIDS) if g is not None]
        while stack:
            obj = stack.pop()
            if obj.dn.lower() in out:
                continue
            out.add(obj.dn.lower())
            if obj.cls == "group":
                stack.extend(m for m in map(idx.get, obj.member) if m is not None)
        for r in (RID_ADMINISTRATOR, RID_KRBTGT):
            acct = idx.by_sid.get(idx.domain_rid_sid(r))
            if acct is not None:
                out.add(acct.dn.lower())
        out.update(d.dn.lower() for d in idx.dcs)
        idx.cache[key] = frozenset(out)
    result: frozenset[str] = idx.cache[key]
    return result


def protected_users_dns(idx: ExportIndex) -> frozenset[str]:
    """dn.lower() рекурсивных членов Protected Users."""
    group = idx.group_by_rid(RID_PROTECTED_USERS)
    return frozenset(m.dn.lower() for m in idx.members_recursive(group)) if group is not None else frozenset()


def tier0_kind(idx: ExportIndex, cfg: AdConfig, sid: str) -> Kind:
    """Как у AD CS, но безопасные RID — tier0_safe_rids (без Cert Publishers), а имена
    администраторов ЦС (adcs_safe_principals) безопасными не считаются."""
    return requester_kind(idx, cfg, sid, safe_rids=cfg.tier0_safe_rids, safe_principals=())


def tier0_writers(idx: ExportIndex, cfg: AdConfig, obj: AdObject, desc: SecurityDescriptor, dangerous: int) -> list[Writer]:
    """Небезопасные субъекты с правами из dangerous, безопасные — как у tier0_kind.

    dangerous перечисляет конкретные права: общие биты (GENERIC_ALL, GENERIC_WRITE) из
    маски отбрасываются, и маска из одного GENERIC_ALL не найдёт никого."""
    return unsafe_writers(idx, cfg, obj, desc, safe_rids=cfg.tier0_safe_rids, safe_principals=(), dangerous=dangerous)


def worst(severity: str, admin: bool, admin_severity: str) -> str:
    """Серьёзность находки об учётке: для админа — своя, обычно выше."""
    return admin_severity if admin else severity
