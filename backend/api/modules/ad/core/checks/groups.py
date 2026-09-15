"""Привилегированные группы и покрытие Protected Users."""
from __future__ import annotations

from api.modules.ad.core.checks.common import date_str
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import RID_PROTECTED_USERS, AdObject, ExportIndex
from api.modules.ad.core.findings import Finding, finalize


def privileged_groups(idx: ExportIndex, cfg: AdConfig) -> list[AdObject]:
    """По RID (не зависят от языка домена), затем по именам из настроек."""
    seen: dict[str, AdObject] = {}
    for rid in cfg.privileged_rids:
        g = idx.group_by_rid(rid) if rid >= 1000 or rid in (512, 518, 519) else idx.by_sid.get(f"S-1-5-32-{rid}")
        if g is not None:
            seen[g.dn.lower()] = g
    for name in cfg.privileged_groups:
        g = idx.group_by_name(name)
        if g is not None:
            seen[g.dn.lower()] = g
    return list(seen.values())


def check_privileged_groups(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out: list[Finding] = []
    for grp in privileged_groups(idx, cfg):
        for m in idx.members_recursive(grp):
            identity = idx.principal_name(m.sid) or m.label
            out.append(
                finalize(
                    Finding(
                        check="PrivilegedGroups",
                        severity="Medium",
                        identity=identity,
                        identity_sid=m.sid or "",
                        target=grp.label,
                        details={
                            "group": grp.label,
                            "member": m.label,
                            "member_type": m.cls,
                            "enabled": m.enabled,
                            "last_logon": date_str(m.lastLogonTimestamp),
                            "pwd_last_set": date_str(m.pwdLastSet),
                        },
                    ),
                    cfg,
                )
            )
    return out


def check_protected_users_coverage(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    protected = idx.group_by_rid(RID_PROTECTED_USERS) or idx.group_by_name("Protected Users")
    if protected is None:
        return []
    covered = {m.dn.lower() for m in idx.members_recursive(protected)}
    out: list[Finding] = []
    for grp in privileged_groups(idx, cfg):
        for m in idx.members_recursive(grp):
            if m.cls != "user" or m.dn.lower() in covered:
                continue
            out.append(
                finalize(
                    Finding(
                        check="ProtectedUsersCoverage",
                        severity="Medium",
                        identity=idx.principal_name(m.sid) or m.label,
                        identity_sid=m.sid or "",
                        target=grp.label,
                        details={"group": grp.label, "details": "Привилегированный пользователь вне Protected Users"},
                    ),
                    cfg,
                )
            )
    return out
