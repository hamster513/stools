"""Проверки по дескрипторам безопасности: DCSync, AdminSDHolder,
msDS-KeyCredentialLink, OU/компьютеры, GPO."""
from __future__ import annotations

import uuid

from api.modules.ad.core import sd
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import AdObject, ExportIndex
from api.modules.ad.core.findings import Finding, finalize, is_allowlisted

DCSYNC_RIGHTS: list[tuple[str, str, str]] = [
    ("DS-Replication-Get-Changes", "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "High"),
    ("DS-Replication-Get-Changes-All", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "Critical"),
    ("DS-Replication-Get-Changes-In-Filtered-Set", "89e95b76-444d-4c62-991a-0facbeda640c", "High"),
]

#: Apply Group Policy — расширенное право, которое есть у всех, кому
#: политика применяется; само по себе оно не даёт менять GPO.
APPLY_GROUP_POLICY = uuid.UUID("edacfd8f-ffb3-11d1-b41d-00a0c968f939")

WRITE_LIKE = sd.GENERIC_ALL | sd.GENERIC_WRITE | sd.WRITE_DACL | sd.WRITE_OWNER | sd.WRITE_PROPERTY | sd.EXTENDED_RIGHT


def _ace_identity(idx: ExportIndex, ace: sd.Ace) -> tuple[str, str]:
    return idx.principal_name(ace.sid), ace.sid


def _guid_of(idx: ExportIndex, right_name: str, default: str) -> uuid.UUID:
    return uuid.UUID(idx.extended_right(right_name) or default)


def check_dcsync(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    root = idx.root
    desc = idx.sd_of(root) if root else None
    if root is None or desc is None:
        return []
    dangerous = {_guid_of(idx, name, guid): (name, severity) for name, guid, severity in DCSYNC_RIGHTS}
    out: list[Finding] = []
    for ace in desc.dacl:
        if not ace.has(sd.EXTENDED_RIGHT) or ace.object_type is None or ace.object_type not in dangerous:
            continue
        name, severity = dangerous[ace.object_type]
        identity, sid_ = _ace_identity(idx, ace)
        out.append(
            finalize(
                Finding(
                    check="DCSync",
                    severity=severity,
                    identity=identity,
                    identity_sid=sid_,
                    target=root.dn,
                    right=name,
                    details={
                        "access_control_type": "Allow" if ace.allow else "Deny",
                        "is_inherited": ace.inherited,
                        "naming_context": root.dn,
                        "right_guid": str(ace.object_type),
                    },
                ),
                cfg,
            )
        )
    return out


def _admin_sd_holder(idx: ExportIndex) -> AdObject | None:
    return idx.get(f"CN=AdminSDHolder,CN=System,{idx.export.domain.dn}")


def check_shadow_admins(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    holder = _admin_sd_holder(idx)
    desc = idx.sd_of(holder) if holder else None
    if holder is None or desc is None:
        return []
    out: list[Finding] = []
    for ace in desc.dacl:
        if not ace.allow or not (ace.mask & WRITE_LIKE):
            continue
        identity, sid_ = _ace_identity(idx, ace)
        out.append(
            finalize(
                Finding(
                    check="ShadowAdmins",
                    severity="High",
                    identity=identity,
                    identity_sid=sid_,
                    target=holder.dn,
                    right=", ".join(ace.rights),
                    details={"is_inherited": ace.inherited, "object_type": str(ace.object_type) if ace.object_type else ""},
                ),
                cfg,
            )
        )
    return out


def check_key_credential_link_acl(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    attr = idx.schema_attribute("msDS-KeyCredentialLink")
    if not attr:
        return []
    attr_guid = uuid.UUID(attr)
    out: list[Finding] = []
    targets = [t for t in (idx.root, _admin_sd_holder(idx)) if t is not None]
    for target in targets:
        desc = idx.sd_of(target)
        if desc is None:
            continue
        for ace in desc.dacl:
            if not ace.allow:
                continue
            danger = ace.has(sd.GENERIC_ALL) or ace.has(sd.WRITE_DACL) or ace.has(sd.WRITE_OWNER)
            if ace.has(sd.WRITE_PROPERTY) and ace.object_type == attr_guid:
                danger = True
            identity, sid_ = _ace_identity(idx, ace)
            # Как в прототипе: allowlist здесь не понижает, а исключает —
            # у администраторов это право по определению.
            if not danger or is_allowlisted(identity, cfg):
                continue
            out.append(
                finalize(
                    Finding(
                        check="KeyCredentialLinkACL",
                        severity="High",
                        identity=identity,
                        identity_sid=sid_,
                        target=target.dn,
                        right=", ".join(ace.rights),
                        details={"naming_context": target.dn, "attribute": "msDS-KeyCredentialLink"},
                    ),
                    cfg,
                    allowlist=False,
                )
            )
    return out


def _sensitive_targets(idx: ExportIndex, cfg: AdConfig) -> list[AdObject]:
    scope = (cfg.sensitive_acl_scope or "Both").upper()
    classes = {"OUS": ["organizationalUnit"], "COMPUTERS": ["computer"]}.get(scope, ["organizationalUnit", "computer"])
    objs = [o for c in classes for o in idx.objects(c)]
    base = (cfg.sensitive_acl_search_base or "").lower()
    if base:
        objs = [o for o in objs if o.dn.lower().endswith(base)]
    excludes = [e.lower() for e in cfg.sensitive_acl_exclude_ous if e.strip()]
    if excludes:
        objs = [o for o in objs if not any(o.dn.lower().endswith(e) for e in excludes)]
    if cfg.sensitive_acl_max_objects > 0:
        objs = objs[: cfg.sensitive_acl_max_objects]
    return objs


def check_sensitive_acl(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out: list[Finding] = []
    for obj in _sensitive_targets(idx, cfg):
        desc = idx.sd_of(obj)
        if desc is None:
            continue
        for ace in desc.dacl:
            if not ace.allow or not (ace.mask & WRITE_LIKE):
                continue
            identity, sid_ = _ace_identity(idx, ace)
            if is_allowlisted(identity, cfg):
                continue
            out.append(
                finalize(
                    Finding(
                        check="SensitiveAcl",
                        severity="High",
                        identity=identity,
                        identity_sid=sid_,
                        target=obj.dn,
                        right=", ".join(ace.rights),
                        details={"object_type": obj.cls, "is_inherited": ace.inherited},
                    ),
                    cfg,
                    allowlist=False,
                )
            )
    return out


GPO_RISKY = WRITE_LIKE | sd.CREATE_CHILD | sd.DELETE_CHILD


def check_gpo_permissions(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out: list[Finding] = []
    for gpo in idx.objects("groupPolicyContainer"):
        desc = idx.sd_of(gpo)
        if desc is None:
            continue
        for ace in desc.dacl:
            mask = ace.mask
            # Apply Group Policy — не право на изменение; прототип его
            # считал, и каждая политика давала находку на Authenticated Users.
            if ace.object_type == APPLY_GROUP_POLICY and (mask & ~sd.EXTENDED_RIGHT & GPO_RISKY) == 0:
                continue
            if not (mask & GPO_RISKY):
                continue
            identity, sid_ = _ace_identity(idx, ace)
            out.append(
                finalize(
                    Finding(
                        check="GpoPermissions",
                        severity="High",
                        identity=identity,
                        identity_sid=sid_,
                        target=gpo.displayName or gpo.dn,
                        right=", ".join(ace.rights),
                        details={
                            "gpo_dn": gpo.dn,
                            "gpo_path": gpo.gpcFileSysPath or "",
                            "access_control_type": "Allow" if ace.allow else "Deny",
                            "is_inherited": ace.inherited,
                        },
                    ),
                    cfg,
                )
            )
    return out
