"""Проверки по дескрипторам безопасности: DCSync, AdminSDHolder,
msDS-KeyCredentialLink, OU/компьютеры, GPO."""
from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

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
    if cfg.sensitive_acl_collapse:
        return _sensitive_acl_collapsed(idx, cfg)
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


#: Как AD разворачивает generic-права в конкретные (ActiveDirectoryRights .NET):
#: на источнике может стоять GenericAll, а у потомка — те же права битами.
GENERIC_MAP = {sd.GENERIC_ALL: 0xF01FF, sd.GENERIC_WRITE: 0x20028, sd.GENERIC_READ: 0x20094, sd.GENERIC_EXECUTE: 0x20004}
SAMPLES = 20
#: Флаги ACE: наследуется потомками; только детьми (не глубже).
CONTAINER_INHERIT = 0x02
NO_PROPAGATE = 0x04

AceKey = tuple[int, int, str, uuid.UUID | None, uuid.UUID | None]


def _ace_key(ace: sd.Ace) -> AceKey:
    """Одна и та же ACE на источнике и у потомка; флаги наследования не сравниваются."""
    mask = ace.mask
    for bit, specific in GENERIC_MAP.items():
        if mask & bit:
            mask = (mask & ~bit) | specific
    return (ace.type, mask, ace.sid, ace.object_type, ace.inherited_object_type)


def _split_dn(dn: str) -> list[str]:
    """RDN по запятым, кроме экранированных (`CN=Smith\\, John`)."""
    parts: list[str] = []
    cur: list[str] = []
    escaped = False
    for ch in dn:
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ",":
            parts.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    parts.append("".join(cur).strip())
    return parts


def _parent_dn(dn: str) -> str | None:
    rdns = _split_dn(dn)
    return ",".join(rdns[1:]) if len(rdns) > 1 else None


def _common_parent(dns: list[str]) -> str:
    """Ближайший общий предок (строго выше каждого DN); пусто, если общего нет."""
    chains = [_split_dn(dn)[1:] for dn in dns]
    common: list[str] = []
    for i in range(1, min(len(c) for c in chains) + 1):
        if len({c[-i].lower() for c in chains}) != 1:
            break
        common.insert(0, chains[0][-i])
    return ",".join(common)


def _nearest_known(idx: ExportIndex, dn: str) -> AdObject | None:
    cur: str | None = dn
    while cur:
        obj = idx.get(cur)
        if obj is not None:
            return obj
        cur = _parent_dn(cur)
    return None


@dataclass
class _Group:
    """Будущая свёрнутая находка: цель, кто и какое право, кого затрагивает."""

    target: str
    cls: str
    sid: str
    right: str
    key_extra: str = ""
    explicit: bool = False
    in_scope: bool = False
    #: dn.lower() → объект: у потомка одна и та же ACE бывает дважды (действующая
    #: и inherit-only копия generic-права, либо от двух предков) — считаем объект один раз.
    inherited: dict[str, AdObject] = field(default_factory=dict)
    explicit_on: list[AdObject] = field(default_factory=list)


def _counts(objs: Iterable[AdObject]) -> dict[str, int]:
    return dict(sorted(Counter(o.cls for o in objs).items()))


def _samples(objs: Iterable[AdObject]) -> list[str]:
    return sorted((o.dn for o in objs), key=str.lower)[:SAMPLES]


def _sensitive_acl_collapsed(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    """Унаследованная ACE — одна находка на источнике (ближайший предок, где она
    явная); одинаковая явная пара «кто + право» больше чем на пороге объектов —
    одна находка на их общем предке."""
    targets = _sensitive_targets(idx, cfg)
    in_scope = {o.dn.lower() for o in targets}
    Aces = dict[AceKey, sd.Ace]
    explicit_cache: dict[str, tuple[Aces, Aces]] = {}
    source_cache: dict[tuple[str, AceKey], tuple[AdObject, sd.Ace] | None] = {}

    def explicit_of(dn: str) -> tuple[AdObject | None, Aces, Aces]:
        """Явные ACE, которые могли дойти до потомков: всех (CI) и только до детей (CI+NP)."""
        obj = idx.get(dn)
        key = dn.lower()
        if key not in explicit_cache:
            desc = idx.sd_of(obj) if obj else None
            deep: Aces = {}
            children: Aces = {}
            for a in desc.dacl if desc else []:
                if not a.inherited and a.flags & CONTAINER_INHERIT:
                    (children if a.flags & NO_PROPAGATE else deep).setdefault(_ace_key(a), a)
            explicit_cache[key] = (deep, children)
        return obj, *explicit_cache[key]

    def source_of(parent: str | None, key: AceKey) -> tuple[AdObject, sd.Ace] | None:
        """Ближайший предок, откуда ACE могла прийти; NP-источник — только родитель."""
        if parent is None:
            return None
        obj, deep, children = explicit_of(parent)
        if obj is not None and key not in deep and key in children:
            return obj, children[key]
        return deep_source_of(parent, key)

    def deep_source_of(dn: str | None, key: AceKey) -> tuple[AdObject, sd.Ace] | None:
        path: list[tuple[str, AceKey]] = []
        found: tuple[AdObject, sd.Ace] | None = None
        while dn is not None:
            ck = (dn.lower(), key)
            if ck in source_cache:
                found = source_cache[ck]
                break
            path.append(ck)
            obj, deep, _ = explicit_of(dn)
            if obj is not None and key in deep:
                found = (obj, deep[key])
                break
            dn = _parent_dn(dn)
        for ck in path:
            source_cache[ck] = found
        return found

    groups: dict[tuple[str, str, str], _Group] = {}
    unknown: dict[tuple[str, str], dict[str, AdObject]] = {}
    pairs: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    for obj in targets:
        desc = idx.sd_of(obj)
        if desc is None:
            continue
        parent = _parent_dn(obj.dn)
        dn_key = obj.dn.lower()
        for ace in desc.dacl:
            if not ace.allow or not (ace.mask & WRITE_LIKE):
                continue
            if is_allowlisted(idx.principal_name(ace.sid), cfg):
                continue
            if not ace.inherited:
                right = ", ".join(ace.rights)
                gk = (dn_key, ace.sid, right)
                g = groups.setdefault(gk, _Group(obj.dn, obj.cls, ace.sid, right, in_scope=True))
                if not g.explicit:
                    g.explicit = True
                    pairs.setdefault((ace.sid, right), []).append(gk)
                continue
            found = source_of(parent, _ace_key(ace))
            if found is None:
                unknown.setdefault((ace.sid, ", ".join(ace.rights)), {})[dn_key] = obj
                continue
            src, src_ace = found
            right = ", ".join(src_ace.rights)
            g = groups.setdefault(
                (src.dn.lower(), ace.sid, right),
                _Group(src.dn, src.cls, ace.sid, right, in_scope=src.dn.lower() in in_scope),
            )
            g.inherited[dn_key] = obj

    # Массовые явные права: пара стоит явно больше чем на пороге объектов.
    mass: list[_Group] = []
    for (sid_, right), keys in pairs.items():
        if len(keys) <= cfg.sensitive_acl_collapse_threshold:
            continue
        members = [groups.pop(k) for k in keys]
        target = _common_parent([m.target for m in members]) or idx.export.domain.dn
        anchor = idx.get(target)
        mg = _Group(target, anchor.cls if anchor else "", sid_, right, key_extra="mass", in_scope=target.lower() in in_scope)
        for m in members:
            obj_ = idx.get(m.target)
            if obj_ is not None:
                mg.explicit_on.append(obj_)
            mg.inherited.update(m.inherited)
        mass.append(mg)

    for (sid_, right), objs in unknown.items():
        common = _common_parent([o.dn for o in objs.values()])
        anchor = _nearest_known(idx, common) if common else None
        target = anchor.dn if anchor else (common or idx.export.domain.dn)
        g = _Group(target, anchor.cls if anchor else "", sid_, right, key_extra="unknown", in_scope=False)
        g.inherited = objs
        mass.append(g)

    out: list[Finding] = []
    for g in [*groups.values(), *mass]:
        details: dict[str, object] = {"object_type": g.cls, "is_inherited": False}
        if g.inherited or g.key_extra:
            details["inherited_to"] = _counts(g.inherited.values())
            details["source_in_scope"] = g.in_scope
            details["samples"] = _samples(g.explicit_on or g.inherited.values())
        if g.key_extra == "mass":
            details["explicit_on"] = _counts(g.explicit_on)
        if g.key_extra == "unknown":
            details["source"] = "unknown"
        out.append(
            finalize(
                Finding(
                    check="SensitiveAcl",
                    severity="High",
                    identity=idx.principal_name(g.sid),
                    identity_sid=g.sid,
                    target=g.target,
                    right=g.right,
                    details=details,
                    key_extra=g.key_extra,
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
