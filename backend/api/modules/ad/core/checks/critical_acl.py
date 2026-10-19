"""Права на критичные объекты: корень домена, привилегированные группы и их участники, OU (BadSuccessor)."""
from __future__ import annotations

import uuid

from api.modules.ad.core import sd
from api.modules.ad.core.checks import principals
from api.modules.ad.core.checks.acl import _admin_sd_holder
from api.modules.ad.core.checks.adcs_rules import (
    CHECK_MEMBERS_NOTE,
    FULL_CONTROL,
    OWNER,
    Kind,
    _forest_rid,
    specific_rights,
    writers_details,
)
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import (
    CRITICAL_BUILTIN_RIDS,
    CRITICAL_GROUP_NAMES,
    CRITICAL_GROUP_RIDS,
    RID_KRBTGT,
    AdObject,
    ExportIndex,
)
from api.modules.ad.core.findings import Finding, finalize
from api.modules.ad.core.sd import Ace

#: Права, дающие полный контроль над доменом (в том числе выдачу себе DCSync).
ROOT_RIGHTS = sd.GENERIC_ALL | sd.WRITE_DACL | sd.WRITE_OWNER
#: SELF и CREATOR OWNER — подстановки, а не субъекты: права получает сам объект или его создатель.
_PLACEHOLDERS = ("S-1-5-10", "S-1-3-0")

GUID_MEMBER = "bf9679c0-0de6-11d0-a285-00aa003049e2"
GUID_RESET_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
DMSA_CLASS = "msDS-DelegatedManagedServiceAccount"
#: Классы, на потомков которых действует inherit-only ACE на OU, если в ней можно создать dMSA:
#: organizationalUnit и container (schemaIDGUID из справочника схемы AD).
GUID_CLASS_OU = "bf967aa5-0de6-11d0-a285-00aa003049e2"
GUID_CLASS_CONTAINER = "bf967a8b-0de6-11d0-a285-00aa003049e2"


def check_domain_root_acl(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    root = idx.root
    desc = idx.sd_of(root) if root is not None else None
    if root is None or desc is None:
        return []
    out = []
    for writer in principals.tier0_writers(idx, cfg, root, desc, ROOT_RIGHTS):
        sid, _, rights = writer
        if sid in _PLACEHOLDERS:
            continue
        severity, details = writers_details(idx, [writer], "Право менять права или владельца корня домена — путь к полному контролю над доменом", "Critical")
        f = Finding(
            check="DomainRootAcl", severity=severity, identity=idx.principal_name(sid), identity_sid=sid,
            target=root.dn, right=", ".join(rights), details=details,
        )
        out.append(finalize(f, cfg))
    return out


def critical_groups(idx: ExportIndex, cfg: AdConfig) -> list[AdObject]:
    """Критичные группы из выгрузки: по RID, DnsAdmins и privileged_groups по имени."""
    groups = [idx.group_by_rid(r) for r in CRITICAL_GROUP_RIDS]
    groups += [idx.by_sid.get(f"S-1-5-32-{r}") for r in CRITICAL_BUILTIN_RIDS]
    groups += [idx.group_by_name(n) for n in (*CRITICAL_GROUP_NAMES, *cfg.privileged_groups)]
    return list({g.dn.lower(): g for g in groups if g is not None}.values())


def critical_objects(idx: ExportIndex, cfg: AdConfig) -> list[AdObject]:
    """Критичные группы, их рекурсивные участники-пользователи и вложенные группы, учётки RID 500 и 502."""
    key = ("critical_objects", tuple(cfg.privileged_groups))
    if key not in idx.cache:
        seen: set[str] = set()
        out: list[AdObject] = []
        stack = list(reversed(critical_groups(idx, cfg)))
        while stack:
            obj = stack.pop()
            if obj.dn.lower() in seen or obj.cls not in ("user", "group"):
                continue
            seen.add(obj.dn.lower())
            out.append(obj)
            if obj.cls == "group":
                stack.extend(m for m in reversed([idx.get(dn) for dn in obj.member]) if m is not None)
        for r in (principals.RID_ADMINISTRATOR, RID_KRBTGT):
            acct = idx.by_sid.get(idx.domain_rid_sid(r))
            if acct is not None and acct.dn.lower() not in seen:
                seen.add(acct.dn.lower())
                out.append(acct)
        idx.cache[key] = out
    result: list[AdObject] = idx.cache[key]
    return result


def _is_critical_group(idx: ExportIndex, cfg: AdConfig, sid: str) -> bool:
    """Субъект — сама критичная группа (RID доменов своего леса, встроенная или по имени):
    право одной такой группы на другую — не путь повышения, а связь внутри tier 0."""
    key = ("critical_group_sids", tuple(cfg.privileged_groups))
    if key not in idx.cache:
        idx.cache[key] = frozenset(g.sid for g in critical_groups(idx, cfg) if g.sid)
    rid = _forest_rid(idx, sid)
    return (rid is not None and rid in CRITICAL_GROUP_RIDS) or sid in {f"S-1-5-32-{r}" for r in CRITICAL_BUILTIN_RIDS} or sid in idx.cache[key]


def _object_type(ace: Ace) -> str | None:
    return str(ace.object_type).lower() if ace.object_type else None


def _full_control(mask: int) -> bool:
    return specific_rights(mask) & FULL_CONTROL == FULL_CONTROL


def _ace_rights(obj: AdObject, ace: Ace, key_credential_link: str | None) -> list[str]:
    """Опасные права ACE на объекте — в порядке показа; полный доступ — одним GenericAll."""
    mask, ot = ace.mask, _object_type(ace)
    if _full_control(mask):
        return ["GenericAll"]
    is_group, is_user = obj.cls == "group", obj.cls == "user"
    checks = [
        ("GenericWrite", bool(mask & sd.GENERIC_WRITE)),
        ("WriteDacl", bool(mask & sd.WRITE_DACL)),
        ("WriteOwner", bool(mask & sd.WRITE_OWNER)),
        ("WriteProperty", bool(mask & sd.WRITE_PROPERTY) and ot is None),
        ("WriteMember", bool(mask & sd.WRITE_PROPERTY) and ot == GUID_MEMBER and is_group),
        ("AddSelf", bool(mask & sd.SELF_WRITE) and ot == GUID_MEMBER and is_group),
        # Shadow Credentials — вход по ключу за учётку; у группы входа нет.
        ("WriteKeyCredentialLink", bool(mask & sd.WRITE_PROPERTY) and key_credential_link is not None
         and ot == key_credential_link and obj.cls in ("user", "computer")),
        ("AllExtendedRights", bool(mask & sd.EXTENDED_RIGHT) and ot is None),
        ("ResetPassword", bool(mask & sd.EXTENDED_RIGHT) and ot == GUID_RESET_PASSWORD and is_user),
    ]
    return [name for name, hit in checks if hit]


_ORDER = ["GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "WriteProperty", "WriteMember", "AddSelf",
          "WriteKeyCredentialLink", "AllExtendedRights", "ResetPassword", OWNER]


def _effective_principals(idx: ExportIndex, sid: str) -> int:
    obj = idx.by_sid.get(sid)
    return len(idx.members_recursive(obj)) if obj is not None and obj.cls == "group" else 1


def _holder_aces(idx: ExportIndex) -> set[tuple[str, int, uuid.UUID | None]]:
    holder = _admin_sd_holder(idx)
    desc = idx.sd_of(holder) if holder is not None else None
    return {(a.sid, a.mask, a.object_type) for a in desc.dacl} if desc is not None else set()


def check_critical_object_acl(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    kcl = idx.schema_attribute("msDS-KeyCredentialLink")
    holder = _holder_aces(idx)
    out: list[Finding] = []
    for obj in critical_objects(idx, cfg):
        desc = idx.sd_of(obj)
        if desc is None:
            continue
        rights: dict[str, set[str]] = {}
        for ace in desc.dacl:
            if not ace.allow or ace.inherit_only or ace.sid in _PLACEHOLDERS:
                continue
            # SDProp копирует DACL AdminSDHolder на защищённые объекты: такие ACE — находки ShadowAdmins.
            if obj.adminCount == 1 and (ace.sid, ace.mask, ace.object_type) in holder:
                continue
            found = _ace_rights(obj, ace, kcl)
            if found:
                rights.setdefault(ace.sid, set()).update(found)
        if desc.owner and desc.owner not in _PLACEHOLDERS:
            rights.setdefault(desc.owner, set()).add(OWNER)
        for sid, names in rights.items():
            kind: Kind = principals.tier0_kind(idx, cfg, sid)
            if kind == "safe" or _is_critical_group(idx, cfg, sid):
                continue
            effective = _effective_principals(idx, sid)
            broad = kind == "broad" or effective > cfg.control_path_many
            text = "Право менять привилегированную группу или её участника — путь к правам этой группы"
            f = Finding(
                check="CriticalObjectAcl", severity="Critical" if broad else "High",
                identity=idx.principal_name(sid), identity_sid=sid, target=obj.dn,
                right=", ".join(sorted(names, key=_ORDER.index)),
                details={
                    "details": text if broad else f"{text}; {CHECK_MEMBERS_NOTE}",
                    "kind": "broad" if broad else kind, "effective_principals": effective, "object_class": obj.cls,
                },
            )
            out.append(finalize(f, cfg))
    return out


def check_bad_successor(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    dmsa = (idx.export.guids.schema_classes.get(DMSA_CLASS) or "").lower()
    if not dmsa:
        return []
    # Атака через dMSA работает только при контроллере Windows Server 2025.
    dc_2025 = any("2025" in (d.operatingSystem or "") for d in idx.dcs)
    out: list[Finding] = []
    for ou in idx.objects("organizationalUnit"):
        desc = idx.sd_of(ou)
        if desc is None:
            continue
        rights: dict[str, set[str]] = {}
        for ace in desc.dacl:
            if not ace.allow or ace.inherited or ace.sid in _PLACEHOLDERS:
                continue
            # Inherit-only ACE даёт права на потомках: опасна, только если доходит до OU или контейнеров.
            inherited_type = str(ace.inherited_object_type).lower() if ace.inherited_object_type else None
            if ace.inherit_only and inherited_type not in (None, GUID_CLASS_OU, GUID_CLASS_CONTAINER):
                continue
            ot = _object_type(ace)
            if _full_control(ace.mask):
                rights.setdefault(ace.sid, set()).add("GenericAll")
            elif ace.mask & sd.CREATE_CHILD and ot in (None, dmsa):
                rights.setdefault(ace.sid, set()).add("CreateChild")
        for sid, names in rights.items():
            kind = principals.tier0_kind(idx, cfg, sid)
            if kind == "safe":
                continue
            severity = ("High" if kind == "broad" else "Medium") if dc_2025 else "Low"
            text = "Право создавать объекты в OU позволяет создать dMSA и назначить ей предшественником любую учётку, включая администратора домена"
            f = Finding(
                check="BadSuccessor", severity=severity, identity=idx.principal_name(sid), identity_sid=sid,
                target=ou.dn, right=", ".join(n for n in ("GenericAll", "CreateChild") if n in names),
                details={"details": text if kind == "broad" else f"{text}; {CHECK_MEMBERS_NOTE}", "kind": kind, "dc_2025": dc_2025},
            )
            out.append(finalize(f, cfg))
    return out
