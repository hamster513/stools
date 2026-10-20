"""Политика репликации паролей на RODC (msDS-RevealOnDemandGroup, -NeverRevealGroup, -RevealedUsers) и учётки krbtgt_NNNNN."""
from __future__ import annotations

from api.modules.ad.core.checks import principals
from api.modules.ad.core.checks.groups import privileged_groups
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import (
    RID_KRBTGT,
    UAC_PARTIAL_SECRETS_ACCOUNT,
    AdObject,
    ExportIndex,
)
from api.modules.ad.core.findings import Finding, finalize

RID_ALLOWED_RODC = 571
RID_DENIED_RODC = 572
#: Кто должен быть в Denied RODC Password Replication Group: Domain Admins, Schema Admins, Enterprise Admins, Domain Controllers, krbtgt.
DENIED_REQUIRED_RIDS = (512, 518, 519, 516, RID_KRBTGT)
#: Виды, которые строятся по атрибутам RODC сборщика 1.1/2.1: в старой выгрузке их нет вовсе.
RODC_ATTRIBUTE_KINDS = frozenset({"never_reveal_missing", "admin_revealed", "reveal_privileged", "krbtgt_orphan"})


def is_rodc(obj: AdObject) -> bool:
    return bool((obj.uac or 0) & UAC_PARTIAL_SECRETS_ACCOUNT)


def is_rodc_krbtgt(obj: AdObject) -> bool:
    return (obj.sam or "").lower().startswith("krbtgt_")


def _finding(cfg: AdConfig, kind: str, target: str, text: str, who: tuple[str, str] = ("", ""), **extra: object) -> Finding:
    f = Finding(
        check="RodcPasswordReplication", severity="Medium", identity=who[0], identity_sid=who[1], target=target, key_extra=kind,
        details={"details": text, "kind": kind, **extra},
    )
    return finalize(f, cfg, allowlist=False)


def _who(idx: ExportIndex, obj: AdObject) -> tuple[str, str]:
    return idx.principal_name(obj.sid) or obj.label, obj.sid or ""


def _reachable(idx: ExportIndex, group: AdObject) -> set[str]:
    """SID всех прямых и вложенных членов группы, включая сами вложенные группы."""
    seen: set[str] = set()
    sids: set[str] = set()
    stack = [group]
    while stack:
        g = stack.pop()
        for dn in g.member:
            m = idx.get(dn)
            if m is None or m.dn.lower() in seen:
                continue
            seen.add(m.dn.lower())
            if m.sid:
                sids.add(m.sid)
            if m.cls == "group":
                stack.append(m)
    return sids


def _rodc_findings(idx: ExportIndex, cfg: AdConfig, rodc: AdObject) -> list[Finding]:
    out = []
    admins = principals.admin_dns(idx, cfg)
    privileged = {g.dn.lower() for g in privileged_groups(idx, cfg)}
    for dn in rodc.revealOnDemand:
        obj = idx.get(dn)
        if obj is not None and (dn.lower() in privileged or dn.lower() in admins):
            out.append(_finding(cfg, "reveal_privileged", rodc.dn, f"RODC {rodc.label}: пароль привилегированного субъекта {obj.label} разрешено кэшировать", _who(idx, obj)))
    denied = idx.group_by_rid(RID_DENIED_RODC)
    if denied is not None and denied.dn.lower() not in {d.lower() for d in rodc.neverReveal}:
        out.append(_finding(cfg, "never_reveal_missing", rodc.dn, f"RODC {rodc.label}: Denied RODC Password Replication Group нет в списке запрета кэширования"))
    for dn in rodc.revealedUsers:
        obj = idx.get(dn)
        if obj is not None and dn.lower() in admins:
            out.append(_finding(cfg, "admin_revealed", rodc.dn, f"RODC {rodc.label}: пароль администратора {obj.label} уже закэширован", _who(idx, obj)))
    return out


def check_rodc_password_replication(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    rodcs = [c for c in idx.objects("computer") if is_rodc(c)]
    out = [f for r in rodcs for f in _rodc_findings(idx, cfg, r)]
    # Учётка krbtgt_NNNNN остаётся после удаления RODC: её ключи — ключи бывшего контроллера.
    linked = {(r.krbTgtLink or "").lower() for r in rodcs}
    for u in idx.objects("user"):
        if is_rodc_krbtgt(u) and u.dn.lower() not in linked:
            out.append(_finding(cfg, "krbtgt_orphan", u.dn, f"Учётка {u.label} не связана ни с одним RODC", _who(idx, u)))
    accounts = idx.objects("user") + idx.objects("computer")
    if accounts and all(o.primaryGroupID is None for o in accounts):
        # Старый сборщик: пустые списки RODC и krbtgtLink — «не собрано», пробел покрытия даёт coverage.
        out = [f for f in out if f.key_extra not in RODC_ATTRIBUTE_KINDS]
    if not rodcs:
        return out
    allowed = idx.group_by_rid(RID_ALLOWED_RODC)
    if allowed is not None:
        for dn in allowed.member:
            m = idx.get(dn)
            who = _who(idx, m) if m is not None else (dn, "")
            out.append(_finding(cfg, "allowed_group_not_empty", allowed.dn, f"В Allowed RODC Password Replication Group состоит {who[0]}: его пароль кэшируется на всех RODC", who))
    denied = idx.group_by_rid(RID_DENIED_RODC)
    if denied is not None:
        members = _reachable(idx, denied)
        # Проверяются только субъекты, которые есть в выгрузке: в дочернем домене Enterprise и Schema Admins лежат в корневом домене.
        missing = [r for r in DENIED_REQUIRED_RIDS if (o := idx.by_sid.get(idx.domain_rid_sid(r))) is not None and o.sid not in members]
        if missing:
            names = [idx.principal_name(idx.domain_rid_sid(r)) for r in missing]
            out.append(_finding(cfg, "denied_group_incomplete", denied.dn,
                                f"В Denied RODC Password Replication Group нет: {', '.join(names)}", missing_rids=missing, missing=names))
    return out
