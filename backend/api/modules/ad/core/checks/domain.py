"""Параметры домена: MachineAccountQuota, возраст пароля krbtgt, число админов, функциональный уровень, Pre-Windows 2000."""
from __future__ import annotations

from api.modules.ad.core.checks import principals
from api.modules.ad.core.checks.adcs_rules import _fsp_sid
from api.modules.ad.core.checks.common import date_str, days_between
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import RID_KRBTGT, ExportIndex
from api.modules.ad.core.findings import Finding, finalize


def check_machine_account_quota(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    quota = idx.export.domain.machine_account_quota
    if quota is None:
        return [finalize(Finding(check="MachineAccountQuota", severity="Info", target=idx.export.domain.dn, details={"details": "ms-DS-MachineAccountQuota не прочитан"}), cfg)]
    return [
        finalize(
            Finding(
                check="MachineAccountQuota",
                severity="Medium" if quota > 0 else "Low",
                target=idx.export.domain.dn,
                details={"details": f"ms-DS-MachineAccountQuota={quota}", "quota": quota},
            ),
            cfg,
        )
    ]


def check_krbtgt_password_age(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    krbtgt = idx.by_sid.get(idx.domain_rid_sid(RID_KRBTGT))
    if krbtgt is None:
        krbtgt = next((u for u in idx.objects("user") if (u.sam or "").lower() == "krbtgt"), None)
    if krbtgt is None:
        return []
    age = days_between(krbtgt.pwdLastSet, idx.export.collected_at)
    limit = cfg.krbtgt_max_age_days if cfg.krbtgt_max_age_days >= 1 else 180
    severity = "High" if age is not None and age > limit else "Low"
    details = (
        f"krbtgt pwdLastSet={date_str(krbtgt.pwdLastSet)}, ageDays={age}" if age is not None else "krbtgt pwdLastSet не найден"
    )
    return [
        finalize(
            Finding(check="KrbtgtPasswordAge", severity=severity, identity="krbtgt", identity_sid=krbtgt.sid or "", target=idx.export.domain.dn, details={"details": details, "age_days": age, "limit_days": limit}),
            cfg,
            allowlist=False,
        )
    ]


#: Сколько имён админов показывать в находке TooManyAdmins.
ADMIN_SAMPLES = 20
#: msDS-Behavior-Version → версия Windows Server.
FUNCTIONAL_LEVELS = {0: "2000", 1: "2003 interim", 2: "2003", 3: "2008", 4: "2008 R2", 5: "2012", 6: "2012 R2", 7: "2016", 10: "2025"}
RID_PRE_WIN2000 = 554
#: Anonymous Logon и Everyone в Pre-Windows 2000 — чтение каталога без входа.
PRE_WIN2000_ANONYMOUS = ("S-1-5-7", "S-1-1-0")


def check_too_many_admins(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    dns = principals.admin_dns(idx, cfg)
    if len(dns) <= cfg.admins_max:
        return []
    names = sorted(idx.principal_name(o.sid) or o.label for o in map(idx.get, dns) if o is not None)
    f = Finding(
        check="TooManyAdmins", severity="Medium", target=idx.export.domain.dn,
        details={"details": f"Администраторов {len(dns)} при пороге {cfg.admins_max}", "count": len(dns), "limit": cfg.admins_max, "samples": names[:ADMIN_SAMPLES]},
    )
    return [finalize(f, cfg, allowlist=False)]


#: Год версии → msDS-Behavior-Version; PowerShell-сборщик пишет имя ADDomainMode (Windows2008R2Domain), LDAP — число.
_LEVEL_BY_YEAR = {"2000": 0, "2003interim": 1, "2003": 2, "2008": 3, "2008r2": 4, "2012": 5, "2012r2": 6, "2016": 7, "2025": 10}


def functional_level_value(raw: str) -> int | None:
    """msDS-Behavior-Version из числа, имени ADDomainMode или года; не распознано — None."""
    text = raw.strip().lower()
    if text.startswith("windows") and text.endswith("domain"):
        text = text[len("windows"):-len("domain")]
    # Год раньше числа: «2016» — Windows Server 2016, а не msDS-Behavior-Version (их значения 0–10).
    if text in _LEVEL_BY_YEAR:
        return _LEVEL_BY_YEAR[text]
    return int(text) if text.isdigit() else None


def check_functional_level(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    level = functional_level_value(idx.export.domain.functional_level)
    if level is None or level >= 7:
        return []
    name = FUNCTIONAL_LEVELS.get(level, str(level))
    f = Finding(
        check="FunctionalLevel", severity="Medium" if level < 4 else "Low", target=idx.export.domain.dn,
        details={"details": f"Функциональный уровень домена — Windows Server {name} ({level})", "level": level, "level_name": name},
    )
    return [finalize(f, cfg, allowlist=False)]


def check_pre_win2000_access(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    grp = idx.group_for_rid(RID_PRE_WIN2000)
    if grp is None:
        return []
    out = []
    for dn in grp.member:
        sid = _fsp_sid(dn)
        if sid is None and (obj := idx.get(dn)) is not None:
            sid = obj.sid
        anonymous = sid in PRE_WIN2000_ANONYMOUS
        f = Finding(
            check="PreWin2000Access", severity="High" if anonymous else "Low",
            identity=idx.principal_name(sid) if sid else dn, identity_sid=sid or "", target=grp.dn,
            details={"details": "Анонимный доступ на чтение каталога" if anonymous else "Участник группы читает атрибуты всех пользователей и групп домена"},
        )
        out.append(finalize(f, cfg))
    return out
