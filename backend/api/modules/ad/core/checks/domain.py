"""Параметры домена: MachineAccountQuota, возраст пароля krbtgt, число админов, функциональный уровень, Pre-Windows 2000, политика паролей,
корзина, dSHeuristics, бэкап, репликация SYSVOL, уязвимый класс схемы."""
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
    """msDS-Behavior-Version из числа, имени ADDomainMode или ADForestMode или года; не распознано — None."""
    text = raw.strip().lower()
    for suffix in ("domain", "forest"):
        if text.startswith("windows") and text.endswith(suffix):
            text = text[len("windows"):-len(suffix)]
            break
    # Год раньше числа: «2016» — Windows Server 2016, а не msDS-Behavior-Version (их значения 0–10).
    if text in _LEVEL_BY_YEAR:
        return _LEVEL_BY_YEAR[text]
    return int(text) if text.isdigit() else None


def _level_finding(idx: ExportIndex, cfg: AdConfig, raw: str, scope: str, key_extra: str) -> list[Finding]:
    level = functional_level_value(raw)
    if level is None or level >= 7:
        return []
    name = FUNCTIONAL_LEVELS.get(level, str(level))
    f = Finding(
        check="FunctionalLevel", severity="Medium" if level < 4 else "Low", target=idx.export.domain.dn, key_extra=key_extra,
        details={"details": f"Функциональный уровень {scope} — Windows Server {name} ({level})", "level": level, "level_name": name},
    )
    return [finalize(f, cfg, allowlist=False)]


def check_functional_level(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    domain = idx.export.domain
    out = _level_finding(idx, cfg, domain.functional_level, "домена", "")
    if domain.forest_functional_level is not None:
        out += _level_finding(idx, cfg, domain.forest_functional_level, "леса", "forest")
    return out


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


def _domain_finding(idx: ExportIndex, cfg: AdConfig, check: str, severity: str, details: str, key_extra: str = "", **extra: object) -> Finding:
    f = Finding(check=check, severity=severity, target=idx.export.domain.dn, key_extra=key_extra, details={"details": details, **extra})
    return finalize(f, cfg, allowlist=False)


#: pwdProperties: DOMAIN_PASSWORD_COMPLEX, DOMAIN_PASSWORD_STORE_CLEARTEXT.
PWD_COMPLEX = 0x1
PWD_STORE_CLEARTEXT = 0x10


def _policy_issues(cfg: AdConfig, min_length: int | None, lockout: int | None, reversible: bool | None, complexity: bool | None) -> list[tuple[str, str, str]]:
    """(вид, серьёзность, текст) по одной политике паролей; None — значение не прочитано, вид не проверяется."""
    out = []
    if min_length is not None and min_length < cfg.password_min_length:
        out.append(("min_length", "Medium", f"Минимальная длина пароля {min_length} (порог {cfg.password_min_length})"))
    if lockout == 0:
        out.append(("no_lockout", "Medium", "Блокировка после неверных паролей выключена: пароли можно подбирать без ограничений"))
    if reversible:
        out.append(("reversible", "High", "Пароли хранятся с обратимым шифрованием: их можно восстановить из базы AD"))
    if complexity is False:
        out.append(("no_complexity", "Low", "Требование сложности пароля выключено"))
    return out


def check_password_policy(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    domain = idx.export.domain
    props = domain.pwd_properties
    out = [
        _domain_finding(idx, cfg, "PasswordPolicy", severity, f"Политика домена: {text}", kind, kind=kind)
        for kind, severity, text in _policy_issues(
            cfg, domain.min_pwd_length, domain.lockout_threshold,
            None if props is None else bool(props & PWD_STORE_CLEARTEXT), None if props is None else bool(props & PWD_COMPLEX),
        )
    ]
    for pso in idx.objects("msDS-PasswordSettings"):
        name = pso.name or pso.rdn_value
        applies = [o.label if (o := idx.get(dn)) is not None else dn for dn in pso.psoAppliesTo]
        for kind, severity, text in _policy_issues(cfg, pso.psoMinLength, pso.psoLockoutThreshold, pso.psoReversible, pso.psoComplexity):
            f = Finding(
                check="PasswordPolicy", severity=severity, identity=name, target=pso.dn, key_extra=kind,
                details={"details": f"PSO {name}: {text}", "kind": kind, "precedence": pso.psoPrecedence, "applies_to": applies},
            )
            out.append(finalize(f, cfg, allowlist=False))
    return out


def check_recycle_bin(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    if idx.export.domain.recycle_bin is not False:
        return []
    return [_domain_finding(idx, cfg, "RecycleBin", "Low", "Корзина AD выключена: удалённый объект восстанавливается только из резервной копии либо из tombstone без большинства атрибутов")]


def heuristic(value: str, position: int) -> str:
    """Символ dSHeuristics на позиции с единицы (MS-ADTS 6.1.1.2.4.1.2); строка короче — "0", значение по умолчанию."""
    return value[position - 1] if len(value) >= position else "0"


#: Вид → (позиция, опасный символ: «=X» — равен X, «!X» — не равен X, серьёзность, текст).
_HEURISTICS: tuple[tuple[str, int, str, str, str], ...] = (
    ("list_object", 3, "=1", "Info", "fDoListObject: включён режим прав List Object"),
    ("anonymous", 7, "=2", "High", "fLDAPBlockAnonOps: анонимным клиентам разрешены все операции LDAP, которые пропускают права"),
    ("anon_nspi", 8, "!0", "Medium", "fAllowAnonNSPI: анонимный доступ к адресной книге по NSPI"),
    ("adminsdex", 16, "!0", "Medium", "dwAdminSDExMask: группы операторов исключены из защиты AdminSDHolder"),
    ("uniqueness", 21, "!0", "Medium", "DoNotVerifyUPNAndOrSPNUniqueness: уникальность UPN и SPN не проверяется"),
)


def _matches(ch: str, cond: str) -> bool:
    return ch == cond[1] if cond[0] == "=" else ch != cond[1]


def check_ds_heuristics(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    value = idx.export.domain.ds_heuristics
    if not value:
        return []
    out = []
    for kind, position, cond, severity, text in _HEURISTICS:
        ch = heuristic(value, position)
        if _matches(ch, cond):
            out.append(_domain_finding(idx, cfg, "DsHeuristics", severity, f"dSHeuristics, позиция {position} = «{ch}»: {text}", kind, kind=kind, value=value))
    # KB5008383: «2» на позиции 28 (LDAPAddAuthZVerifications) или 29 (LDAPOwnerModify) выключает дополнительные проверки прав.
    disabled = [p for p in (28, 29) if heuristic(value, p) == "2"]
    if disabled:
        out.append(_domain_finding(
            idx, cfg, "DsHeuristics", "Medium",
            f"dSHeuristics, позиция {' и '.join(map(str, disabled))} = «2»: защита KB5008383 при создании и изменении компьютеров выключена явно",
            "ldap_authz", kind="ldap_authz", value=value,
        ))
    return out


def check_backup_age(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    domain = idx.export.domain
    if not domain.backup_read:
        return []
    limit = cfg.backup_max_age_days
    if domain.last_backup is None:
        return [_domain_finding(idx, cfg, "BackupAge", "Medium", "Отметки бэкапа нет: резервная копия AD не делалась ни разу", limit_days=limit)]
    age = (idx.export.collected_at - domain.last_backup).days
    if age <= limit:
        return []
    return [_domain_finding(
        idx, cfg, "BackupAge", "Medium", f"Последний бэкап AD {domain.last_backup.strftime('%Y-%m-%d')}, {age} дн. назад (порог {limit})",
        age_days=age, limit_days=limit, last_backup=domain.last_backup.strftime("%Y-%m-%d"),
    )]


def check_ntfrs_sysvol(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    if (idx.export.domain.sysvol_replication or "").lower() != "ntfrs":
        return []
    return [_domain_finding(idx, cfg, "NtfrsSysvol", "Low", "SYSVOL реплицируется устаревшей службой FRS: контроллер Windows Server 2019 и новее в такой домен не вводится, переведите SYSVOL на DFSR")]


#: Класс Exchange, в который можно вкладывать компьютеры: CVE-2021-34470.
VULNERABLE_CLASS = "msExchStorageGroup"


def check_schema_vulnerable_class(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    superiors = (idx.export.domain.schema_poss_superiors or {}).get(VULNERABLE_CLASS) or []
    if "computer" not in {s.lower() for s in superiors}:
        return []
    return [_domain_finding(
        idx, cfg, "SchemaVulnerableClass", "Medium",
        f"possSuperiors класса {VULNERABLE_CLASS} содержит computer (CVE-2021-34470): схема Exchange не обновлена",
        poss_superiors=superiors,
    )]
