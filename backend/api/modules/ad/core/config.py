"""Настройки проверок — то, что в прототипе лежало в AD_audit.config.json.

Привилегированные группы задаются и именами (для нестандартных), и RID —
RID не зависят от языка домена, а прототип держал списки на двух языках.
"""
from __future__ import annotations

import datetime

from pydantic import BaseModel, Field


class UserRight(BaseModel):
    right: str
    severity: str


class AdConfig(BaseModel):
    #: Короткие имена (после «\»), которым разрешено быть в опасных местах.
    allowlist_short: list[str] = Field(
        default_factory=lambda: [
            "DOMAIN ADMINS",
            "ENTERPRISE ADMINS",
            "ADMINISTRATORS",
            "DOMAIN CONTROLLERS",
            "ENTERPRISE DOMAIN CONTROLLERS",
            "АДМИНИСТРАТОРЫ ДОМЕНА",
            "АДМИНИСТРАТОРЫ ПРЕДПРИЯТИЯ",
            "АДМИНИСТРАТОРЫ",
            "КОНТРОЛЛЕРЫ ДОМЕНА",
            "КОНТРОЛЛЕРЫ ДОМЕНА ПРЕДПРИЯТИЯ",
            "СИСТЕМА",
            "SYSTEM",
        ]
    )
    allowlist_full: list[str] = Field(
        default_factory=lambda: ["NT AUTHORITY\\SYSTEM", "BUILTIN\\ADMINISTRATORS", "BUILTIN\\АДМИНИСТРАТОРЫ"]
    )
    privileged_groups: list[str] = Field(
        default_factory=lambda: [
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "Account Operators",
            "Backup Operators",
            "Server Operators",
            "Администраторы домена",
            "Администраторы предприятия",
            "Администраторы схемы",
            "Администраторы",
            "Операторы учетных записей",
            "Операторы архива",
            "Операторы серверов",
            "DnsAdmins",
        ]
    )
    #: Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account, Backup, Server, Print Operators,
    #: Replicator, Cert Publishers, Group Policy Creator Owners, Key Admins, Enterprise Key Admins.
    #: RID 544–582 — встроенные (S-1-5-32-<RID>), остальные — RID своего домена.
    privileged_rids: list[int] = Field(default_factory=lambda: [512, 519, 518, 544, 548, 551, 549, 550, 552, 517, 520, 526, 527])
    user_rights: list[UserRight] = Field(
        default_factory=lambda: [
            UserRight(right="SeEnableDelegationPrivilege", severity="High"),
            UserRight(right="SeDebugPrivilege", severity="High"),
            UserRight(right="SeTcbPrivilege", severity="High"),
            UserRight(right="SeBackupPrivilege", severity="Medium"),
            UserRight(right="SeRestorePrivilege", severity="Medium"),
        ]
    )
    user_inactivity_days: int = Field(default=90, ge=1)
    krbtgt_max_age_days: int = Field(default=180, ge=1)
    #: Больше стольких админов (§0 спеки гигиены) — находка TooManyAdmins.
    admins_max: int = Field(default=20, ge=1)
    admin_password_max_age_days: int = Field(default=1095, ge=1)
    builtin_admin_recent_days: int = Field(default=35, ge=1)
    azure_sso_key_max_age_days: int = Field(default=90, ge=1)
    computer_inactivity_days: int = Field(default=90, ge=1)
    computer_password_max_age_days: int = Field(default=90, ge=1)
    #: Минимальная длина пароля в политике домена и в каждой PSO.
    password_min_length: int = Field(default=8, ge=1)
    #: Последний бэкап AD (по dSASignature) старше стольких дней — находка BackupAge.
    backup_max_age_days: int = Field(default=7, ge=1)
    #: Пароль учётки «только смарт-карта» старше — находка SmartcardPassword (если домен его не меняет сам).
    smartcard_password_max_age_days: int = Field(default=90, ge=1)
    #: Сборка Windows (из operatingSystemVersion) → дата окончания поддержки; после неё ОС считается устаревшей.
    obsolete_os_builds: dict[str, datetime.date] = Field(
        default_factory=lambda: {"22000": datetime.date(2024, 10, 8), "22621": datetime.date(2025, 10, 14)}
    )
    low_priv_groups: list[str] = Field(
        default_factory=lambda: [
            "AUTHENTICATED USERS",
            "DOMAIN USERS",
            "USERS",
            "EVERYONE",
            "NT AUTHORITY\\AUTHENTICATED USERS",
            "BUILTIN\\USERS",
            "ПОЛЬЗОВАТЕЛИ ДОМЕНА",
            "ПОЛЬЗОВАТЕЛИ",
            "АУТЕНТИФИЦИРОВАННЫЕ ПОЛЬЗОВАТЕЛИ",
            "ВСЕ",
        ]
    )
    #: Low-priv по SID: Everyone, Authenticated Users, BUILTIN\Users и RID 513/515 домена.
    low_priv_sids: list[str] = Field(default_factory=lambda: ["S-1-1-0", "S-1-5-11", "S-1-5-32-545"])
    low_priv_rids: list[int] = Field(default_factory=lambda: [513, 515])
    #: AD CS: безопасны только заведомые администраторы, любой другой заявитель
    #: под вопросом; low_priv_* выше задают «широкие» группы, у них серьёзность выше.
    #: SYSTEM, BUILTIN\Administrators, Enterprise Domain Controllers.
    adcs_safe_sids: list[str] = Field(default_factory=lambda: ["S-1-5-18", "S-1-5-32-544", "S-1-5-9"])
    #: RID доменов своего леса (свой и доверия внутри леса; в старой выгрузке — любого домена):
    #: Administrator, Domain Admins, Domain Controllers, Schema Admins, Enterprise Admins, Enterprise Read-only DCs, Read-only DCs,
    #: Cert Publishers (серверы ЦС; AD по умолчанию даёт ей запись в AIA, CDP и Certification Authorities).
    adcs_safe_rids: list[int] = Field(default_factory=lambda: [500, 512, 516, 518, 519, 498, 521, 517])
    #: Имена (свои группы администраторов ЦС).
    adcs_safe_principals: list[str] = Field(default_factory=list)
    #: Админы — включённые рекурсивные члены этих групп и учётка RID 500. RID 544–582 —
    #: встроенные (S-1-5-32-<RID>): Domain Admins, Schema Admins, Enterprise Admins, Administrators.
    admin_rids: list[int] = Field(default_factory=lambda: [512, 518, 519, 544])
    #: Безопасные субъекты ACL вне AD CS (RID доменов своего леса) — как adcs_safe_rids, но без Cert Publishers.
    tier0_safe_rids: list[int] = Field(default_factory=lambda: [500, 512, 516, 518, 519, 498, 521])
    #: OUs | Computers | Both
    sensitive_acl_scope: str = "Both"
    sensitive_acl_search_base: str = ""
    sensitive_acl_exclude_ous: list[str] = Field(default_factory=list)
    sensitive_acl_max_objects: int = Field(default=0, ge=0)
    #: Сворачивать унаследованные ACE к объекту-источнику, а одинаковые явные
    #: права на множестве объектов — в одну находку.
    sensitive_acl_collapse: bool = True
    #: С какого числа объектов (строго больше) явная пара «кто + право» сворачивается.
    sensitive_acl_collapse_threshold: int = Field(default=50, ge=1, le=100000)


DEFAULT_CONFIG = AdConfig()
