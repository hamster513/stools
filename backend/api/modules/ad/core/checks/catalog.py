"""«Как исправить» и ссылки для каждой проверки — отдельно от логики проверок.

Реестр (`checks/__init__.py`) подставляет эти поля в `CheckSpec`; у проверки
без записи здесь реестр не соберётся (KeyError) — тест каталога это ловит.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from api.modules.ad.core.checks.common import CheckSpec

Ref = tuple[str, str]


@dataclass(frozen=True)
class Guidance:
    category: str
    remediation: str
    references: tuple[Ref, ...] = ()


def with_guidance(spec: CheckSpec) -> CheckSpec:
    g = GUIDANCE[spec.code]
    return replace(spec, category=g.category, remediation=g.remediation, references=g.references)


def _attack(technique: str, name: str) -> Ref:
    return f"MITRE ATT&CK {technique}: {name}", f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"


_LEARN = "https://learn.microsoft.com/en-us"
_PREV = f"{_LEARN}/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings"
PROTECTED_ACCOUNTS: Ref = ("Microsoft: защищённые учётные записи и группы (AdminSDHolder)", f"{_LEARN}/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory")
LEAST_PRIVILEGE: Ref = ("Microsoft: модель наименьших привилегий в AD", f"{_LEARN}/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models")
DELEGATION: Ref = ("Microsoft: ограниченная делегация Kerberos", f"{_LEARN}/windows-server/security/kerberos/kerberos-constrained-delegation-overview")
GMSA: Ref = ("Microsoft: групповые управляемые учётные записи служб (gMSA)", f"{_LEARN}/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview")
SET_ACCOUNT_CONTROL: Ref = ("Microsoft: Set-ADAccountControl", f"{_LEARN}/powershell/module/activedirectory/set-adaccountcontrol")
UAC_FLAGS: Ref = ("Microsoft: флаги userAccountControl", f"{_LEARN}/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties")
CERT_ASSESSMENTS: Ref = ("Microsoft Defender for Identity: оценки безопасности AD CS", f"{_LEARN}/defender-for-identity/security-posture-assessments/certificates")
CERTIFIED_PRE_OWNED: Ref = ("SpecterOps: Certified Pre-Owned (ESC1–8)", "https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf")
CERT_T1649 = _attack("T1649", "Steal or Forge Authentication Certificates")

GUIDANCE: dict[str, Guidance] = {
    "DCSync": Guidance(
        "acl",
        "Уберите у субъекта расширенные права DS-Replication-Get-Changes и DS-Replication-Get-Changes-All на корне домена (вкладка «Безопасность» объекта домена в «Пользователи и компьютеры» или dsacls). Право репликации оставьте только контроллерам домена, Domain Admins и Enterprise Admins; учётке синхронизации каталога — только если синхронизация действительно используется.",
        (
            ("Microsoft: право DS-Replication-Get-Changes-All", f"{_LEARN}/windows/win32/adschema/r-ds-replication-get-changes-all"),
            _attack("T1003.006", "OS Credential Dumping: DCSync"),
        ),
    ),
    "PrivilegedGroups": Guidance(
        "privileged",
        "Пересмотрите состав группы и удалите участников, которым права не нужны постоянно. Администрирование выполняйте отдельными учётками администратора, сервисные учётки уберите из группы и выдайте им точечные права (лучше перевести на gMSA).",
        (LEAST_PRIVILEGE, PROTECTED_ACCOUNTS, _attack("T1078.002", "Valid Accounts: Domain Accounts")),
    ),
    "Delegation": Guidance(
        "kerberos",
        "Снимите неограниченную делегацию (флаг TRUSTED_FOR_DELEGATION, «Доверять компьютеру делегирование любых служб») и замените её ограниченной на конкретные службы или RBCD. У ограниченной делегации сократите список msDS-AllowedToDelegateTo и уберите protocol transition, если он не нужен. Привилегированным учёткам включите «Учётная запись важна и не может быть делегирована» или добавьте их в Protected Users.",
        (DELEGATION, _attack("T1558", "Steal or Forge Kerberos Tickets"), _attack("T1187", "Forced Authentication")),
    ),
    "ShadowAdmins": Guidance(
        "acl",
        "Удалите с объекта CN=AdminSDHolder,CN=System лишние ACE с правами записи (GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty). SDProp раз в час копирует этот DACL на все защищённые учётки и группы — после правки проверьте их на такие же ACE и удалите.",
        (PROTECTED_ACCOUNTS, _attack("T1098", "Account Manipulation")),
    ),
    "RBCD": Guidance(
        "kerberos",
        "Очистите msDS-AllowedToActOnBehalfOfOtherIdentity у объекта-цели (Set-ADComputer <имя> -PrincipalsAllowedToDelegateToAccount $null) или оставьте в нём только нужные сервисные учётки. Отберите у посторонних субъектов право записи этого атрибута и GenericWrite или GenericAll на компьютер.",
        (
            DELEGATION,
            ("Microsoft: Set-ADComputer", f"{_LEARN}/powershell/module/activedirectory/set-adcomputer"),
            _attack("T1550", "Use Alternate Authentication Material"),
        ),
    ),
    "ASREP": Guidance(
        "kerberos",
        "Включите предварительную аутентификацию Kerberos: снимите флаг «Не требовать предварительной проверки подлинности Kerberos» (DONT_REQ_PREAUTH) в свойствах учётки или командой Set-ADAccountControl <имя> -DoesNotRequirePreAuth $false. Если флаг нужен старому приложению — задайте учётке случайный пароль от 25 символов.",
        (SET_ACCOUNT_CONTROL, UAC_FLAGS, _attack("T1558.004", "Steal or Forge Kerberos Tickets: AS-REP Roasting")),
    ),
    "Kerberoast": Guidance(
        "kerberos",
        "Переведите службу на gMSA (пароль из 120 символов меняется автоматически) или задайте учётке случайный пароль от 25 символов и меняйте его регулярно. Уберите неиспользуемые SPN (Set-ADUser <имя> -ServicePrincipalNames @{Remove='<SPN>'}) и разрешите учётке только AES (msDS-SupportedEncryptionTypes = 24).",
        (GMSA, _attack("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting")),
    ),
    "AdminCount": Guidance(
        "privileged",
        "Если объект больше не состоит в защищённых группах, сбросьте атрибут (Set-ADUser <имя> -Clear adminCount) и включите наследование разрешений («Безопасность» → «Дополнительно»): иначе на нём остаётся DACL от AdminSDHolder и не действуют права OU. Если объект в защищённой группе — проверьте, нужно ли ему это членство.",
        (PROTECTED_ACCOUNTS, _attack("T1078.002", "Valid Accounts: Domain Accounts")),
    ),
    "GpoPermissions": Guidance(
        "gpo",
        "Оставьте право изменять GPO (Edit settings, Edit settings, delete, modify security, владение) только Domain Admins, Enterprise Admins и SYSTEM, остальным — Read и Apply. Права меняются в GPMC на вкладке «Делегирование» или командой Set-GPPermission -Replace; затем проверьте права NTFS на папку политики в SYSVOL.",
        (
            ("Microsoft: Set-GPPermission", f"{_LEARN}/powershell/module/grouppolicy/set-gppermission"),
            _attack("T1484.001", "Domain or Tenant Policy Modification: Group Policy Modification"),
        ),
    ),
    "UserRightsAssignment": Guidance(
        "gpo",
        "В GPO из находки (Конфигурация компьютера → Политики → Конфигурация Windows → Параметры безопасности → Локальные политики → Назначение прав пользователя) удалите субъекта из опасного права. SeDebugPrivilege, SeTcbPrivilege и SeEnableDelegationPrivilege оставьте только Administrators или никому, SeBackupPrivilege и SeRestorePrivilege — Administrators и Backup Operators.",
        (
            ("Microsoft: назначение прав пользователя", f"{_PREV}/user-rights-assignment"),
            _attack("T1134", "Access Token Manipulation"),
        ),
    ),
    "PasswordNeverExpires": Guidance(
        "accounts",
        "Снимите флаг «Срок действия пароля не ограничен» (Set-ADUser <имя> -PasswordNeverExpires $false) и смените пароль. Сервисные учётки переведите на gMSA; если флаг оставить нельзя — случайный пароль от 25 символов и смена по регламенту.",
        (
            ("Microsoft: максимальный срок действия пароля", f"{_PREV}/maximum-password-age"),
            GMSA,
            _attack("T1110", "Brute Force"),
        ),
    ),
    "InactiveUsers": Guidance(
        "accounts",
        "Выключите учётку (Disable-ADAccount) и перенесите её в OU отключённых, через согласованный срок удалите. Сервисные учётки сначала сверьте с владельцем службы. Найти все такие учётки: Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly.",
        (
            ("Microsoft: Search-ADAccount", f"{_LEARN}/powershell/module/activedirectory/search-adaccount"),
            _attack("T1078.002", "Valid Accounts: Domain Accounts"),
        ),
    ),
    "MachineAccountQuota": Guidance(
        "domain",
        "Установите ms-DS-MachineAccountQuota = 0 на корне домена (Set-ADDomain -Identity <домен> -Replace @{'ms-DS-MachineAccountQuota'=0}) и делегируйте ввод компьютеров в домен отдельной группе на конкретную OU (право «Создание объектов Компьютер»).",
        (
            ("Microsoft: атрибут ms-DS-MachineAccountQuota", f"{_LEARN}/windows/win32/adschema/a-ms-ds-machineaccountquota"),
            _attack("T1136.002", "Create Account: Domain Account"),
        ),
    ),
    "KeyCredentialLinkACL": Guidance(
        "acl",
        "Уберите у субъекта право записи msDS-KeyCredentialLink на объекте из находки, а также GenericAll и GenericWrite, которые его включают. Запись атрибута нужна только Key Admins, Enterprise Key Admins и самому устройству для Windows Hello for Business. Проверьте значения атрибута и удалите неизвестные ключи.",
        (_attack("T1098", "Account Manipulation"),),
    ),
    "ProtectedUsersCoverage": Guidance(
        "privileged",
        "Добавьте привилегированные учётки в группу Protected Users: для них отключаются NTLM, делегирование, DES и RC4, а билеты Kerberos живут 4 часа. Перед добавлением убедитесь, что учётка не запускает службы и не входит на системы старше Windows Server 2012 R2; сервисные учётки и компьютеры в группу не добавляйте.",
        (
            ("Microsoft: группа Protected Users", f"{_LEARN}/windows-server/security/credentials-protection-and-management/protected-users-security-group"),
            _attack("T1003", "OS Credential Dumping"),
        ),
    ),
    "KrbtgtPasswordAge": Guidance(
        "kerberos",
        "Смените пароль krbtgt дважды: второй раз — после репликации первой смены на все контроллеры и не раньше, чем истечёт максимальный срок жизни билета (по умолчанию 10 часов). Удобно сценарием Microsoft New-KrbtgtKeys.ps1; дальше меняйте пароль регулярно, не реже срока из настройки krbtgt_max_age_days.",
        (
            ("Microsoft: сброс пароля krbtgt", f"{_LEARN}/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password"),
            _attack("T1558.001", "Steal or Forge Kerberos Tickets: Golden Ticket"),
        ),
    ),
    "WeakEncryption": Guidance(
        "kerberos",
        "Разрешите учётке только AES: msDS-SupportedEncryptionTypes = 24 (AES128 и AES256) или флажки AES в свойствах учётки, затем смените пароль, чтобы появились ключи AES. Флаг «Использовать только типы шифрования DES» снимите (Set-ADAccountControl <имя> -UseDESKeyOnly $false). После проверки совместимости запретите DES и RC4 политикой «Сетевая безопасность: настройка типов шифрования, разрешённых Kerberos».",
        (
            ("Microsoft: типы шифрования, разрешённые Kerberos", f"{_PREV}/network-security-configure-encryption-types-allowed-for-kerberos"),
            _attack("T1558", "Steal or Forge Kerberos Tickets"),
        ),
    ),
    "SensitiveAcl": Guidance(
        "acl",
        "Удалите у субъекта права записи (GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty, CreateChild) на OU или компьютере из находки; нужное делегирование оформите отдельной группой с минимальными правами. Унаследованное право правьте на объекте-источнике из находки, а не на потомках.",
        (LEAST_PRIVILEGE, _attack("T1098", "Account Manipulation"), _attack("T1484", "Domain or Tenant Policy Modification")),
    ),
    "ADCS_ESC": Guidance(
        "pki",
        "В оснастке «Шаблоны сертификатов» (certtmpl.msc) уберите Enroll и AutoEnroll у широких групп, выключите «Предоставляется в запросе» (ENROLLEE_SUPPLIES_SUBJECT) у шаблонов с проверкой подлинности клиента, включите одобрение диспетчером сертификатов и оставьте право изменять шаблон только администраторам PKI. Ненужный шаблон снимите с публикации на ЦС.",
        (
            ("Microsoft: шаблоны сертификатов", f"{_LEARN}/windows-server/identity/ad-cs/certificate-template-concepts"),
            CERT_ASSESSMENTS,
            CERTIFIED_PRE_OWNED,
            CERT_T1649,
        ),
    ),
    "ADCS_CA": Guidance(
        "pki",
        "Снимите флаг EDITF_ATTRIBUTESUBJECTALTNAME2 (certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2, затем перезапуск certsvc), включите IF_ENFORCEENCRYPTICERTREQUEST и уберите расширение 1.3.6.1.4.1.311.25.2 из списка отключённых. Права ManageCA, ManageCertificates и запись в контейнеры PKI оставьте только администраторам PKI. Веб-выдачу (certsrv) переведите на HTTPS с Extended Protection for Authentication или отключите.",
        (
            ("Microsoft: KB5005413, защита AD CS от NTLM relay", "https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429"),
            CERT_ASSESSMENTS,
            CERTIFIED_PRE_OWNED,
            CERT_T1649,
        ),
    ),
    "ADCS_MAPPING": Guidance(
        "pki",
        "Переведите контроллеры домена в режим полной принудительной привязки: StrongCertificateBindingEnforcement = 2 в HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc, и уберите сопоставление по UPN (бит 0x4) из CertificateMappingMethods в ключе Schannel. Слабые явные сопоставления в altSecurityIdentities (по субъекту или e-mail) замените на X509IssuerSerialNumber или X509SKI.",
        (
            ("Microsoft: KB5014754, привязка сертификатов на контроллерах", "https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16"),
            CERT_T1649,
        ),
    ),
}
