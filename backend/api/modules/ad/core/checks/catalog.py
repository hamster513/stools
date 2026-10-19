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
        "В GPO из находки (Конфигурация компьютера → Политики → Конфигурация Windows → Параметры безопасности → Локальные политики → Назначение прав пользователя) удалите субъекта из опасного права. SeDebugPrivilege, SeTcbPrivilege и SeEnableDelegationPrivilege оставьте только Administrators или никому, SeBackupPrivilege и SeRestorePrivilege — Administrators и Backup Operators, SeTrustedCredManAccessPrivilege (доступ к диспетчеру учётных данных от имени доверенного вызывающего) не назначайте никому.",
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
    "PasswordNotRequired": Guidance(
        "accounts",
        "Снимите флаг PASSWD_NOTREQD (Set-ADAccountControl <имя> -PasswordNotRequired $false) и задайте учётке пароль, соответствующий парольной политике. Найти такие учётки: Get-ADUser -Filter 'PasswordNotRequired -eq $true'.",
        (SET_ACCOUNT_CONTROL, UAC_FLAGS, _attack("T1078.002", "Valid Accounts: Domain Accounts")),
    ),
    "ReversiblePassword": Guidance(
        "accounts",
        "Снимите флаг «Хранить пароль с использованием обратимого шифрования» (Set-ADAccountControl <имя> -AllowReversiblePasswordEncryption $false) и смените пароль, чтобы старое значение перестало храниться. Проверьте политику домена «Store passwords using reversible encryption»: она должна быть отключена.",
        (
            ("Microsoft: хранение паролей с обратимым шифрованием", f"{_PREV}/store-passwords-using-reversible-encryption"),
            SET_ACCOUNT_CONTROL,
            _attack("T1003", "OS Credential Dumping"),
        ),
    ),
    "AdminDelegable": Guidance(
        "privileged",
        "Включите администраторам флаг «Учётная запись важна и не может быть делегирована» (Set-ADAccountControl <имя> -AccountNotDelegated $true) или добавьте их в группу Protected Users. Перед этим проверьте, что учётка не нужна службам с делегацией.",
        (SET_ACCOUNT_CONTROL, PROTECTED_ACCOUNTS, _attack("T1558", "Steal or Forge Kerberos Tickets")),
    ),
    "AdminPasswordAge": Guidance(
        "privileged",
        "Смените пароль администратора на длинный уникальный (от 20 символов). Для учёток с постоянным паролем настройте регулярную смену по графику; для сервисных — переведите на gMSA.",
        (LEAST_PRIVILEGE, GMSA, _attack("T1078.002", "Valid Accounts: Domain Accounts")),
    ),
    "BuiltinAdminUsed": Guidance(
        "privileged",
        "Не используйте встроенный Administrator для повседневной работы: заведите отдельные именные учётки администраторов. Пароль Administrator сделайте длинным и уникальным, храните в сейфе, а недавний вход разберите по журналу событий 4624 на контроллерах.",
        (PROTECTED_ACCOUNTS, LEAST_PRIVILEGE, _attack("T1078.002", "Valid Accounts: Domain Accounts")),
    ),
    "GuestEnabled": Guidance(
        "privileged",
        "Отключите учётку Guest (Disable-ADAccount -Identity Guest) и убедитесь, что она не состоит в привилегированных группах и не имеет прав на ресурсы.",
        (
            ("Microsoft: Disable-ADAccount", f"{_LEARN}/powershell/module/activedirectory/disable-adaccount"),
            _attack("T1078.001", "Valid Accounts: Default Accounts"),
        ),
    ),
    "AzureSsoKeyAge": Guidance(
        "trust",
        "Смените ключ Kerberos для Seamless SSO командой Update-AzureADSSOForest (модуль AzureADSSO в Microsoft Entra Connect) в каждом лесу, где включён Seamless SSO. Microsoft рекомендует менять ключ каждые 30 дней; порог проверки задаётся в настройках.",
        (
            ("Microsoft: Seamless SSO в Microsoft Entra, вопросы и ответы", f"{_LEARN}/entra/identity/hybrid/connect/how-to-connect-sso-faq"),
            _attack("T1558", "Steal or Forge Kerberos Tickets"),
        ),
    ),
    "DuplicateObjects": Guidance(
        "accounts",
        "Определите, какой из конфликтующих объектов настоящий (по SID, дате создания и использованию), удалите лишний и проверьте репликацию (repadmin /replsummary). Объекты с CNF: в имени — следы конфликта репликации.",
        (
            ("Microsoft: конфликты репликации AD", f"{_LEARN}/troubleshoot/windows-server/active-directory/active-directory-replication-errors"),
        ),
    ),
    "Clusters": Guidance(
        "inventory",
        "Это инвентарная находка, не уязвимость: учётки кластера и ролей — виртуальные имена без агентов и входов, их не нужно лечить как хосты. Проверьте выключенные роли: объекты брошенных ролей удалите из AD (Remove-ClusterResource на кластере, затем объект компьютера), чтобы они не копились в каталоге.",
        (
            ("Microsoft: учётные записи кластера в Active Directory", f"{_LEARN}/windows-server/failover-clustering/configure-ad-accounts"),
        ),
    ),
    "InactiveComputers": Guidance(
        "accounts",
        "Определите владельца машины. Ненужные компьютеры отключите (Disable-ADAccount), через положенный срок удалите; для контроллера проверьте репликацию и при выводе из эксплуатации снимите роль через dcpromo или Uninstall-ADDSDomainController, а не удаляйте объект вручную.",
        (
            ("Microsoft: Search-ADAccount", f"{_LEARN}/powershell/module/activedirectory/search-adaccount"),
            ("Microsoft: Disable-ADAccount", f"{_LEARN}/powershell/module/activedirectory/disable-adaccount"),
            _attack("T1078.002", "Valid Accounts: Domain Accounts"),
        ),
    ),
    "ComputerPasswordAge": Guidance(
        "accounts",
        "Проверьте, что смена пароля компьютера не отключена: политика «Domain member: Disable machine account password changes» должна быть выключена, а значение DisablePasswordChange в реестре равно 0. Сбросьте пароль учётки (Reset-ComputerMachinePassword) или верните машину в домен.",
        (
            ("Microsoft: Domain member, отключение смены пароля учётной записи компьютера", f"{_PREV}/domain-member-disable-machine-account-password-changes"),
            ("Microsoft: Reset-ComputerMachinePassword", f"{_LEARN}/powershell/module/microsoft.powershell.management/reset-computermachinepassword"),
            _attack("T1078.002", "Valid Accounts: Domain Accounts"),
        ),
    ),
    "ObsoleteOs": Guidance(
        "accounts",
        "Обновите ОС до поддерживаемой версии или выведите компьютер из эксплуатации. Если обновить нельзя, изолируйте машину в отдельный сегмент сети, ограничьте доступ к ней и из неё и включите расширенные обновления безопасности, если они предлагаются. Устаревшие контроллеры замените в первую очередь. Даты окончания поддержки сборок хранятся в настройках проверки.",
        (
            ("Microsoft: жизненный цикл Windows", f"{_LEARN}/lifecycle/products/?products=windows"),
            _attack("T1210", "Exploitation of Remote Services"),
        ),
    ),
    "DcCount": Guidance(
        "dc",
        "Добавьте в домен минимум второй контроллер (Install-ADDSDomainController), желательно на другой площадке или хосте виртуализации, и убедитесь, что репликация работает (repadmin /replsummary).",
        (
            ("Microsoft: добавление контроллера домена в существующий домен", f"{_LEARN}/windows-server/identity/ad-ds/deploy/introduction-to-active-directory-domain-services-ad-ds-virtualization-level-100"),
        ),
    ),
    "DcDelegation": Guidance(
        "dc",
        "Очистите msDS-AllowedToDelegateTo у контроллера и снимите флаг «Доверять компьютеру делегирование указанных служб с любым протоколом аутентификации» (Set-ADComputer <имя> -Clear msDS-AllowedToDelegateTo; Set-ADAccountControl <имя> -TrustedToAuthForDelegation $false). Если делегация действительно нужна, перенесите её на отдельную службу.",
        (
            DELEGATION,
            SET_ACCOUNT_CONTROL,
            _attack("T1558", "Steal or Forge Kerberos Tickets"),
        ),
    ),
    "DcOwner": Guidance(
        "dc",
        "Верните владельцем объекта контроллера группу Domain Admins (вкладка «Безопасность» → «Дополнительно» → «Владелец» в «Пользователях и компьютерах»). Проверьте, кто и когда создавал объект и какие права успел выдать, и отмените лишние. Владельцем становится учётка, создавшая объект, а при вводе контроллера в домен делегированной учёткой владельцем остаётся она.",
        (
            ("Microsoft: защита контроллеров домена от атак", f"{_LEARN}/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory"),
            _attack("T1098", "Account Manipulation"),
        ),
    ),
    "TooManyAdmins": Guidance(
        "privileged",
        "Сократите число администраторов домена: оставьте в группах Domain Admins, Enterprise Admins, Schema Admins и Administrators только тех, кому полный контроль нужен постоянно. Остальным выдайте делегированные права на конкретные OU и задачи; сервисные учётки уберите из этих групп. Порог задаётся в настройках.",
        (LEAST_PRIVILEGE, PROTECTED_ACCOUNTS, _attack("T1078.002", "Valid Accounts: Domain Accounts")),
    ),
    "FunctionalLevel": Guidance(
        "domain",
        "Обновите или выведите из домена контроллеры со старыми версиями Windows Server и поднимите функциональный уровень домена (Set-ADDomainMode), затем леса (Set-ADForestMode) до Windows Server 2016. Повышение уровня необратимо на практике: перед ним убедитесь, что все контроллеры работают на нужной версии.",
        (
            ("Microsoft: функциональные уровни AD DS", f"{_LEARN}/windows-server/identity/ad-ds/active-directory-functional-levels"),
        ),
    ),
    "PreWin2000Access": Guidance(
        "domain",
        "Удалите из группы Pre-Windows 2000 Compatible Access участников Anonymous Logon и Everyone, затем Authenticated Users и прочих, если не используются приложения, которым нужен такой доступ (старые серверы RAS, NT 4.0). Проверяйте изменение на тестовой OU: некоторые старые приложения перестанут читать каталог.",
        (
            ("Microsoft: группы безопасности Active Directory", f"{_LEARN}/windows-server/identity/ad-ds/manage/understand-security-groups"),
            _attack("T1087.002", "Account Discovery: Domain Account"),
        ),
    ),
    "DomainRootAcl": Guidance(
        "acl",
        "Уберите у субъекта GenericAll, WriteDacl и WriteOwner на объекте домена (вкладка «Безопасность» → «Дополнительно» в «Пользователях и компьютерах» или dsacls) и верните владельцем Domain Admins. Такие права часто остаются после установки Exchange: обновите Exchange и выполните /PrepareAD с исправлением прав. Проверьте, не выдал ли себе субъект права репликации (находки DCSync).",
        (
            LEAST_PRIVILEGE,
            ("Microsoft: право DS-Replication-Get-Changes-All", f"{_LEARN}/windows/win32/adschema/r-ds-replication-get-changes-all"),
            _attack("T1222.001", "File and Directory Permissions Modification: Windows File and Directory Permissions Modification"),
        ),
    ),
    "PrimaryGroup": Guidance(
        "accounts",
        "Верните учётке стандартную первичную группу (Set-ADUser или Set-ADComputer -Replace @{primaryGroupID=513}; для компьютера 515, для контроллера 516) — прежде добавьте её в эту группу обычным членством. Выясните, кто и зачем менял primaryGroupID: так скрывают участника привилегированной группы.",
        (
            ("Microsoft: атрибут primaryGroupID", f"{_LEARN}/windows/win32/adschema/a-primarygroupid"),
            _attack("T1098", "Account Manipulation"),
        ),
    ),
    "SidHistory": Guidance(
        "accounts",
        "Если миграция завершена, очистите sIDHistory (Set-ADUser <учётка> -Remove @{sIDHistory='<SID>'}). SID своего домена или привилегированный SID в истории — признак атаки: расследуйте, кто записал атрибут, и смените пароль учётки. На внешних и лесных довериях держите включённой фильтрацию SID.",
        (
            ("Microsoft: атрибут sIDHistory", f"{_LEARN}/windows/win32/adschema/a-sidhistory"),
            _attack("T1134.005", "Access Token Manipulation: SID-History Injection"),
        ),
    ),
    "SmartcardPassword": Guidance(
        "accounts",
        "Поднимите функциональный уровень домена до Windows Server 2016 и включите смену NTLM-секретов учёток «только смарт-карта» (Центр администрирования AD → домен → «Enable rolling of expiring NTLM secrets…»). До этого периодически снимайте и заново ставьте флаг «Для входа требуется смарт-карта»: при этом AD генерирует новый случайный пароль.",
        (
            ("Microsoft: новое в AD DS Windows Server 2016 (смена NTLM-секретов)", f"{_LEARN}/windows-server/identity/whats-new-active-directory-domain-services"),
            _attack("T1550.002", "Use Alternate Authentication Material: Pass the Hash"),
        ),
    ),
    "UnixPasswords": Guidance(
        "accounts",
        "Очистите атрибуты userPassword и unixUserPassword (Set-ADUser <учётка> -Clear userPassword, unixUserPassword) и смените пароль учётки, если значение могло быть её паролем. Если Unix-системам нужна аутентификация, переведите их на Kerberos или LDAP bind.",
        (
            ("Microsoft: атрибут unixUserPassword", f"{_LEARN}/windows/win32/adschema/a-unixuserpassword"),
            _attack("T1552", "Unsecured Credentials"),
        ),
    ),
    "ComputerCreators": Guidance(
        "accounts",
        "Проверьте, кто создатель и нужны ли эти компьютеры; лишние удалите. Обнулите ms-DS-MachineAccountQuota и вводите машины в домен через делегированную группу с правом создания компьютеров в выделенной OU.",
        (
            ("Microsoft: атрибут ms-DS-CreatorSID", f"{_LEARN}/windows/win32/adschema/a-ms-ds-creatorsid"),
            ("Microsoft: ограничение числа компьютеров, которые пользователь вводит в домен", f"{_LEARN}/troubleshoot/windows-server/active-directory/default-workstation-numbers-join-domain"),
            _attack("T1136.002", "Create Account: Domain Account"),
        ),
    ),
    "LapsDeployment": Guidance(
        "domain",
        "Разверните Windows LAPS: расширьте схему (Update-LapsADSchema), выдайте компьютерам право записи пароля (Set-LapsADComputerSelfPermission) и включите политику LAPS групповой политикой на всех рабочих станциях и серверах. Для компьютеров из выборки проверьте, применяется ли политика.",
        (
            ("Microsoft: обзор Windows LAPS", f"{_LEARN}/windows-server/identity/laps/laps-overview"),
            ("Microsoft: Windows LAPS с Active Directory", f"{_LEARN}/windows-server/identity/laps/laps-scenarios-windows-server-active-directory"),
            _attack("T1078.003", "Valid Accounts: Local Accounts"),
        ),
    ),
    "PasswordPolicy": Guidance(
        "domain",
        "В Default Domain Policy и в каждой PSO задайте минимальную длину пароля не меньше порога (лучше 14), порог блокировки (например, 10 попыток), включите сложность и выключите обратимое шифрование. Если обратимое хранение было включено, смените пароли затронутых учёток. Порог длины задаётся в настройках.",
        (
            ("Microsoft: политика паролей", f"{_PREV}/password-policy"),
            ("Microsoft: порог блокировки учётной записи", f"{_PREV}/account-lockout-threshold"),
            ("Microsoft: хранение паролей с обратимым шифрованием", f"{_PREV}/store-passwords-using-reversible-encryption"),
            ("Microsoft: детализированные политики паролей (PSO)", f"{_LEARN}/windows-server/identity/ad-ds/get-started/adac/fine-grained-password-policies"),
            _attack("T1110", "Brute Force"),
        ),
    ),
    "RecycleBin": Guidance(
        "domain",
        "Включите корзину AD (Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target <лес>). Включение необратимо и требует функционального уровня леса Windows Server 2008 R2.",
        (
            ("Microsoft: включение корзины AD", f"{_LEARN}/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin"),
            ("Microsoft: Enable-ADOptionalFeature", f"{_LEARN}/powershell/module/activedirectory/enable-adoptionalfeature"),
        ),
    ),
    "DsHeuristics": Guidance(
        "domain",
        "Верните названные символы dSHeuristics (CN=Directory Service,CN=Windows NT,CN=Services в разделе конфигурации) в значение по умолчанию «0»: 7-й — запрет анонимных операций LDAP, 8-й — анонимного NSPI, 16-й — исключения операторов из AdminSDHolder, 21-й — проверки уникальности UPN и SPN, 28-й и 29-й — защиты KB5008383. Позиции 10 и 20 — контрольные, их не трогайте.",
        (
            ("Microsoft: атрибут dSHeuristics (MS-ADTS)", "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5"),
            ("Microsoft: KB5008383, обновление прав AD (CVE-2021-42291)", "https://support.microsoft.com/en-us/topic/kb5008383-active-directory-permissions-updates-cve-2021-42291-536d5555-ffba-4248-a60e-d6cbc849cde1"),
            _attack("T1087.002", "Account Discovery: Domain Account"),
        ),
    ),
    "BackupAge": Guidance(
        "domain",
        "Настройте регулярную резервную копию состояния системы хотя бы одного контроллера каждого домена (wbadmin start systemstatebackup или средство резервного копирования, поддерживающее AD) и проверяйте восстановление. Порог давности задаётся в настройках.",
        (
            ("Microsoft: восстановление леса AD — резервная копия сервера", f"{_LEARN}/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-backing-up-a-full-server"),
        ),
    ),
    "NtfrsSysvol": Guidance(
        "domain",
        "Переведите репликацию SYSVOL на DFSR утилитой dfsrmig (состояния Prepared → Redirected → Eliminated), проверяя репликацию на каждом шаге.",
        (
            ("Microsoft: миграция репликации SYSVOL с FRS на DFSR", f"{_LEARN}/windows-server/storage/dfs-replication/migrate-sysvol-to-dfsr"),
        ),
    ),
    "SchemaVulnerableClass": Guidance(
        "domain",
        "Установите актуальное накопительное обновление Exchange и выполните Setup /PrepareSchema (или /PrepareAD): обновление убирает computer из possSuperiors класса msExchStorageGroup. Если Exchange выведен, исправьте схему по инструкции Microsoft к CVE-2021-34470.",
        (
            ("Microsoft: CVE-2021-34470", "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34470"),
            _attack("T1068", "Exploitation for Privilege Escalation"),
        ),
    ),
    "TrustSecurity": Guidance(
        "trust",
        "Включите фильтрацию SID на внешнем доверии (netdom trust <наш домен> /domain:<партнёр> /quarantine:yes), снимите флаг «как внешнее» с лесного (/enablesidhistory:no) и выключите делегирование TGT (/EnableTGTDelegation:no). Доверие к домену Windows NT 4.0 и неработающие доверия удалите. Для доверия включите AES («Другой домен поддерживает шифрование Kerberos AES» в свойствах доверия). Порог давности задаётся в настройках.",
        (
            ("Microsoft: атрибут trustAttributes", f"{_LEARN}/windows/win32/adschema/a-trustattributes"),
            ("Microsoft: атрибут trustDirection", f"{_LEARN}/windows/win32/adschema/a-trustdirection"),
            ("Microsoft: атрибут trustType", f"{_LEARN}/windows/win32/adschema/a-trusttype"),
            _attack("T1134.005", "Access Token Manipulation: SID-History Injection"),
            _attack("T1482", "Domain Trust Discovery"),
        ),
    ),
    "DnsZones": Guidance(
        "domain",
        "Переведите зону на безопасные динамические обновления (Set-DnsServerPrimaryZone -Name <зона> -DynamicUpdate Secure). Право Authenticated Users создавать записи — настройка по умолчанию: если записи регистрирует DHCP, снимите его, а имена WPAD и ISATAP держите в глобальном списке блокировки запросов DNS.",
        (
            ("Microsoft: Set-DnsServerPrimaryZone", f"{_LEARN}/powershell/module/dnsserver/set-dnsserverprimaryzone"),
            ("Microsoft: класс dnsZone", f"{_LEARN}/windows/win32/adschema/c-dnszone"),
            _attack("T1557", "Adversary-in-the-Middle"),
        ),
    ),
    "RodcPasswordReplication": Guidance(
        "dc",
        "Уберите привилегированные группы и администраторов из списка разрешённого кэширования RODC (msDS-RevealOnDemandGroup) и добавьте в список запрета (msDS-NeverRevealGroup) Denied RODC Password Replication Group; закэшированным администраторам смените пароли. Верните в Denied RODC Password Replication Group Domain Admins, Enterprise Admins, Schema Admins, Domain Controllers и krbtgt, очистите Allowed RODC Password Replication Group и разрешайте кэширование группами конкретного филиала. Учётки krbtgt_NNNNN удалённых RODC удалите.",
        (
            ("Microsoft: Get-ADDomainControllerPasswordReplicationPolicy", f"{_LEARN}/powershell/module/activedirectory/get-addomaincontrollerpasswordreplicationpolicy"),
            ("Microsoft: Remove-ADDomainControllerPasswordReplicationPolicy", f"{_LEARN}/powershell/module/activedirectory/remove-addomaincontrollerpasswordreplicationpolicy"),
            ("Microsoft: атрибут msDS-RevealOnDemandGroup", f"{_LEARN}/windows/win32/adschema/a-msds-revealondemandgroup"),
            _attack("T1003", "OS Credential Dumping"),
        ),
    ),
    "CriticalObjectAcl": Guidance(
        "acl",
        "Уберите у субъекта права на объект (вкладка «Безопасность» → «Дополнительно» в «Пользователях и компьютерах» или dsacls): членство в привилегированной группе меняют только администраторы домена, сброс пароля и запись msDS-KeyCredentialLink администраторов не делегируются службе поддержки. Владельцем верните Domain Admins. Если право выдано на учётку с adminCount = 1, исправьте и AdminSDHolder, иначе SDProp вернёт его в течение часа.",
        (
            LEAST_PRIVILEGE,
            PROTECTED_ACCOUNTS,
            _attack("T1098", "Account Manipulation"),
            _attack("T1222.001", "File and Directory Permissions Modification: Windows File and Directory Permissions Modification"),
        ),
    ),
    "BadSuccessor": Guidance(
        "acl",
        "Уберите у субъекта право создавать объекты в OU (CreateChild для всех объектов или для msDS-DelegatedManagedServiceAccount) и GenericAll на OU; делегируйте создание только нужных классов объектов. Установите на контроллеры Windows Server 2025 обновления безопасности с августа 2025 года (CVE-2025-53779). Проверьте существующие dMSA: атрибут msDS-ManagedAccountPrecededByLink не должен указывать на привилегированные учётки.",
        (
            ("Microsoft: делегированные управляемые учётные записи служб (dMSA)", f"{_LEARN}/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview"),
            ("Microsoft: CVE-2025-53779", "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779"),
            _attack("T1098", "Account Manipulation"),
        ),
    ),
    "GppPasswords": Guidance(
        "gpo",
        "Удалите из GPO настройку с паролем (GPP «Локальные пользователи и группы», «Задания», «Службы», «Источники данных», «Подключённые диски») или параметр DefaultPassword автологона и смените этот пароль везде, где он использовался: значение уже известно любому пользователю домена. Для паролей локальных администраторов используйте LAPS, для служб — gMSA.",
        (
            ("Microsoft: MS14-025, пароли в настройках групповой политики", f"{_LEARN}/security-updates/securitybulletins/2014/ms14-025"),
            _attack("T1552.006", "Unsecured Credentials: Group Policy Preferences"),
        ),
    ),
    "GpoSecurityOptions": Guidance(
        "gpo",
        "В GPO из находки (Конфигурация компьютера → Политики → Конфигурация Windows → Параметры безопасности → Локальные политики → Параметры безопасности) задайте безопасные значения: уровень проверки подлинности LAN Manager «Отправлять только NTLMv2, отказывать LM и NTLM» (5) на контроллерах, не хранить хэш LM, запретить анонимное перечисление и права Everyone для анонимных, ограничить пустые пароли входом с консоли, требовать подписи LDAP на контроллерах, разрешить смену паролей компьютерных учёток, выключить автоматический вход в консоль восстановления, выключить обратимое хранение паролей. Перед режимом «только NTLMv2» проверьте аудитом NTLM, что старые клиенты не используют LM и NTLMv1.",
        (
            ("Microsoft: уровень проверки подлинности LAN Manager", f"{_PREV}/network-security-lan-manager-authentication-level"),
            ("Microsoft: не хранить хэш LAN Manager", f"{_PREV}/network-security-do-not-store-lan-manager-hash-value-on-next-password-change"),
            ("Microsoft: права Everyone для анонимных пользователей", f"{_PREV}/network-access-let-everyone-permissions-apply-to-anonymous-users"),
            ("Microsoft: требования к подписи LDAP на контроллере", f"{_PREV}/domain-controller-ldap-server-signing-requirements"),
            ("Microsoft: обратимое шифрование паролей", f"{_PREV}/store-passwords-using-reversible-encryption"),
            _attack("T1557.001", "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay"),
            _attack("T1003", "OS Credential Dumping"),
            _attack("T1087.002", "Account Discovery: Domain Account"),
        ),
    ),
    "DcLogonRights": Guidance(
        "gpo",
        "В GPO, применимой к контроллерам, оставьте права «Локальный вход в систему», «Разрешить вход через службу удалённых рабочих столов» и «Вход в качестве пакетного задания» только Administrators и, если нужно, операторам (Backup, Server, Account Operators); широкие группы из этих прав удалите.",
        (
            ("Microsoft: локальный вход в систему", f"{_PREV}/allow-log-on-locally"),
            ("Microsoft: вход через службу удалённых рабочих столов", f"{_PREV}/allow-log-on-through-remote-desktop-services"),
            ("Microsoft: вход в качестве пакетного задания", f"{_PREV}/log-on-as-a-batch-job"),
            _attack("T1078.002", "Valid Accounts: Domain Accounts"),
        ),
    ),
    "TieringLogonDeny": Guidance(
        "gpo",
        "Создайте GPO для рабочих станций и рядовых серверов (не для контроллеров) с правами «Запретить локальный вход» и «Запретить вход через службу удалённых рабочих столов» для Domain Admins (и Enterprise Admins, Schema Admins): администраторы домена должны входить только на контроллеры и выделенные административные станции.",
        (
            ("Microsoft: защита группы Domain Admins", f"{_LEARN}/windows-server/identity/ad-ds/plan/security-best-practices/appendix-f--securing-domain-admins-groups-in-active-directory"),
            ("Microsoft: запретить локальный вход", f"{_PREV}/deny-log-on-locally"),
            _attack("T1078.002", "Valid Accounts: Domain Accounts"),
        ),
    ),
    "RestrictedGroups": Guidance(
        "gpo",
        "Уберите широкую группу из Restricted Groups (Конфигурация компьютера → Политики → Конфигурация Windows → Параметры безопасности → Группы с ограниченным доступом) или из настройки GPP «Локальные пользователи и группы» и добавляйте в локальные группы только выделенные группы администраторов этих компьютеров.",
        (
            LEAST_PRIVILEGE,
            _attack("T1098", "Account Manipulation"),
        ),
    ),
}
