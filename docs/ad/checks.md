# Проверки модуля Active Directory

Версия анализатора — 3. Реестр — `backend/api/modules/ad/core/checks/__init__.py`, «Как исправить» и
ссылки — `checks/catalog.py`, пороги и списки — настройки правил (Active Directory → Настройки и
данные → «Правила проверок»).

Общие правила:

- **Админ** — включённый пользователь, рекурсивный член групп из `admin_rids` (512, 518, 519, 544), и
  включённая учётка RID 500.
- **Безопасный субъект** ACL — SID из `adcs_safe_sids` или RID из `tier0_safe_rids` доменов своего леса;
  остальные делятся на **широких** (`low_priv_*`: Everyone, Authenticated Users, Users, Domain Users,
  Domain Computers) и **прочих**. «Широкий / прочий» в колонке серьёзности — серьёзность для каждого.
- Находка, у которой субъект в allowlist (`allowlist_short`, `allowlist_full`), понижается до Low и
  помечается; у находок уровня домена (без субъекта) allowlist не действует.
- Если в выгрузке нет данных для проверки, обзор показывает её как «Не проверено» с причиной, а не
  «Без находок».

Колонка «PingCastle» — ближайшее правило PingCastle; «—» — соответствия нет или оно не сопоставлялось.

## Учётные записи — `accounts`

| Код | Условие | Серьёзность | Данные | PingCastle |
|---|---|---|---|---|
| `PasswordNeverExpires` | включённый пользователь с «пароль не истекает» | Low; админ High | `uac` | — |
| `InactiveUsers` | включённый пользователь без входа дольше `user_inactivity_days` (90); без входов вообще — если создан раньше порога | Low; админ High | `uac`, `lastLogonTimestamp`, `whenCreated` | — |
| `PasswordNotRequired` | включённая учётка (пользователь, компьютер) с флагом «пароль не требуется» | Medium; админ High | `uac` | S-PwdNotRequired |
| `ReversiblePassword` | включённая учётка с обратимым шифрованием пароля | Medium | `uac` | S-Reversible, S-C-Reversible |
| `DuplicateObjects` | `CNF:` в DN или `sAMAccountName` начинается с `$DUPLICATE-` | Low | DN, `sAMAccountName` | S-Duplicate |
| `InactiveComputers` | включённый компьютер без входа дольше `computer_inactivity_days` (90) | Low; контроллер High | `uac`, `lastLogonTimestamp` | S-C-Inactive, S-DC-Inactive |
| `ComputerPasswordAge` | включённый компьютер входил за 45 дней, пароль старше `computer_password_max_age_days` (90); у контроллера — старше 45 | Low; контроллер Medium | `uac`, `lastLogonTimestamp`, `pwdLastSet` | S-PwdLastSet-45, -90, -DC |
| `PrimaryGroup` | пользователь с `primaryGroupID` не 513 (Guest — 514); компьютер не 515, контроллер не 516, RODC не 521 | Medium | `primaryGroupID`, `uac` | S-PrimaryGroup, S-C-PrimaryGroup |
| `SidHistory` | SID в `sIDHistory`, по виду (`key_extra` — сам SID): `same_domain` своего домена; `privileged` RID < 1000 или `S-1-5-32-*`; `unknown_domain` домена нет среди доверий; `other` | Critical; High; Medium; Low | `sIDHistory`, доверия | T-SIDHistorySameDomain, T-SIDHistoryDangerous, T-SIDHistoryUnknownDomain, S-SIDHistory |
| `SmartcardPassword` | домен не меняет пароли учёток «только смарт-карта» (`smartcard_rotation = false`): включённый пользователь с `0x40000`, пароль старше `smartcard_password_max_age_days` (90) | Medium; админ High | `uac`, `pwdLastSet`, `msDS-ExpirePasswordsOnSmartCardOnlyAccounts` | A-SmartCardRequired, A-SmartCardPwdRotation |
| `UnixPasswords` | заполнен `userPassword` или `unixUserPassword` (значения не читаются) | Medium | `hasUnixPassword` | A-UnixPwd |
| `ComputerCreators` | компьютеры с `ms-DS-CreatorSID`, создатель не админ и не безопасный субъект; одна находка на создателя со счётчиком и выборкой | Low | `creatorSid` | A-LAPS-Joined-Computers |
| `ObsoleteOs` | активный компьютер с ОС вне поддержки (NT/2000/XP/2003 — High; Vista/7/8/2008/2012 и Windows 10 кроме LTSC/IoT — Medium; сборка из `obsolete_os_builds` после даты окончания — Low) | по ОС; контроллер на ступень выше | `operatingSystem`, `operatingSystemVersion`, `lastLogonTimestamp` | S-OS-*, S-DC-* |

## Привилегированные учётные записи — `privileged`

| Код | Условие | Серьёзность | Данные | PingCastle |
|---|---|---|---|---|
| `PrivilegedGroups` | рекурсивный член привилегированной группы (`privileged_rids`: 13 групп, и имена из `privileged_groups`, в том числе DnsAdmins) | Medium | `member` | — |
| `ProtectedUsersCoverage` | пользователь из привилегированной группы не в Protected Users | Medium | `member` | — |
| `AdminCount` | `adminCount=1` у объекта вне защищённых групп — след прежних привилегий | Medium | `adminCount`, `member` | — |
| `AdminDelegable` | админ без «учётная запись важна и не может быть делегирована» и не в Protected Users | Medium | `uac`, `member` | P-Delegated |
| `AdminPasswordAge` | пароль админа старше `admin_password_max_age_days` (1095) | Medium | `pwdLastSet`, `member` | P-AdminPwdTooOld |
| `BuiltinAdminUsed` | учётка RID 500 входила за последние `builtin_admin_recent_days` (35) | Medium | `lastLogonTimestamp` | P-AdminLogin |
| `GuestEnabled` | учётка RID 501 включена | High | `uac` | A-Guest |
| `TooManyAdmins` | админов больше `admins_max` (20); одна находка на домен со списком до 20 имён | Medium | `member`, `uac` | P-AdminNum |

## Kerberos и делегирование — `kerberos`

| Код | Условие | Серьёзность | Данные | PingCastle |
|---|---|---|---|---|
| `Delegation` | неограниченная или ограниченная делегация (в том числе protocol transition) у пользователя или компьютера, кроме контроллеров | High неограниченная; Medium ограниченная | `uac`, `msDS-AllowedToDelegateTo` | — |
| `RBCD` | у компьютера задан `msDS-AllowedToActOnBehalfOfOtherIdentity` | High; контроллер Critical | `msDS-AllowedToActOnBehalfOfOtherIdentity` | — |
| `ASREP` | включённый пользователь без Kerberos preauth | High; админ Critical | `uac` | — |
| `Kerberoast` | включённый пользователь с SPN, кроме krbtgt | Medium; админ High | `servicePrincipalName` | — |
| `KrbtgtPasswordAge` | пароль krbtgt старше `krbtgt_max_age_days` (180) | High; иначе Low | `pwdLastSet` krbtgt | — |
| `WeakEncryption` | у пользователя или компьютера RC4 в `msDS-SupportedEncryptionTypes` или флаг «только DES» | Medium, если AES тоже разрешён; иначе High | `msDS-SupportedEncryptionTypes`, `uac` | — |

## Права на объекты — `acl`

| Код | Условие | Серьёзность | Данные | PingCastle |
|---|---|---|---|---|
| `DCSync` | права репликации каталога на корне домена | Critical (Get-Changes-All); High (прочие) | ACL корня домена | — |
| `ShadowAdmins` | опасные права на AdminSDHolder | High | ACL AdminSDHolder | — |
| `KeyCredentialLinkACL` | право записи `msDS-KeyCredentialLink` (Shadow Credentials) | High | ACL учёток | — |
| `SensitiveAcl` | опасные права на OU и компьютерах; унаследованные и массовые сворачиваются | High | ACL OU и компьютеров | — |
| `GpoPermissions` | опасные права на объекты GPO | High | ACL GPO | — |
| `DomainRootAcl` | небезопасный субъект с GenericAll, WriteDacl или WriteOwner на корне домена (ACE действует на сам корень) или владелец корня | Critical широкий / High прочий | ACL корня домена | P-ExchangePrivEsc |

## Групповые политики — `gpo`

| Код | Условие | Серьёзность | Данные | PingCastle |
|---|---|---|---|---|
| `UserRightsAssignment` | опасное право из `user_rights` назначено в GPO | по настройке `user_rights` | `GptTmpl.inf` из SYSVOL | — |

## Контроллеры домена — `dc`

| Код | Условие | Серьёзность | Данные | PingCastle |
|---|---|---|---|---|
| `DcCount` | в домене один контроллер | Low | `uac` компьютеров | A-NotEnoughDC |
| `DcDelegation` | контроллер с `msDS-AllowedToDelegateTo` или protocol transition | High | `uac`, `msDS-AllowedToDelegateTo` | P-DelegationDCa2d2, P-DelegationDCt2a4d |
| `DcOwner` | владелец объекта контроллера — небезопасный субъект | Medium | ACL контроллеров | P-DCOwner |

## Настройки домена и леса — `domain`

| Код | Условие | Серьёзность | Данные | PingCastle |
|---|---|---|---|---|
| `MachineAccountQuota` | `ms-DS-MachineAccountQuota` больше 0 | Medium; 0 — Low | атрибут корня домена | — |
| `FunctionalLevel` | функциональный уровень домена, отдельной находкой (`key_extra = forest`) — леса, ниже Windows Server 2016 | Medium ниже 2008 R2; 2008 R2–2012 R2 Low | `msDS-Behavior-Version` домена и леса | S-FunctionalLevel1, 3, 4 |
| `PasswordPolicy` | политика домена и каждая PSO, по виду: `min_length` длина < `password_min_length` (8); `no_lockout` порог блокировки 0; `reversible` обратимое хранение; `no_complexity` сложность выключена | Medium; Medium; High; Low | `minPwdLength`, `lockoutThreshold`, `pwdProperties`, PSO | A-MinPwdLen, A-ReversiblePwd |
| `LapsDeployment` | `not_installed`: в схеме нет атрибутов LAPS; `coverage`: у включённых компьютеров Windows (или без ОС), входивших за `computer_inactivity_days`, не контроллеров, нет срока пароля LAPS — одна находка со счётчиком, долей и выборкой | Medium; `coverage` Low при доле ≤ 10 %, иначе Medium | схема, `lapsExpiry`, `lapsNewExpiry` | A-LAPS-Not-Installed |
| `RecycleBin` | корзина AD выключена | Low | `msDS-EnabledFeatureBL` | P-RecycleBin |
| `DsHeuristics` | символ `dSHeuristics` (позиции с единицы), по виду: `anonymous` 7-й `2`; `anon_nspi` 8-й не `0`; `adminsdex` 16-й не `0`; `uniqueness` 21-й не `0`; `ldap_authz` 28-й или 29-й `2` (защита KB5008383 выключена явно); `list_object` 3-й `1` | High; Medium; Medium; Medium; Medium; Info | `dSHeuristics` | A-DsHeuristicsAnonymous, -AllowAnonNSPI, P-DsHeuristicsAdminSDExMask, A-DsHeuristicsDoNotVerifyUniqueness, -LDAPSecurity, P-DsHeuristicsDoListObject |
| `BackupAge` | последний бэкап (`dSASignature` корня) старше `backup_max_age_days` (7) или отметки нет | Medium | `msDS-ReplAttributeMetaData` корня | A-BackupMetadata |
| `NtfrsSysvol` | SYSVOL реплицируется через FRS | Low | DFSR-GlobalSettings | A-NTFRSOnSysvol |
| `SchemaVulnerableClass` | `possSuperiors` класса `msExchStorageGroup` содержит `computer` (CVE-2021-34470) | Medium | схема | S-ADRegistrationSchema |
| `PreWin2000Access` | член группы Pre-Windows 2000 Compatible Access (`S-1-5-32-554`) | High Anonymous Logon и Everyone; Authenticated Users и прочие Low | `member` группы | A-PreWin2000Anonymous, -AuthenticatedUsers, -Other |

## Доверие — `trust`

| Код | Условие | Серьёзность | Данные | PingCastle |
|---|---|---|---|---|
| `AzureSsoKeyAge` | пароль компьютера `AZUREADSSOACC` старше `azure_sso_key_max_age_days` (90) | Medium | `pwdLastSet` | T-AzureADSSO |

## AD CS и сертификаты — `pki`

| Код | Условие | Серьёзность | Данные | PingCastle |
|---|---|---|---|---|
| `ADCS_ESC` | шаблон, по которому небезопасный заявитель выпускает сертификат для входа от чужого имени или меняет шаблон (ESC1–4, 9, 13, 15) | по ESC; широкий заявитель — базовая, прочий — на ступень ниже; неопубликованный шаблон Low | шаблоны сертификатов, ЦС | — |
| `ADCS_CA` | права на объекты PKI и ЦС, настройки ЦС и веб-выдачи (ESC5–8, 11, 16) | по ESC | объекты PKI, данные ЦС (`stools-ad-ca/1`) | — |
| `ADCS_MAPPING` | слабая привязка сертификатов на контроллерах и слабые `altSecurityIdentities` (ESC10, 14) | по ESC | реестр контроллеров (данные ЦС), `altSecurityIdentities` | — |

## Инвентарь — `inventory`

| Код | Условие | Серьёзность | Данные | PingCastle |
|---|---|---|---|---|
| `Clusters` | компьютер с SPN `MSServerCluster` — учётка кластера; `MSClusterVirtualServer` без него — роль (кластер по `ms-DS-CreatorSID`, выключенная помечается как брошенная); `MSServerClusterMgmtAPI` без обоих — узел; узлы к кластеру не привязываются | Info | `servicePrincipalName`, `ms-DS-CreatorSID`, `uac`, ОС | — |
