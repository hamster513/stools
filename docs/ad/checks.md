# Проверки модуля Active Directory

Версия анализатора — 8. Реестр — `backend/api/modules/ad/core/checks/__init__.py`, «Как исправить» и
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
| `CriticalObjectAcl` | на критичном объекте (группы 512, 517, 518, 519, 520, 526, 527, 571 домена, 544, 548–552 встроенные, `DnsAdmins` и `privileged_groups` по имени, их рекурсивные участники-пользователи и вложенные группы, учётки RID 500 и 502) у небезопасного субъекта разрешающая ACE (не inherit-only; SELF и CREATOR OWNER не в счёт) с GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty без типа, записью `member` или AddSelf (у групп), записью `msDS-KeyCredentialLink` (у пользователей), всеми расширенными правами, сбросом пароля (у пользователей), либо он владелец. Субъект — сама критичная группа (связь внутри tier 0) — не в счёт. Группы из `privileged_groups` сверх списков RID проверяются, только если сборщик прочитал их дескрипторы, а он читает фиксированный список. У объекта с `adminCount = 1` ACE, совпадающие с AdminSDHolder (SID, маска, тип), пропускаются. Полный доступ (0xF01FF) показывается одним GenericAll. Одна находка на пару «объект × субъект», в `details.effective_principals` — число фактических участников субъекта | Critical широкий / High прочий; прочий с участниками > `control_path_many` (100) — как широкий | `sd` критичных объектов (`collector.critical_acl`) | P-ControlPathIndirectEveryone, P-ControlPathIndirectMany, P-DelegationKeyAdmin |
| `BadSuccessor` | класс dMSA есть в схеме (`guids.schema_classes`); у небезопасного субъекта явная (не унаследованная) разрешающая ACE на OU: CreateChild без типа или для dMSA, либо GenericAll (полный доступ); inherit-only — только если наследуется на все объекты, OU или контейнеры | High широкий / Medium прочий, если есть контроллер с «2025» в ОС; иначе Low | `sd` OU, класс dMSA, ОС контроллеров | A-BadSuccessor |

## Групповые политики — `gpo`

| Код | Условие | Серьёзность | Данные | PingCastle |
|---|---|---|---|---|
| `UserRightsAssignment` | опасное право из `user_rights` назначено в GPO (по умолчанию SeEnableDelegation, SeDebug, SeTcb — High; SeBackup, SeRestore, SeTrustedCredManAccess — Medium) | по настройке `user_rights` | `GptTmpl.inf` из SYSVOL | P-TrustedCredManAccessPrivilege |
| `GppPasswords` | запись GPP с `cpassword` (`key_extra` — `<часть>\|<файл>\|<имя>`, субъект — учётка записи, allowlist не действует; GPO с выключенной компьютерной частью тоже проверяется — файл читается из SYSVOL); значение `DefaultPassword` автологона в `Registry.pol` (`autologon`) | High | блок `gpo`: `gpp`, `registry` | A-PwdGPO |
| `GpoSecurityOptions` | по виду, из `[Registry Values]` `GptTmpl.inf` и `Registry.pol` (INF важнее): `ntlm_level` `LmCompatibilityLevel` < 3; `lm_hash` `NoLMHash` = 0; `anonymous` `EveryoneIncludesAnonymous` = 1 или `RestrictAnonymous` = 0; `blank_password` `LimitBlankPasswordUse` = 0; `ldap_signing` `NTDS\Parameters\LDAPServerIntegrity` = 1; `refuse_pwd_change` `Netlogon\Parameters\RefusePasswordChange` = 1; `recovery_console` `Setup\RecoveryConsole\SecurityLevel` = 1; `cleartext_password` `[System Access] ClearTextPassword` = 1; `ntlm_level_missing` — ни одна GPO, применимая к контроллерам, не задаёт `LmCompatibilityLevel` = 5 (одна находка на домен, цель — DN домена) | High; Medium; Medium; Medium; Medium; Low; Medium; High; Medium | `GptTmpl.inf`, блок `gpo`, `gpLink` | S-OldNtlm, A-LMHashAuthorized, A-AnonymousAuthorizedGPO, A-LimitBlankPasswordUse, A-LDAPSigningDisabled, A-DCRefuseComputerPwdChange, P-RecoveryModeUnprotected, A-ReversiblePwd |
| `DcLogonRights` | в GPO, применимой к контроллерам, `SeInteractiveLogonRight`, `SeRemoteInteractiveLogonRight` или `SeBatchLogonRight` у широкой группы | High | `GptTmpl.inf`, `gpLink` | P-LoginDCEveryone |
| `TieringLogonDeny` | ни в одной GPO нет `SeDenyInteractiveLogonRight` или `SeDenyRemoteInteractiveLogonRight` с Domain Admins (SID или имя); одна находка на домен | Low | `GptTmpl.inf` | P-LogonDenied |
| `RestrictedGroups` | широкая группа добавляется в локальную встроенную группу (`S-1-5-32-*`): `[Group Membership]` `…__Members` и `…__Memberof` (у `Memberof` субъект — сама группа строки, записи — группы, куда она входит; `key_extra` `inf\|<SID группы>`) или GPP `Groups` (элемент не «D», участник `ADD`; `gpp\|<SID группы>`) | High в Administrators (`S-1-5-32-544`); иначе Medium | `GptTmpl.inf`, блок `gpo`: `gpp` | A-MembershipEveryone |
| `GpoRegistrySettings` | по виду, из `Registry.pol` (ключи и имена значений без учёта регистра): `llmnr` — GPO с `DNSClient\EnableMultiCast` = 1 (цель — GPO) или ни одна привязанная GPO не задаёт 0 (цель — DN домена); `hardened_paths` — значение `NetworkProvider\HardenedPaths` для пути, оканчивающегося на `\SYSVOL` или `\NETLOGON`, с `RequireMutualAuthentication=0` или `RequireIntegrity=0`; `wsus_http` — `WindowsUpdate\WUServer` начинается с `http://`; `wsus_user_proxy` — `SetProxyBehaviorForUpdateDetection` = 1; `wsus_no_pinning` — `DoNotEnforceEnterpriseTLSCertPinningForUpdateDetection` = 1; `ps_logging` — ни одна привязанная GPO (компьютерная или пользовательская часть) не задаёт `ScriptBlockLogging\EnableScriptBlockLogging` = 1 (цель — DN домена) | Low; Medium; Medium; Low; Low; Low | блок `gpo`: `registry`, `gpLink` | A-NoGPOLLMNR, A-HardenedPaths, S-WSUS-HTTP, S-WSUS-UserProxy, S-WSUS-NoPinning, A-AuditPowershell |
| `DcAuditPolicy` | ни в одной GPO, применимой к контроллерам, нет аудита успеха (`setting & 1` в `audit.csv`) для подкатегории из 15 (спека §3.2: проверка учётных данных, Kerberos AS и TGS, управление учётками пользователей и компьютеров и группами, изменения каталога, вход, специальный вход, создание процесса, расширение системы безопасности, использование важных привилегий, изменение политики аудита и проверки подлинности, DPAPI); одна находка на подкатегорию, цель — DN домена, `key_extra` — GUID | Medium | блок `gpo`: `audit`, `gpLink` | A-AuditDC |
| `GpoExternalFiles` | UNC-путь, сервер которого не домен (`dns_root`, NetBIOS) и не контроллер (FQDN или короткое имя): команда сценария GPO (`scripts.ini`, `psscripts.ini`), источник GPP `Files` (цель — GPO; запись пропускается, если её часть GPO — пользовательская или компьютерная — выключена), `scriptPath` учётки (цель — DN учётки); `key_extra` — путь, allowlist не действует | Medium | блок `gpo`: `scripts`, `gpp`; `scriptPath` | T-ScriptOutOfDomain, T-FileDeployedOutOfDomain |
| `SysvolAcl` | субъект, не безопасный по `tier0_safe_rids` и `adcs_safe_sids`, может писать в папку GPO (`key_extra` пустой) или в файл её сценария (`key_extra` — путь внутри папки GPO); одна находка на субъект и путь, право `write`; проверяются все GPO | Critical для широкой группы; иначе High | блок `gpo`: `acl` (только PowerShell-сборщик) | P-DelegationGPOData, P-DelegationLoginScript, P-DelegationFileDeployed |

Проверки GPO по файлам SYSVOL, кроме `GppPasswords`, `GpoExternalFiles` и `SysvolAcl`, пропускают GPO с выключенной компьютерной частью (`flags & 2`); в описании находки — куда привязана GPO. Применимость к контроллерам — включённая ссылка на корень домена или на предка контроллера; если в выгрузке нет `gpLink` (сборщик старой версии), GPO считается применимой, а обзор приписывает «привязка GPO неизвестна» у `GpoSecurityOptions`, `DcLogonRights`, `DcAuditPolicy`. Без блока `gpo` не проверены `GppPasswords`, `GpoRegistrySettings`, `DcAuditPolicy`, `GpoExternalFiles`, `SysvolAcl`, и находки на домен (`llmnr`, `ps_logging`, `DcAuditPolicy`) не выдаются; без SYSVOL и блока `gpo` — также `GpoSecurityOptions`, `DcLogonRights`, `RestrictedGroups`, и `ntlm_level_missing` не выдаётся; без `GptTmpl.inf` (SYSVOL) не проверены `DcLogonRights` и `TieringLogonDeny` (последняя не выдаётся). Если `acl` нет ни у одной GPO (LDAP-сборщик), `SysvolAcl` не проверена: «права на SYSVOL читает только PowerShell-сборщик».

## Контроллеры домена — `dc`

| Код | Условие | Серьёзность | Данные | PingCastle |
|---|---|---|---|---|
| `DcCount` | в домене один контроллер | Low | `uac` компьютеров | A-NotEnoughDC |
| `DcDelegation` | контроллер с `msDS-AllowedToDelegateTo` или protocol transition | High | `uac`, `msDS-AllowedToDelegateTo` | P-DelegationDCa2d2, P-DelegationDCt2a4d |
| `DcOwner` | владелец объекта контроллера — небезопасный субъект | Medium | ACL контроллеров | P-DCOwner |
| `DcHardening` | по виду, на пару «контроллер × вид» (цель — `host`, `key_extra` — вид): `ntlmv1` — `lm_compatibility` (нет значения — 3) < 3 или 3–4; `lm_hash` — `no_lm_hash` = 0; `ldap_signing` — `ldap_integrity` (нет значения — 1) ≠ 2; `channel_binding` — `ldap_channel_binding` (нет значения — 0) = 0 или 1; `smb1` — SMBv1 включён; `smb_signing` — `smb_require_signing` = false; `spooler`, `webclient` — служба `running`; `uptime` — `last_boot` старше `dc_max_uptime_days` (180) на дату выгрузки; `tls_old` — у SSL 3.0, TLS 1.0 или TLS 1.1 `Enabled` задан и ≠ 0. Значение по умолчанию подставляется только при `registry_read`; в `details` — фактическое значение, `default` (подставлено ли) и дата сбора раздела; allowlist не действует | `ntlmv1` High (< 3) или Medium (3–4); `lm_hash` Medium; `ldap_signing` Medium; `channel_binding` Medium (0) или Low (1); `smb1` High; `smb_signing` High; `spooler` Medium; `webclient` Low; `uptime` Medium; `tls_old` Low | данные ЦС, раздел `dc` (сборщик 2.3, пункт 6) | S-OldNtlm, A-LMHashAuthorized, A-DCLdapSign, A-DCLdapsChannelBinding, S-SMB-v1, A-SMB2SignatureNotRequired, A-DC-Spooler, A-DC-WebClient, S-DC-NotUpdated, A-DCLdapsProtocol |
| `RodcPasswordReplication` | по виду: `reveal_privileged` привилегированная группа или админ в `revealOnDemand` RODC; `never_reveal_missing` в `neverReveal` нет группы 572; `admin_revealed` админ в `revealedUsers`; `krbtgt_orphan` учётка `krbtgt_NNNNN` не связана ни с одним RODC (`krbTgtLink`); при наличии RODC — `allowed_group_not_empty` в группе 571 есть члены (находка на члена), `denied_group_incomplete` в группе 572 (с вложенными) нет 512, 518, 519, 516 или 502 из тех, что есть в выгрузке | Medium | `uac`, `msDS-RevealOnDemandGroup`, `msDS-NeverRevealGroup`, `msDS-RevealedUsers`, `msDS-KrbTgtLink`, `member` | P-RODC* |

Без раздела `dc` в данных ЦС `DcHardening` не проверена — в том числе в домене без AD CS. По контроллеру причина «не проверено» — по каналу (реестр не прочитан; службы и SMB не прочитаны) или, если CIM отработал, по его части: SMB, службы, время загрузки. Виды этой части у контроллера тогда не выдаются.

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
| `DnsZones` | зона DNS (кроме `RootDNSServers`, `..TrustAnchors`), по виду: `insecure_update` `allowUpdate = 1` (небезопасные обновления); `au_create` Authenticated Users могут создавать записи (ACE не только для наследования) | High для зоны домена и `_msdcs.*`, прочая Medium; Info | `dNSProperty` (`allowUpdate`), ACL зоны | A-DnsZoneUpdate1, -2, A-DnsZoneAUCreateChild |
| `PreWin2000Access` | член группы Pre-Windows 2000 Compatible Access (`S-1-5-32-554`) | High Anonymous Logon и Everyone; Authenticated Users и прочие Low | `member` группы | A-PreWin2000Anonymous, -AuthenticatedUsers, -Other |

## Доверие — `trust`

| Код | Условие | Серьёзность | Данные | PingCastle |
|---|---|---|---|---|
| `AzureSsoKeyAge` | пароль компьютера `AZUREADSSOACC` старше `azure_sso_key_max_age_days` (90) | Medium | `pwdLastSet` | T-AzureADSSO |
| `TrustSecurity` | объект доверия, по виду: `sid_filtering` исходящее доверие (`trustDirection & 2`) вне своего леса, внешнее без карантина (`0x4`) либо лесное (`0x8`) с «как внешнее» (`0x40`); `downlevel` `trustType = 1` (NT 4.0); `tgt_delegation` лесное с `0x800`; `inactive` `whenChanged` старше `trust_inactive_days` (40); `no_aes` нет AES (`0x18`) в `supportedEncryptionTypes`; доверия своего леса (`0x20`) проверяются только на `downlevel` и `inactive` | High; High; Medium; Medium; Low | `trustAttributes`, `trustDirection`, `trustType`, `whenChanged`, `msDS-SupportedEncryptionTypes` | T-SIDFiltering, T-Downlevel, T-TGTDelegation, T-Inactive, T-AlgsAES |

## AD CS и сертификаты — `pki`

| Код | Условие | Серьёзность | Данные | PingCastle |
|---|---|---|---|---|
| `ADCS_ESC` | шаблон, по которому небезопасный заявитель выпускает сертификат для входа от чужого имени или меняет шаблон (ESC1–4, 9, 13, 15) | по ESC; широкий заявитель — базовая, прочий — на ступень ниже; неопубликованный шаблон Low | шаблоны сертификатов, ЦС | — |
| `ADCS_CA` | права на объекты PKI и ЦС, настройки ЦС и веб-выдачи (ESC5–8, 11, 16) | по ESC | объекты PKI, данные ЦС (`stools-ad-ca/1`) | — |
| `ADCS_MAPPING` | слабая привязка сертификатов на контроллерах и слабые `altSecurityIdentities` (ESC10, 14) | по ESC | реестр контроллеров (данные ЦС), `altSecurityIdentities` | — |
| `CertificateStrength` | сертификат ЦС в AD, по виду: `rsa_weak` модуль RSA < 1024 бит или 1024–2047; `rsa_exponent` экспонента < 65537; `hash` подпись MD2, MD4, MD5 или SHA-1 (по OID алгоритма подписи, в том числе OIW); `dsa` ключ DSA; `roca` модуль проходит тест отпечатка ROCA (остаток по каждому простому 3…167 — степень 65537). Корневой — самоподписанный сертификат в любом хранилище; иначе хранилище первого держателя (`root` — `CN=Certification Authorities`, `intermediate` — `CN=AIA`), у ЦС выдачи и `NTAuthCertificates` — промежуточный. Просроченные на дату выгрузки и неразборчивые сертификаты пропускаются. Одна находка на пару «сертификат × вид» по всей выгрузке: цель — DN первого держателя (корневое хранилище, AIA, NTAuth, ЦС выдачи; внутри — по DN), в `details.holders` — все держатели, субъект — субъект сертификата (RFC 4514), `key_extra` — `<вид>|<SHA-256, первые 16 символов>`; allowlist не действует | `rsa_weak` High (< 1024) или Low; `rsa_exponent` Low; `hash` MD* High, SHA-1 Low, у корневого Info; `dsa` Info; `roca` High | `cACertificate` у `pKIEnrollmentService`, `CN=NTAuthCertificates` и `certificationAuthority` (LDAP-сборщик 1.3, PowerShell 2.4) | A-WeakRSARootCert, A-WeakRSARootCert2, A-CertWeakRsaComponent, A-MD*IntermediateCert, A-MD*RootCert, A-SHA1IntermediateCert, A-SHA1RootCert, A-CertWeakDSA, A-CertROCA |

В домене с AD CS (есть шаблоны или ЦС выдачи) `CertificateStrength` не проверена, если `cACertificate` нет ни у одного объекта выгрузки: «сертификаты ЦС не собраны (сборщик старой версии)».

## Инвентарь — `inventory`

| Код | Условие | Серьёзность | Данные | PingCastle |
|---|---|---|---|---|
| `Clusters` | компьютер с SPN `MSServerCluster` — учётка кластера; `MSClusterVirtualServer` без него — роль (кластер по `ms-DS-CreatorSID`, выключенная помечается как брошенная); `MSServerClusterMgmtAPI` без обоих — узел; узлы к кластеру не привязываются | Info | `servicePrincipalName`, `ms-DS-CreatorSID`, `uac`, ОС | — |
