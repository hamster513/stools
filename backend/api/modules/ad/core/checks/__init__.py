"""Реестр проверок: код, название, описание из прототипа, функция."""
from __future__ import annotations

from api.modules.ad.core.checks.account_flags import (
    check_admin_delegable,
    check_admin_password_age,
    check_azure_sso_key_age,
    check_builtin_admin_used,
    check_duplicate_objects,
    check_guest_enabled,
    check_password_not_required,
    check_primary_group,
    check_reversible_password,
    check_sid_history,
    check_smartcard_password,
    check_unix_passwords,
)
from api.modules.ad.core.checks.accounts import (
    check_admin_count,
    check_asrep_roastable,
    check_delegation,
    check_inactive_users,
    check_kerberoast,
    check_password_never_expires,
    check_rbcd,
    check_weak_encryption,
)
from api.modules.ad.core.checks.acl import (
    check_dcsync,
    check_gpo_permissions,
    check_key_credential_link_acl,
    check_sensitive_acl,
    check_shadow_admins,
)
from api.modules.ad.core.checks.adcs import check_adcs_templates
from api.modules.ad.core.checks.adcs_ca import check_adcs_ca
from api.modules.ad.core.checks.adcs_mapping import check_adcs_mapping
from api.modules.ad.core.checks.catalog import with_guidance
from api.modules.ad.core.checks.clusters import check_clusters
from api.modules.ad.core.checks.common import CheckSpec
from api.modules.ad.core.checks.computers import (
    check_computer_creators,
    check_computer_password_age,
    check_dc_count,
    check_dc_delegation,
    check_dc_owner,
    check_inactive_computers,
    check_laps_deployment,
    check_obsolete_os,
)
from api.modules.ad.core.checks.critical_acl import (
    check_bad_successor,
    check_critical_object_acl,
    check_domain_root_acl,
)
from api.modules.ad.core.checks.dc_hardening import check_dc_hardening
from api.modules.ad.core.checks.dns import check_dns_zones
from api.modules.ad.core.checks.domain import (
    check_backup_age,
    check_ds_heuristics,
    check_functional_level,
    check_krbtgt_password_age,
    check_machine_account_quota,
    check_ntfrs_sysvol,
    check_password_policy,
    check_pre_win2000_access,
    check_recycle_bin,
    check_schema_vulnerable_class,
    check_too_many_admins,
)
from api.modules.ad.core.checks.gpo import check_user_rights_assignment
from api.modules.ad.core.checks.gpo_files_checks import (
    check_dc_audit_policy,
    check_gpo_external_files,
    check_gpo_registry_settings,
    check_sysvol_acl,
)
from api.modules.ad.core.checks.gpo_settings import (
    check_dc_logon_rights,
    check_gpo_security_options,
    check_gpp_passwords,
    check_restricted_groups,
    check_tiering_logon_deny,
)
from api.modules.ad.core.checks.groups import (
    check_privileged_groups,
    check_protected_users_coverage,
)
from api.modules.ad.core.checks.rodc import check_rodc_password_replication
from api.modules.ad.core.checks.trusts import check_trust_security
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex
from api.modules.ad.core.findings import Finding

# Поднимать при любой правке логики находок или формата их ключей: по версии сверка статусов отличает настоящие исчезновения от смены правил (docs/platform/findings.md).
ANALYZER_VERSION = "7"

_CHECKS: list[CheckSpec] = [
    CheckSpec("DCSync", "Права DCSync", "Права DCSync позволяют извлекать хэши паролей из AD и дают полный контроль над доменом.", check_dcsync, ("T1003.006",)),
    CheckSpec("PrivilegedGroups", "Члены привилегированных групп", "Членство в привилегированных группах даёт расширенные права. Лишние или неожиданные участники повышают риск компрометации.", check_privileged_groups, ("T1078.002",)),
    CheckSpec("Delegation", "Делегация Kerberos", "Делегация Kerberos может позволить перехват и использование учётных данных. Unconstrained особенно рискованна.", check_delegation, ("T1558", "T1187")),
    CheckSpec("ShadowAdmins", "Теневые администраторы (AdminSDHolder)", "Опасные ACL на AdminSDHolder позволяют незаметно получить привилегии администратора.", check_shadow_admins, ("T1098",)),
    CheckSpec("RBCD", "RBCD (AllowedToActOnBehalfOfOtherIdentity)", "RBCD позволяет одному объекту действовать от имени другого. Неправильные настройки дают эскалацию привилегий.", check_rbcd, ("T1550",)),
    CheckSpec("ASREP", "AS-REP roastable", "Отключённая Kerberos preauth позволяет AS-REP roast и офлайн-подбор пароля.", check_asrep_roastable, ("T1558.004",)),
    CheckSpec("Kerberoast", "Кандидаты на Kerberoasting (SPN)", "Учётные записи с SPN можно kerberoast'ить. Слабые пароли приводят к компрометации сервисов.", check_kerberoast, ("T1558.003",)),
    CheckSpec("AdminCount", "adminCount=1 вне защищённых групп", "След прежних привилегий: ACL объекта остался от AdminSDHolder, наследование выключено.", check_admin_count, ("T1078.002",)),
    CheckSpec("GpoPermissions", "Права на GPO", "Опасные права на GPO позволяют менять политики и захватывать машины и пользователей.", check_gpo_permissions, ("T1484.001",)),
    CheckSpec("UserRightsAssignment", "User Rights Assignment в GPO", "Опасные User Rights в GPO дают системные и отладочные привилегии и возможность обхода защиты.", check_user_rights_assignment, ("T1134",)),
    CheckSpec("PasswordNeverExpires", "Неистекающие пароли", "Неистекающие пароли повышают риск компрометации и длительного доступа.", check_password_never_expires, ("T1110",)),
    CheckSpec("InactiveUsers", "Неактивные пользователи", "Долго неиспользуемые учётные записи часто забываются и используются злоумышленниками.", check_inactive_users, ("T1078.002",)),
    CheckSpec("MachineAccountQuota", "MachineAccountQuota", "MAQ>0 позволяет пользователям создавать компьютеры в домене, что может быть использовано для атак.", check_machine_account_quota, ("T1136.002",)),
    CheckSpec("KeyCredentialLinkACL", "ACL на msDS-KeyCredentialLink (Shadow Credentials)", "Запись в msDS-KeyCredentialLink позволяет Shadow Credentials и бесшумную эскалацию.", check_key_credential_link_acl, ("T1098",)),
    CheckSpec("ProtectedUsersCoverage", "Покрытие Protected Users", "Привилегированные пользователи вне Protected Users уязвимы к старым протоколам и релеям.", check_protected_users_coverage, ("T1003",)),
    CheckSpec("KrbtgtPasswordAge", "Возраст пароля krbtgt", "Редкая смена пароля krbtgt увеличивает риск длительной компрометации Kerberos.", check_krbtgt_password_age, ("T1558.001",)),
    CheckSpec("WeakEncryption", "Слабое шифрование Kerberos (RC4, DES)", "Разрешение RC4 и слабых шифров, в том числе флаг «только DES», снижает стойкость Kerberos и упрощает атаки.", check_weak_encryption, ("T1558",)),
    CheckSpec("SensitiveAcl", "Опасные ACL на OU и компьютерах", "Опасные ACL на OU и компьютерах позволяют изменять объекты и продвигаться по привилегиям. Унаследованное право показывается одной находкой на объекте-источнике, а одинаковое явное право на множестве объектов — одной находкой на их общем предке.", check_sensitive_acl, ("T1098", "T1484")),
    CheckSpec("ADCS_ESC", "Шаблоны AD CS (ESC1–4, 9, 13, 15)", "Шаблоны сертификатов, по которым небезопасный заявитель может выпустить сертификат для входа от чужого имени или с чужими правами, либо изменить сам шаблон. Безопасными заявителями считаются только заведомые администраторы; для широких групп серьёзность выше, для прочих — на ступень ниже. Неопубликованный шаблон даёт находку Low.", check_adcs_templates, ("T1649",)),
    CheckSpec("ADCS_CA", "Центр сертификации (ESC5–8, 11, 16)", "Права на объекты PKI и центр сертификации, настройки ЦС и веб-выдачи, которые позволяют выпустить сертификат от чужого имени. ESC12 (доступ к HSM) удалённо не определяется.", check_adcs_ca, ("T1649",)),
    CheckSpec("ADCS_MAPPING", "Привязка сертификатов к учётным записям (ESC10, 14)", "Слабая привязка сертификата к учётной записи на контроллерах домена и слабые явные сопоставления (altSecurityIdentities) позволяют войти по сертификату, выпущенному на другого.", check_adcs_mapping, ("T1649",)),
    CheckSpec("PasswordNotRequired", "Пароль не требуется", "Флаг «пароль не требуется» позволяет учётке иметь пустой пароль и входить без него.", check_password_not_required, ("T1078.002",)),
    CheckSpec("ReversiblePassword", "Обратимое шифрование пароля", "Пароль с обратимым шифрованием восстанавливается из базы AD в открытом виде при компрометации контроллера.", check_reversible_password, ("T1003",)),
    CheckSpec("AdminDelegable", "Делегируемые администраторы", "Администратор без запрета делегирования и вне Protected Users: его билеты могут быть использованы службами с делегацией.", check_admin_delegable, ("T1558",)),
    CheckSpec("AdminPasswordAge", "Возраст паролей администраторов", "Давно не менявшийся пароль администратора повышает риск использования ранее украденных учётных данных.", check_admin_password_age, ("T1078.002",)),
    CheckSpec("BuiltinAdminUsed", "Встроенный Administrator в работе", "Встроенная учётка Administrator (RID 500) не подлежит блокировке и должна использоваться только в аварийных случаях.", check_builtin_admin_used, ("T1078.002",)),
    CheckSpec("GuestEnabled", "Включена учётка Guest", "Включённая учётка Guest даёт вход в домен без личной учётной записи.", check_guest_enabled, ("T1078.001",)),
    CheckSpec("AzureSsoKeyAge", "Возраст ключа Entra Seamless SSO", "Пароль компьютерной учётки AZUREADSSOACC$ — ключ для билетов Kerberos в облако; редкая смена позволяет подделывать билеты (silver ticket).", check_azure_sso_key_age, ("T1558",)),
    CheckSpec("DuplicateObjects", "Объекты-дубликаты", "Объекты с CNF: в имени и учётки $DUPLICATE- возникают из-за конфликтов репликации и указывают на проблемы каталога.", check_duplicate_objects, ()),
    CheckSpec("InactiveComputers", "Неактивные компьютеры", "Включённые компьютеры без входа дольше порога: забытые машины остаются без обновлений и мониторинга. Неактивный контроллер — отдельный риск.", check_inactive_computers, ("T1078.002",)),
    CheckSpec("ComputerPasswordAge", "Возраст паролей компьютеров", "Работающий компьютер меняет пароль учётки сам; старый пароль у активной машины говорит об отключённой смене или клонировании.", check_computer_password_age, ("T1078.002",)),
    CheckSpec("ObsoleteOs", "Устаревшие операционные системы", "Компьютеры с ОС, снятой с поддержки, не получают исправлений безопасности и уязвимы к известным атакам. Контроллер с такой ОС опаснее рядового компьютера.", check_obsolete_os, ("T1210",)),
    CheckSpec("DcCount", "Число контроллеров домена", "Один контроллер домена — единая точка отказа: при его потере домен недоступен, а восстановление затруднено.", check_dc_count, ()),
    CheckSpec("DcDelegation", "Делегация контроллеров домена", "Ограниченная делегация у контроллера (служб или protocol transition) позволяет от имени его учётки получать доступ к службам; контроллер — цель высшей ценности.", check_dc_delegation, ("T1558",)),
    CheckSpec("DcOwner", "Владелец объекта контроллера", "Владелец объекта контроллера домена может менять его права независимо от ACL; владельцем должны быть только администраторы.", check_dc_owner, ("T1098",)),
    CheckSpec("DcHardening", "Настройки контроллеров домена (NTLM, подпись LDAP и SMB, службы)", "Контроллер, который принимает NTLMv1, не требует подписи LDAP и SMB, держит SMBv1, запущенные Spooler и WebClient или давно не перезагружался (не обновлялся), открывает перехват и ретрансляцию проверки подлинности, принуждение контроллера к входу и известные уязвимости.", check_dc_hardening, ("T1557", "T1187", "T1210")),
    CheckSpec("TooManyAdmins", "Слишком много администраторов", "Чем больше администраторов домена, тем больше учётных записей, захват любой из которых даёт полный контроль над доменом.", check_too_many_admins, ("T1078.002",)),
    CheckSpec("FunctionalLevel", "Функциональный уровень домена и леса", "Низкий функциональный уровень домена или леса не даёт включить защиту новых версий Windows Server: Protected Users, политики и силосы проверки подлинности, AES для Kerberos по умолчанию.", check_functional_level, ()),
    CheckSpec("PreWin2000Access", "Группа Pre-Windows 2000 Compatible Access", "Участники группы читают атрибуты всех пользователей и групп домена; Anonymous Logon или Everyone в ней открывают каталог без входа.", check_pre_win2000_access, ("T1087.002",)),
    CheckSpec("Clusters", "Кластеры Windows", "Отказоустойчивые кластеры по SPN компьютеров: учётка кластера, его роли (виртуальные имена, не хосты) и узлы. Роль привязана к кластеру по создателю объекта; узлы к кластеру из AD не привязываются. Выключенная роль — вероятно, брошена.", check_clusters, ()),
    CheckSpec("DomainRootAcl", "Опасные права на корень домена", "GenericAll, WriteDacl или WriteOwner на корне домена позволяют выдать себе права репликации (DCSync) и получить полный контроль над доменом.", check_domain_root_acl, ("T1222.001",)),
    CheckSpec("PrimaryGroup", "Нестандартная первичная группа", "Членство через primaryGroupID не видно в списке участников группы: так прячут учётку в привилегированной группе. У пользователя ожидается Domain Users (у Guest — Domain Guests), у компьютера Domain Computers, у контроллера Domain Controllers, у RODC Read-only Domain Controllers.", check_primary_group, ("T1098",)),
    CheckSpec("SidHistory", "SID History", "SID в истории даёт учётке права этого субъекта без членства в группах. SID своего домена или привилегированный SID — признак закрепления злоумышленника; SID неизвестного домена или после завершённой миграции — мусор, который стоит очистить.", check_sid_history, ("T1134.005",)),
    CheckSpec("SmartcardPassword", "Пароли учёток «только смарт-карта»", "Учётка со входом только по смарт-карте сохраняет хэш пароля; если домен не меняет его сам (msDS-ExpirePasswordsOnSmartCardOnlyAccounts), старый хэш годится для pass-the-hash годами.", check_smartcard_password, ("T1550.002",)),
    CheckSpec("UnixPasswords", "Unix-пароли в каталоге", "Атрибуты userPassword и unixUserPassword хранят пароль в виде, доступном на чтение из каталога. Значения сборщик не читает, только факт заполнения.", check_unix_passwords, ("T1552",)),
    CheckSpec("ComputerCreators", "Компьютеры, созданные не администраторами", "Компьютеры, введённые в домен обычной учёткой по MachineAccountQuota (ms-DS-CreatorSID): создатель сохраняет права на объект, а такие машины обходят процесс ввода в домен.", check_computer_creators, ("T1136.002",)),
    CheckSpec("LapsDeployment", "Развёртывание LAPS", "Без LAPS пароль локального администратора одинаков или не меняется на многих машинах, и захват одной открывает остальные. Проверяются схема и наличие срока пароля LAPS у включённых активных компьютеров Windows, кроме контроллеров.", check_laps_deployment, ("T1078.003",)),
    CheckSpec("PasswordPolicy", "Политика паролей домена и PSO", "Короткие пароли, отсутствие блокировки и выключенная сложность упрощают подбор, обратимое хранение раскрывает пароли при захвате базы AD. Проверяются политика домена и каждая PSO.", check_password_policy, ("T1110",)),
    CheckSpec("RecycleBin", "Корзина AD", "Без корзины AD удалённый объект восстанавливается только из резервной копии или из tombstone без большинства атрибутов.", check_recycle_bin, ()),
    CheckSpec("DsHeuristics", "Опасные значения dSHeuristics", "Атрибут dSHeuristics меняет поведение каталога для всего леса: анонимный доступ к LDAP и NSPI, исключение операторов из AdminSDHolder, отказ от проверки уникальности UPN и SPN, выключение защиты KB5008383.", check_ds_heuristics, ("T1087.002",)),
    CheckSpec("BackupAge", "Давность резервной копии AD", "Без свежей резервной копии AD после шифровальщика или порчи каталога восстанавливать нечего. Дата берётся из метаданных репликации dSASignature корня домена.", check_backup_age, ()),
    CheckSpec("NtfrsSysvol", "Репликация SYSVOL через FRS", "FRS — устаревшая служба репликации SYSVOL: контроллер новых версий Windows Server в такой домен не вводится, а сама служба не получает исправлений.", check_ntfrs_sysvol, ()),
    CheckSpec("SchemaVulnerableClass", "Уязвимый класс схемы Exchange", "Если в possSuperiors класса msExchStorageGroup есть computer (CVE-2021-34470), пользователь, управляющий объектом компьютера, может создать под ним объект этого класса и повысить привилегии в домене.", check_schema_vulnerable_class, ("T1068",)),
    CheckSpec("TrustSecurity", "Безопасность доверий", "Доверия без фильтрации SID пропускают чужие SID из sIDHistory, доверие к домену Windows NT 4.0 работает только по NTLM, делегирование TGT через лесное доверие отдаёт билеты наших пользователей службам партнёра. Давно не менявшийся объект доверия говорит о том, что доверие не работает; без AES межсферные билеты шифруются RC4.", check_trust_security, ("T1134.005", "T1482")),
    CheckSpec("DnsZones", "Зоны DNS в AD", "Небезопасные динамические обновления позволяют без входа менять записи зоны и уводить трафик на себя; в зоне домена и _msdcs это записи контроллеров. Создание записей Authenticated Users (настройка по умолчанию) позволяет занимать несуществующие имена, например WPAD.", check_dns_zones, ("T1557",)),
    CheckSpec("RodcPasswordReplication", "Репликация паролей на RODC", "Пароли, которые кэширует RODC, достаются тому, кто захватил сам RODC. Привилегированные учётки не должны кэшироваться, Denied RODC Password Replication Group должна запрещать кэширование контроллеров, администраторов и krbtgt, а учётки krbtgt_NNNNN удалённых RODC — удаляться.", check_rodc_password_replication, ("T1003",)),
    CheckSpec("CriticalObjectAcl", "Опасные права на критичные объекты", "Право менять привилегированную группу (членство, права, владельца) или её участника (сброс пароля, Shadow Credentials) даёт права этой группы. Проверяются группы администраторов и операторов, DnsAdmins, их рекурсивные участники и учётки Administrator и krbtgt; права, совпадающие с AdminSDHolder, показывает ShadowAdmins. Учитывается один шаг: цепочки через вложенные права не строятся.", check_critical_object_acl, ("T1098", "T1222.001")),
    CheckSpec("BadSuccessor", "Создание dMSA в OU (BadSuccessor)", "Кто может создать в OU объект dMSA, тот назначает ему предшественником любую учётку и получает её права, включая администратора домена. Опасно при контроллере Windows Server 2025; без такого контроллера находка Low. Учитываются явные права CreateChild (любых объектов или dMSA) и GenericAll на OU.", check_bad_successor, ("T1098",)),
    CheckSpec("GppPasswords", "Пароли в GPO (GPP, автологон)", "Пароль в настройках GPP (cpassword) расшифровывается опубликованным ключом, пароль автологона в Registry.pol лежит открытым текстом; файлы SYSVOL читает любой пользователь домена. Значения сборщик не передаёт, только факт.", check_gpp_passwords, ("T1552.006",)),
    CheckSpec("GpoSecurityOptions", "Параметры безопасности в GPO", "Параметры безопасности из GptTmpl.inf и Registry.pol: разрешённые LM и NTLMv1 и отсутствие режима «только NTLMv2» на контроллерах, хранение хэша LM, анонимный доступ, вход с пустым паролем, LDAP без подписи, запрет смены пароля компьютеров, консоль восстановления без пароля, обратимое хранение паролей.", check_gpo_security_options, ("T1557.001", "T1003", "T1087.002", "T1557")),
    CheckSpec("DcLogonRights", "Вход на контроллеры для широких групп", "GPO, применимая к контроллерам домена, разрешает широкой группе (Everyone, Authenticated Users, Users, Domain Users, Domain Computers) локальный вход, вход по RDP или как пакетное задание: любая учётка домена получает сеанс на контроллере.", check_dc_logon_rights, ("T1078.002",)),
    CheckSpec("TieringLogonDeny", "Нет запрета входа администраторов домена", "Ни одна GPO не запрещает Domain Admins локальный вход и вход по RDP: учётные данные администраторов домена остаются на рабочих станциях и серверах, где их можно украсть.", check_tiering_logon_deny, ("T1078.002",)),
    CheckSpec("RestrictedGroups", "Широкие группы в локальных группах (Restricted Groups, GPP)", "Restricted Groups в GptTmpl.inf или настройка GPP Groups добавляет широкую группу в локальную встроенную группу компьютеров: в Administrators — права администратора на всех компьютерах, куда применяется GPO.", check_restricted_groups, ("T1098",)),
    CheckSpec("GpoRegistrySettings", "Параметры реестра в GPO (LLMNR, Hardened Paths, WSUS, PowerShell)", "Административные шаблоны GPO: LLMNR не выключен, для SYSVOL и NETLOGON не требуются взаимная проверка подлинности и целостность, WSUS по HTTP или с прокси пользователя, журналирование блоков сценариев PowerShell не включено. Это открывает перехват хэшей и подмену политик и обновлений в сети и скрывает следы атакующего.", check_gpo_registry_settings, ("T1557.001", "T1557")),
    CheckSpec("DcAuditPolicy", "Аудит на контроллерах домена", "GPO, применимые к контроллерам, не включают аудит успеха важных подкатегорий (проверка учётных данных, Kerberos, изменения учёток, групп и каталога, вход, создание процессов): без этих событий атаку на домен не видно в журналах.", check_dc_audit_policy, ("T1685.001",)),
    CheckSpec("GpoExternalFiles", "Сценарии и файлы GPO с серверов вне домена", "Сценарий GPO, сценарий входа учётки (scriptPath) или файл из настройки GPP «Файлы» берётся с сервера вне домена и контроллеров: кто управляет этим сервером, тот выполняет код на компьютерах и от имени пользователей, куда применяется GPO.", check_gpo_external_files, ("T1037",)),
    CheckSpec("SysvolAcl", "Права на папки GPO в SYSVOL", "Субъект вне администраторов домена может менять папку GPO или файл её сценария в SYSVOL: подменённые настройки и сценарии выполняются на всех компьютерах и у всех пользователей, куда привязана GPO.", check_sysvol_acl, ("T1484.001",)),
]

CHECKS: list[CheckSpec] = [with_guidance(c) for c in _CHECKS]
CHECK_BY_CODE: dict[str, CheckSpec] = {c.code: c for c in CHECKS}


def run_all(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out: list[Finding] = []
    for spec in CHECKS:
        out.extend(spec.func(idx, cfg))
    return out
