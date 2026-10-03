"""Реестр проверок: код, название, описание из прототипа, функция."""
from __future__ import annotations

from api.modules.ad.core.checks.accounts import (
    check_admin_count,
    check_asrep_roastable,
    check_delegation,
    check_inactive_users,
    check_kerberoast,
    check_password_never_expires,
    check_preauth_disabled,
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
from api.modules.ad.core.checks.common import CheckSpec
from api.modules.ad.core.checks.domain import check_krbtgt_password_age, check_machine_account_quota
from api.modules.ad.core.checks.gpo import check_user_rights_assignment
from api.modules.ad.core.checks.groups import (
    check_privileged_groups,
    check_protected_users_coverage,
)
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex
from api.modules.ad.core.findings import Finding

# Поднимать при любой правке логики находок или формата их ключей: по версии сверка статусов отличает настоящие исчезновения от смены правил (docs/platform/findings.md).
ANALYZER_VERSION = "2"

_CHECKS: list[CheckSpec] = [
    CheckSpec("DCSync", "Права DCSync", "Права DCSync позволяют извлекать хэши паролей из AD и дают полный контроль над доменом.", check_dcsync, ("T1003.006",)),
    CheckSpec("PrivilegedGroups", "Члены привилегированных групп", "Членство в привилегированных группах даёт расширенные права. Лишние или неожиданные участники повышают риск компрометации.", check_privileged_groups, ("T1078.002",)),
    CheckSpec("Delegation", "Делегация Kerberos", "Делегация Kerberos может позволить перехват и использование учётных данных. Unconstrained особенно рискованна.", check_delegation, ("T1558", "T1187")),
    CheckSpec("ShadowAdmins", "Теневые администраторы (AdminSDHolder)", "Опасные ACL на AdminSDHolder позволяют незаметно получить привилегии администратора.", check_shadow_admins, ("T1098",)),
    CheckSpec("RBCD", "RBCD (AllowedToActOnBehalfOfOtherIdentity)", "RBCD позволяет одному объекту действовать от имени другого. Неправильные настройки дают эскалацию привилегий.", check_rbcd, ("T1550",)),
    CheckSpec("ASREP", "AS-REP roastable", "Отключённая Kerberos preauth позволяет AS-REP roast и офлайн-подбор пароля.", check_asrep_roastable, ("T1558.004",)),
    CheckSpec("Kerberoast", "Кандидаты на Kerberoasting (SPN)", "Учётные записи с SPN можно kerberoast'ить. Слабые пароли приводят к компрометации сервисов.", check_kerberoast, ("T1558.003",)),
    CheckSpec("AdminCount", "Объекты с adminCount=1", "adminCount=1 указывает на защищённые объекты. Лишние объекты здесь — признак неверных прав или наследования.", check_admin_count, ("T1078.002",)),
    CheckSpec("GpoPermissions", "Права на GPO", "Опасные права на GPO позволяют менять политики и захватывать машины и пользователей.", check_gpo_permissions, ("T1484.001",)),
    CheckSpec("UserRightsAssignment", "User Rights Assignment в GPO", "Опасные User Rights в GPO дают системные и отладочные привилегии и возможность обхода защиты.", check_user_rights_assignment, ("T1134",)),
    CheckSpec("PasswordNeverExpires", "Неистекающие пароли", "Неистекающие пароли повышают риск компрометации и длительного доступа.", check_password_never_expires, ("T1110",)),
    CheckSpec("InactiveUsers", "Неактивные пользователи", "Долго неиспользуемые учётные записи часто забываются и используются злоумышленниками.", check_inactive_users, ("T1078.002",)),
    CheckSpec("MachineAccountQuota", "MachineAccountQuota", "MAQ>0 позволяет пользователям создавать компьютеры в домене, что может быть использовано для атак.", check_machine_account_quota, ("T1136.002",)),
    CheckSpec("KeyCredentialLinkACL", "ACL на msDS-KeyCredentialLink (Shadow Credentials)", "Запись в msDS-KeyCredentialLink позволяет Shadow Credentials и бесшумную эскалацию.", check_key_credential_link_acl, ("T1098",)),
    CheckSpec("ProtectedUsersCoverage", "Покрытие Protected Users", "Привилегированные пользователи вне Protected Users уязвимы к старым протоколам и релеям.", check_protected_users_coverage, ("T1003",)),
    CheckSpec("KrbtgtPasswordAge", "Возраст пароля krbtgt", "Редкая смена пароля krbtgt увеличивает риск длительной компрометации Kerberos.", check_krbtgt_password_age, ("T1558.001",)),
    CheckSpec("WeakEncryption", "Слабое шифрование Kerberos (RC4)", "Разрешение RC4 и слабых шифров снижает стойкость Kerberos и упрощает атаки.", check_weak_encryption, ("T1558",)),
    CheckSpec("PreauthDisabled", "Preauth отключена", "Отключённая preauth позволяет получать ответы AS-REP для офлайн-подбора.", check_preauth_disabled, ("T1558.004",)),
    CheckSpec("SensitiveAcl", "Опасные ACL на OU и компьютерах", "Опасные ACL на OU и компьютерах позволяют изменять объекты и продвигаться по привилегиям. Унаследованное право показывается одной находкой на объекте-источнике, а одинаковое явное право на множестве объектов — одной находкой на их общем предке.", check_sensitive_acl, ("T1098", "T1484")),
    CheckSpec("ADCS_ESC", "Шаблоны AD CS (ESC1–4, 9, 13, 15)", "Шаблоны сертификатов, по которым небезопасный заявитель может выпустить сертификат для входа от чужого имени или с чужими правами, либо изменить сам шаблон. Безопасными заявителями считаются только заведомые администраторы; для широких групп серьёзность выше, для прочих — на ступень ниже. Неопубликованный шаблон даёт находку Low.", check_adcs_templates, ("T1649",)),
    CheckSpec("ADCS_CA", "Центр сертификации (ESC5–8, 11, 16)", "Права на объекты PKI и центр сертификации, настройки ЦС и веб-выдачи, которые позволяют выпустить сертификат от чужого имени. ESC12 (доступ к HSM) удалённо не определяется.", check_adcs_ca, ("T1649",)),
    CheckSpec("ADCS_MAPPING", "Привязка сертификатов к учётным записям (ESC10, 14)", "Слабая привязка сертификата к учётной записи на контроллерах домена и слабые явные сопоставления (altSecurityIdentities) позволяют войти по сертификату, выпущенному на другого.", check_adcs_mapping, ("T1649",)),
]

CHECKS: list[CheckSpec] = [with_guidance(c) for c in _CHECKS]
CHECK_BY_CODE: dict[str, CheckSpec] = {c.code: c for c in CHECKS}


def run_all(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out: list[Finding] = []
    for spec in CHECKS:
        out.extend(spec.func(idx, cfg))
    return out
