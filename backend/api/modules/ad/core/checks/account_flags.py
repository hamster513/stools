"""Проверки флагов и возраста учётных записей: пароль, делегируемость, встроенные учётки."""
from __future__ import annotations

from api.modules.ad.core.checks import principals
from api.modules.ad.core.checks.common import account_finding, days_between
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import AdObject, ExportIndex
from api.modules.ad.core.findings import Finding

UAC_PASSWD_NOTREQD = 0x20
UAC_ENCRYPTED_TEXT_PWD_ALLOWED = 0x80
UAC_NOT_DELEGATED = 0x100000

RID_GUEST = 501
AZURE_SSO_SAM = "AZUREADSSOACC$"


def _enabled_accounts(idx: ExportIndex) -> list[AdObject]:
    return [o for o in idx.objects("user") + idx.objects("computer") if o.enabled]


def _enabled_admins(idx: ExportIndex, cfg: AdConfig) -> list[AdObject]:
    return [u for u in idx.objects("user") if u.enabled and principals.is_admin(idx, cfg, u)]


def check_password_not_required(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    return [
        account_finding(
            idx, cfg, "PasswordNotRequired", principals.worst("Medium", principals.is_admin(idx, cfg, o), "High"), o,
            details="Установлен флаг «пароль не требуется» (PASSWD_NOTREQD): учётку можно использовать с пустым паролем",
        )
        for o in _enabled_accounts(idx)
        if (o.uac or 0) & UAC_PASSWD_NOTREQD
    ]


def check_reversible_password(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    return [
        account_finding(
            idx, cfg, "ReversiblePassword", "Medium", o,
            details="Пароль хранится с обратимым шифрованием (ENCRYPTED_TEXT_PWD_ALLOWED): его можно восстановить из базы AD",
        )
        for o in _enabled_accounts(idx)
        if (o.uac or 0) & UAC_ENCRYPTED_TEXT_PWD_ALLOWED
    ]


def check_admin_delegable(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    in_protected_users = principals.protected_users_dns(idx)
    return [
        account_finding(
            idx, cfg, "AdminDelegable", "Medium", u,
            details="Администратор без флага «учётная запись важна и не может быть делегирована» и вне Protected Users: его билеты можно делегировать",
        )
        for u in _enabled_admins(idx, cfg)
        if not (u.uac or 0) & UAC_NOT_DELEGATED and u.dn.lower() not in in_protected_users
    ]


def check_admin_password_age(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    now = idx.export.collected_at
    out = []
    for u in _enabled_admins(idx, cfg):
        age = days_between(u.pwdLastSet, now)
        if age is not None and age > cfg.admin_password_max_age_days:
            out.append(
                account_finding(
                    idx, cfg, "AdminPasswordAge", "Medium", u,
                    details=f"Пароль администратора не менялся {age} дн. (порог {cfg.admin_password_max_age_days})",
                    password_age_days=age,
                )
            )
    return out


def check_builtin_admin_used(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    admin = idx.by_sid.get(idx.domain_rid_sid(principals.RID_ADMINISTRATOR))
    if admin is None:
        return []
    idle = days_between(admin.lastLogonTimestamp, idx.export.collected_at)
    if idle is None or idle > cfg.builtin_admin_recent_days:
        return []
    return [
        account_finding(
            idx, cfg, "BuiltinAdminUsed", "Medium", admin,
            details=f"Встроенный Administrator входил {idle} дн. назад (порог {cfg.builtin_admin_recent_days}): им должны пользоваться только в аварии",
            idle_days=idle,
        )
    ]


def check_guest_enabled(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    guest = idx.by_sid.get(idx.domain_rid_sid(RID_GUEST))
    if guest is None or not guest.enabled:
        return []
    return [account_finding(idx, cfg, "GuestEnabled", "High", guest, details="Учётная запись Guest включена: вход возможен без личной учётки")]


def check_azure_sso_key_age(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    now = idx.export.collected_at
    out = []
    for c in idx.objects("computer"):
        if (c.sam or "").upper() != AZURE_SSO_SAM:
            continue
        age = days_between(c.pwdLastSet, now)
        if age is not None and age > cfg.azure_sso_key_max_age_days:
            out.append(
                account_finding(
                    idx, cfg, "AzureSsoKeyAge", "Medium", c,
                    details=f"Ключ Kerberos для Entra Seamless SSO не менялся {age} дн. (порог {cfg.azure_sso_key_max_age_days})",
                    password_age_days=age,
                )
            )
    return out


def check_duplicate_objects(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    # CNF: AD дописывает к имени при конфликте репликации, $DUPLICATE- — при конфликте sAMAccountName.
    return [
        account_finding(idx, cfg, "DuplicateObjects", "Low", o, details="Объект-дубликат, созданный конфликтом репликации AD: проверьте и удалите")
        for o in idx.export.objects
        if "cnf:" in o.dn.lower() or (o.sam or "").upper().startswith("$DUPLICATE-")
    ]
