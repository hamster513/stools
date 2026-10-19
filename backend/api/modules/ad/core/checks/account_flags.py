"""Проверки флагов и возраста учётных записей: пароль, делегируемость, встроенные учётки."""
from __future__ import annotations

from api.modules.ad.core.checks import principals
from api.modules.ad.core.checks.common import account_finding, days_between
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import UAC_PARTIAL_SECRETS_ACCOUNT, AdObject, ExportIndex
from api.modules.ad.core.findings import Finding, finding_key

UAC_PASSWD_NOTREQD = 0x20
UAC_ENCRYPTED_TEXT_PWD_ALLOWED = 0x80
UAC_NOT_DELEGATED = 0x100000
UAC_SMARTCARD_REQUIRED = 0x40000

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


#: Ожидаемая первичная группа: Domain Users, Domain Guests (у Guest), Domain Computers, Domain Controllers, Read-only DCs.
PG_USERS, PG_GUESTS, PG_COMPUTERS, PG_DCS, PG_RODCS = 513, 514, 515, 516, 521


def _expected_primary_group(idx: ExportIndex, o: AdObject) -> int:
    if o.cls == "user":
        return PG_GUESTS if o.rid == RID_GUEST else PG_USERS
    if (o.uac or 0) & UAC_PARTIAL_SECRETS_ACCOUNT:
        return PG_RODCS
    return PG_DCS if idx.is_dc(o) else PG_COMPUTERS


def check_primary_group(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    # Членство через primaryGroupID не видно в member группы: так прячут участников Domain Admins.
    out = []
    for o in idx.objects("user") + idx.objects("computer"):
        if o.primaryGroupID is None:
            continue
        expected = _expected_primary_group(idx, o)
        if o.primaryGroupID != expected:
            group = idx.principal_name(idx.domain_rid_sid(o.primaryGroupID))
            out.append(
                account_finding(
                    idx, cfg, "PrimaryGroup", "Medium", o,
                    details=f"Первичная группа — {group} (primaryGroupID={o.primaryGroupID}), ожидается {expected}: членство в ней не видно в списке участников группы",
                    primary_group_id=o.primaryGroupID,
                    expected_primary_group_id=expected,
                )
            )
    return out


_SID_HISTORY = {
    "same_domain": ("Critical", "SID своего домена в SID History: учётка получает права этого субъекта без членства в группах"),
    "privileged": ("High", "встроенный или привилегированный SID (RID < 1000) в SID History"),
    "unknown_domain": ("Medium", "SID домена, которого нет среди доверий: история от удалённого или чужого домена"),
    "other": ("Low", "SID History после миграции: очистите, когда миграция завершена"),
}


def sid_history_kind(idx: ExportIndex, sid: str) -> str:
    domain_part, _, rid_text = sid.rpartition("-")
    if domain_part == idx.domain_sid:
        return "same_domain"
    if sid.startswith("S-1-5-32-") or (rid_text.isdigit() and int(rid_text) < 1000):
        return "privileged"
    if domain_part not in idx.trusted_domains:
        return "unknown_domain"
    return "other"


def check_sid_history(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out = []
    for o in idx.export.objects:
        for sid in o.sIDHistory:
            kind = sid_history_kind(idx, sid)
            severity, reason = _SID_HISTORY[kind]
            f = account_finding(idx, cfg, "SidHistory", severity, o, details=f"{idx.principal_name(sid)}: {reason}", sid_history=sid, kind=kind)
            # Ключ — с SID из истории: у одной учётки их бывает несколько.
            f.key_extra = sid
            f.key = finding_key(f)
            out.append(f)
    return out


def check_smartcard_password(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    # Домен с msDS-ExpirePasswordsOnSmartCardOnlyAccounts сам меняет такие пароли; без него хэш живёт годами.
    if idx.export.domain.smartcard_rotation is not False:
        return []
    now = idx.export.collected_at
    limit = cfg.smartcard_password_max_age_days
    out = []
    for u in idx.objects("user"):
        if not u.enabled or not (u.uac or 0) & UAC_SMARTCARD_REQUIRED:
            continue
        age = days_between(u.pwdLastSet, now)
        if age is not None and age > limit:
            out.append(
                account_finding(
                    idx, cfg, "SmartcardPassword", principals.worst("Medium", principals.is_admin(idx, cfg, u), "High"), u,
                    details=f"Вход только по смарт-карте, но хэш пароля не менялся {age} дн. (порог {limit}): его можно использовать для pass-the-hash",
                    password_age_days=age,
                )
            )
    return out


def check_unix_passwords(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    return [
        account_finding(idx, cfg, "UnixPasswords", "Medium", o, details="Заполнен userPassword или unixUserPassword: такой пароль может прочитать любой, у кого есть чтение атрибута в каталоге")
        for o in idx.export.objects
        if o.hasUnixPassword
    ]
