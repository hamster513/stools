"""Проверки учётных записей: Kerberos, пароли, делегация, шифрование."""
from __future__ import annotations

import base64
import datetime as dt

from api.modules.ad.core import sd
from api.modules.ad.core.checks import principals
from api.modules.ad.core.checks.common import account_finding, days_between
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import (
    RID_KRBTGT,
    UAC_DONT_EXPIRE_PASSWORD,
    UAC_DONT_REQ_PREAUTH,
    AdObject,
    ExportIndex,
    datetime_to_filetime,
)
from api.modules.ad.core.findings import Finding, finalize

UAC_USE_DES_KEY_ONLY = 0x200000


def _enabled_users(idx: ExportIndex) -> list[AdObject]:
    return [u for u in idx.objects("user") if u.enabled]


def _severity(idx: ExportIndex, cfg: AdConfig, obj: AdObject, severity: str, admin_severity: str) -> str:
    return principals.worst(severity, principals.is_admin(idx, cfg, obj), admin_severity)


def check_asrep_roastable(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    return [
        account_finding(idx, cfg, "ASREP", _severity(idx, cfg, u, "High", "Critical"), u, details="Kerberos preauth отключена: AS-REP roast")
        for u in _enabled_users(idx)
        if (u.uac or 0) & UAC_DONT_REQ_PREAUTH
    ]


def check_kerberoast(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out = []
    for u in _enabled_users(idx):
        if not u.spn or (u.sam or "").lower() == "krbtgt" or u.rid == RID_KRBTGT:
            continue
        out.append(account_finding(idx, cfg, "Kerberoast", _severity(idx, cfg, u, "Medium", "High"), u, spn=list(u.spn), details="; ".join(u.spn)))
    return out


def check_password_never_expires(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    return [
        account_finding(idx, cfg, "PasswordNeverExpires", _severity(idx, cfg, u, "Low", "High"), u, details="PasswordNeverExpires")
        for u in _enabled_users(idx)
        if (u.uac or 0) & UAC_DONT_EXPIRE_PASSWORD
    ]


def check_inactive_users(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    days = cfg.user_inactivity_days if cfg.user_inactivity_days >= 1 else 90
    now = idx.export.collected_at
    cutoff = datetime_to_filetime(now) - days * 864_000_000_000
    out = []
    for u in _enabled_users(idx):
        if u.lastLogonTimestamp and u.lastLogonTimestamp <= cutoff:
            out.append(
                account_finding(
                    idx, cfg, "InactiveUsers", _severity(idx, cfg, u, "Low", "High"), u,
                    details=f"Нет входа больше {days} дн.",
                    idle_days=days_between(u.lastLogonTimestamp, now),
                )
            )
        # Граница как у ветки выше (<= cutoff): создана ровно days дней назад — уже неактивна.
        elif not u.lastLogonTimestamp and u.whenCreated is not None and u.whenCreated <= now - dt.timedelta(days=days):
            out.append(
                account_finding(
                    idx, cfg, "InactiveUsers", _severity(idx, cfg, u, "Low", "High"), u,
                    details=f"Ни разу не входила, создана {u.whenCreated.strftime('%Y-%m-%d')}",
                    created=u.whenCreated.strftime("%Y-%m-%d"),
                )
            )
    return out


def decode_enc_types(value: int) -> str:
    names = [(1, "DES-CBC-CRC"), (2, "DES-CBC-MD5"), (4, "RC4"), (8, "AES128"), (16, "AES256"), (32, "FAST")]
    return ", ".join(n for bit, n in names if value & bit)


def check_weak_encryption(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out = []
    for obj in idx.objects("user") + idx.objects("computer"):
        des_only = bool((obj.uac or 0) & UAC_USE_DES_KEY_ONLY)
        val = None if obj.supportedEncryptionTypes is None else int(obj.supportedEncryptionTypes)
        rc4 = val is not None and bool(val & 4)
        if not rc4 and not des_only:
            continue
        has_aes = val is not None and bool(val & 8 or val & 16)
        parts = [] if val is None else [f"msDS-SupportedEncryptionTypes={val} ({decode_enc_types(val)})"]
        if des_only:
            parts.append("флаг «только DES» (USE_DES_KEY_ONLY)")
        out.append(
            account_finding(
                idx, cfg, "WeakEncryption", "Medium" if has_aes and not des_only else "High", obj,
                details="; ".join(parts),
                rc4_only=rc4 and not has_aes,
                des_only=des_only,
            )
        )
    return out


def check_admin_count(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out = []
    protected = principals.protected_dns(idx)
    for obj in idx.export.objects:
        if obj.adminCount == 1 and obj.cls in ("user", "computer", "group") and obj.dn.lower() not in protected:
            out.append(account_finding(idx, cfg, "AdminCount", "Medium", obj))
    return out


def check_delegation(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out = []
    for obj in idx.objects("user") + idx.objects("computer"):
        # Неограниченная делегация — штатный флаг контроллера; делегацию контроллеров разбирает DcDelegation.
        if idx.is_dc(obj):
            continue
        kinds = []
        if obj.unconstrained_delegation:
            kinds.append("Unconstrained")
        if obj.protocol_transition:
            kinds.append("Constrained (S4U)")
        if obj.allowedToDelegateTo:
            kinds.append("Constrained (Services)")
        if not kinds:
            continue
        out.append(
            account_finding(
                idx, cfg, "Delegation", "High" if obj.unconstrained_delegation else "Medium", obj,
                delegation_type="; ".join(kinds),
                allowed_to_delegate_to="; ".join(obj.allowedToDelegateTo),
            )
        )
    return out


def check_rbcd(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out: list[Finding] = []
    for comp in idx.objects("computer"):
        if not comp.allowedToActOnBehalf:
            continue
        severity = "Critical" if idx.is_dc(comp) else "High"
        try:
            desc = sd.parse_sd(base64.b64decode(comp.allowedToActOnBehalf))
            aces = desc.dacl
        except (ValueError, IndexError, KeyError):
            aces = []
        if not aces:
            out.append(
                finalize(
                    Finding(check="RBCD", severity=severity, target=comp.label, details={"details": "Дескриптор есть, но ACE не разобраны"}),
                    cfg,
                )
            )
            continue
        for ace in aces:
            identity = idx.principal_name(ace.sid)
            out.append(
                finalize(
                    Finding(
                        check="RBCD",
                        severity=severity,
                        identity=identity,
                        identity_sid=ace.sid,
                        target=comp.label,
                        details={"object_type": "computer", "target_dn": comp.dn},
                    ),
                    cfg,
                )
            )
    return out
