"""Проверки учётных записей: Kerberos, пароли, делегация, шифрование."""
from __future__ import annotations

import base64

from api.modules.ad.core import sd
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


def _enabled_users(idx: ExportIndex) -> list[AdObject]:
    return [u for u in idx.objects("user") if u.enabled]


def _preauth_disabled(idx: ExportIndex, cfg: AdConfig, check: str, detail: str) -> list[Finding]:
    return [
        account_finding(idx, cfg, check, "High", u, details=detail)
        for u in _enabled_users(idx)
        if (u.uac or 0) & UAC_DONT_REQ_PREAUTH
    ]


def check_asrep_roastable(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    return _preauth_disabled(idx, cfg, "ASREP", "Kerberos preauth отключена: AS-REP roast")


def check_preauth_disabled(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    return _preauth_disabled(idx, cfg, "PreauthDisabled", "Kerberos preauth disabled")


def check_kerberoast(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out = []
    for u in _enabled_users(idx):
        if not u.spn or (u.sam or "").lower() == "krbtgt" or u.rid == RID_KRBTGT:
            continue
        out.append(account_finding(idx, cfg, "Kerberoast", "Medium", u, spn=list(u.spn), details="; ".join(u.spn)))
    return out


def check_password_never_expires(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    return [
        account_finding(idx, cfg, "PasswordNeverExpires", "Medium", u, details="PasswordNeverExpires")
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
                    idx, cfg, "InactiveUsers", "Low", u,
                    details=f"Нет входа больше {days} дн.",
                    idle_days=days_between(u.lastLogonTimestamp, now),
                )
            )
    return out


def decode_enc_types(value: int) -> str:
    names = [(1, "DES-CBC-CRC"), (2, "DES-CBC-MD5"), (4, "RC4"), (8, "AES128"), (16, "AES256"), (32, "FAST")]
    return ", ".join(n for bit, n in names if value & bit)


def check_weak_encryption(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out = []
    for obj in idx.objects("user") + idx.objects("computer"):
        if obj.supportedEncryptionTypes is None:
            continue
        val = int(obj.supportedEncryptionTypes)
        if not val & 4:
            continue
        has_aes = bool(val & 8 or val & 16)
        out.append(
            account_finding(
                idx, cfg, "WeakEncryption", "Medium" if has_aes else "High", obj,
                details=f"msDS-SupportedEncryptionTypes={val} ({decode_enc_types(val)})",
                rc4_only=not has_aes,
            )
        )
    return out


def check_admin_count(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out = []
    for obj in idx.export.objects:
        if obj.adminCount == 1 and obj.cls in ("user", "computer", "group"):
            out.append(account_finding(idx, cfg, "AdminCount", "Medium", obj))
    return out


def check_delegation(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    out = []
    for obj in idx.objects("user") + idx.objects("computer"):
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
        try:
            desc = sd.parse_sd(base64.b64decode(comp.allowedToActOnBehalf))
            aces = desc.dacl
        except (ValueError, IndexError, KeyError):
            aces = []
        if not aces:
            out.append(
                finalize(
                    Finding(check="RBCD", severity="High", target=comp.label, details={"details": "Дескриптор есть, но ACE не разобраны"}),
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
                        severity="High",
                        identity=identity,
                        identity_sid=ace.sid,
                        target=comp.label,
                        details={"object_type": "computer", "target_dn": comp.dn},
                    ),
                    cfg,
                )
            )
    return out
