"""Параметры домена: MachineAccountQuota и возраст пароля krbtgt."""
from __future__ import annotations

from api.modules.ad.core.checks.common import date_str, days_between
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import RID_KRBTGT, ExportIndex
from api.modules.ad.core.findings import Finding, finalize


def check_machine_account_quota(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    quota = idx.export.domain.machine_account_quota
    if quota is None:
        return [finalize(Finding(check="MachineAccountQuota", severity="Info", target=idx.export.domain.dn, details={"details": "ms-DS-MachineAccountQuota не прочитан"}), cfg)]
    return [
        finalize(
            Finding(
                check="MachineAccountQuota",
                severity="Medium" if quota > 0 else "Low",
                target=idx.export.domain.dn,
                details={"details": f"ms-DS-MachineAccountQuota={quota}", "quota": quota},
            ),
            cfg,
        )
    ]


def check_krbtgt_password_age(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    krbtgt = idx.by_sid.get(idx.domain_rid_sid(RID_KRBTGT))
    if krbtgt is None:
        krbtgt = next((u for u in idx.objects("user") if (u.sam or "").lower() == "krbtgt"), None)
    if krbtgt is None:
        return []
    age = days_between(krbtgt.pwdLastSet, idx.export.collected_at)
    limit = cfg.krbtgt_max_age_days if cfg.krbtgt_max_age_days >= 1 else 180
    severity = "High" if age is not None and age > limit else "Low"
    details = (
        f"krbtgt pwdLastSet={date_str(krbtgt.pwdLastSet)}, ageDays={age}" if age is not None else "krbtgt pwdLastSet не найден"
    )
    return [
        finalize(
            Finding(check="KrbtgtPasswordAge", severity=severity, identity="krbtgt", identity_sid=krbtgt.sid or "", target=idx.export.domain.dn, details={"details": details, "age_days": age, "limit_days": limit}),
            cfg,
            allowlist=False,
        )
    ]
