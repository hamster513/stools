"""Лицензии: истекла, истекает, устройств больше лимита."""
from __future__ import annotations

import datetime as dt

from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.export import ExportIndex, unwrap
from api.modules.ksc.core.findings import Finding, finalize


def check_license(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    out = []
    for lic in idx.export.licenses:
        used_raw = unwrap(lic.get("KLLIC_USED_BY_ADM_SRV"))
        used = int(used_raw) if used_raw is not None else -1
        installed = bool(unwrap(lic.get("KLLICSRV_KEY_INSTALLED")))
        if used < 0 and not installed:
            continue  # ключ не используется сервером
        serial = str(unwrap(lic.get("KLLIC_SERIAL")) or "")
        limit = unwrap(lic.get("KLLIC_LIMIT_DATE"))
        days_left = (limit - idx.now).days if isinstance(limit, dt.datetime) else None
        count = int(unwrap(lic.get("KLLIC_LIC_COUNT")) or 0)
        current = int(unwrap(lic.get("KLLIC_NHOSTS_ASCURRENT")) or 0)
        over = max(0, current - count) if count else 0
        expired = days_left is not None and days_left < 0
        expiring = days_left is not None and 0 <= days_left <= cfg.license_days
        if not (expired or expiring or over):
            continue
        severity = "Critical" if expired else "High"
        out.append(finalize(Finding("LICENSE", severity, target=serial, details={
            "name": str(unwrap(lic.get("KLLIC_PROD_NAME")) or ""), "limit_date": limit.strftime("%Y-%m-%d") if isinstance(limit, dt.datetime) else "",
            "days_left": days_left, "expired": expired, "devices": current, "limit": count, "over_limit": over, "role": "активный" if used == 0 else "резервный" if used == 1 else "установлен",
        }), cfg))
    return out
