"""Находка проверки, allowlist и стабильный ключ (спека §4–5)."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from api.modules.ad.core.config import AdConfig

SEVERITY_RANK = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 5}
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


#: slots: у крупного домена сотни тысяч находок — без словаря атрибутов у каждой.
@dataclass(slots=True)
class Finding:
    check: str
    severity: str
    identity: str = ""
    identity_sid: str = ""
    target: str = ""
    right: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    #: Компоненты ключа сверх стандартных: для проверок, где идентичность
    #: находки определяется не identity/target/right (ESC-номер и т. п.).
    key_extra: str = ""
    severity_original: str = ""
    allowlisted: bool = False
    key: str = ""

    def __post_init__(self) -> None:
        if not self.severity_original:
            self.severity_original = self.severity


def short_name(identity: str) -> str:
    """`CORP\\Domain Admins` → `DOMAIN ADMINS`; без домена — как есть."""
    return identity.rsplit("\\", 1)[-1].upper().strip()


def is_allowlisted(identity: str, cfg: AdConfig) -> bool:
    full = identity.upper().strip()
    if full in {a.upper() for a in cfg.allowlist_full}:
        return True
    return short_name(identity) in {a.upper() for a in cfg.allowlist_short}


def is_low_priv(identity: str, sid: str | None, cfg: AdConfig, domain_sid: str) -> bool:
    if sid:
        if sid in cfg.low_priv_sids:
            return True
        if sid.startswith(domain_sid + "-"):
            try:
                if int(sid.rsplit("-", 1)[1]) in cfg.low_priv_rids:
                    return True
            except ValueError:
                pass
    upper = identity.upper().strip()
    groups = {g.upper() for g in cfg.low_priv_groups}
    return upper in groups or short_name(identity) in groups


def finding_key(f: Finding) -> str:
    ident = f.identity_sid or f.identity.upper()
    raw = f"{f.check}|{ident}|{f.target.lower()}|{f.right}|{f.key_extra}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def finalize(f: Finding, cfg: AdConfig, *, allowlist: bool = True) -> Finding:
    """Allowlist понижает до Low и помечает; ключ считается по исходным полям."""
    if allowlist and f.identity and is_allowlisted(f.identity, cfg):
        f.allowlisted = True
        f.severity = "Low"
    f.key = finding_key(f)
    return f
