"""Права на критичные объекты: корень домена."""
from __future__ import annotations

from api.modules.ad.core import sd
from api.modules.ad.core.checks import principals
from api.modules.ad.core.checks.adcs_rules import writers_details
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex
from api.modules.ad.core.findings import Finding, finalize

#: Права, дающие полный контроль над доменом (в том числе выдачу себе DCSync).
ROOT_RIGHTS = sd.GENERIC_ALL | sd.WRITE_DACL | sd.WRITE_OWNER
#: SELF и CREATOR OWNER — подстановки, а не субъекты: права получает сам объект или его создатель.
_PLACEHOLDERS = ("S-1-5-10", "S-1-3-0")


def check_domain_root_acl(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    root = idx.root
    desc = idx.sd_of(root) if root is not None else None
    if root is None or desc is None:
        return []
    out = []
    for writer in principals.tier0_writers(idx, cfg, root, desc, ROOT_RIGHTS):
        sid, _, rights = writer
        if sid in _PLACEHOLDERS:
            continue
        severity, details = writers_details(idx, [writer], "Право менять права или владельца корня домена — путь к полному контролю над доменом", "Critical")
        f = Finding(
            check="DomainRootAcl", severity=severity, identity=idx.principal_name(sid), identity_sid=sid,
            target=root.dn, right=", ".join(rights), details=details,
        )
        out.append(finalize(f, cfg))
    return out
