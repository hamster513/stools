"""User Rights Assignment из GptTmpl.inf политик."""
from __future__ import annotations

import re

from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex
from api.modules.ad.core.findings import Finding, finalize

SID_RE = re.compile(r"^S-1-\d+(-\d+)+$")


def parse_privilege_rights(text: str) -> dict[str, list[str]]:
    """Секция [Privilege Rights]: право = *SID,*SID,имя…"""
    rights: dict[str, list[str]] = {}
    in_section = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            in_section = line.lower() == "[privilege rights]"
            continue
        if not in_section or "=" not in line:
            continue
        right, _, values = line.partition("=")
        entries = [v.strip().lstrip("*") for v in values.split(",") if v.strip()]
        rights[right.strip()] = entries
    return rights


def check_user_rights_assignment(idx: ExportIndex, cfg: AdConfig) -> list[Finding]:
    severity_of = {r.right: r.severity for r in cfg.user_rights}
    out: list[Finding] = []
    for gpo in idx.objects("groupPolicyContainer"):
        text = idx.gpo_inf(gpo)
        if not text:
            continue
        for right, entries in parse_privilege_rights(text).items():
            if right not in severity_of:
                continue
            for entry in entries:
                is_sid = bool(SID_RE.match(entry))
                identity = idx.principal_name(entry) if is_sid else entry
                out.append(
                    finalize(
                        Finding(
                            check="UserRightsAssignment",
                            severity=severity_of[right],
                            identity=identity,
                            identity_sid=entry if is_sid else "",
                            target=gpo.displayName or gpo.dn,
                            right=right,
                            details={"gpo_dn": gpo.dn, "gpo_path": gpo.gpcFileSysPath or ""},
                        ),
                        cfg,
                    )
                )
    return out
