"""Опасные исключения в активных политиках: находка на каждое исключение с рисками (`core/exclusion_risks`)."""
from __future__ import annotations

from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.exclusion_risks import RISKS, exclusion_risks
from api.modules.ksc.core.export import ExportIndex, _int, _str, unwrap
from api.modules.ksc.core.findings import SEVERITY_RANK, Finding, finalize
from api.modules.ksc.core.policy_index import policy_objects
from api.modules.ksc.core.policy_model import exclusion_key


def check_policy_exclusion_risky(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Исключения и доверенные программы активной политики и её профилей, у которых есть риски. Серьёзность — старшая
    из кодов; ключ — политика, профиль и `exclusion_key`. Повтор того же исключения в той же политике и профиле
    (тот же ключ) второй находкой не становится."""
    out: list[Finding] = []
    contents = idx.export.policy_contents
    for policy in idx.export.policies:
        policy_id = _str(policy.get("KLPOL_ID"))
        if not bool(unwrap(policy.get("KLPOL_ACTIVE"))) or policy_id not in contents:
            continue
        objs, _ = policy_objects(idx.export, policy_id)
        target = _str(policy.get("KLPOL_DN")) or policy_id
        seen: set[str] = set()
        for e in objs.exclusions:
            risks = exclusion_risks(e, cfg)
            key_extra = f"{policy_id}|{e.profile}|{exclusion_key(e)}"
            if not risks or key_extra in seen:
                continue
            seen.add(key_extra)
            severity = min((RISKS[code][0] for code in risks), key=SEVERITY_RANK.__getitem__)
            details = {"policy_id": _int(policy.get("KLPOL_ID")), "profile": e.profile, "kind": e.kind, "value": e.value, "risks": risks,
                       "why": [RISKS[code][1] for code in risks], "comment": e.comment}
            out.append(finalize(Finding(check="POLICY_EXCLUSION_RISKY", severity=severity, target=target, details=details, key_extra=key_extra), cfg))
    return out
