"""Опасные исключения в активных политиках: находка на каждое исключение с рисками (`core/exclusion_risks`)."""
from __future__ import annotations

from typing import Any

from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.exclusion_risks import RISKS, exclusion_risks
from api.modules.ksc.core.export import ExportIndex, _int, _str, unwrap
from api.modules.ksc.core.findings import SEVERITY_RANK, Finding, finalize
from api.modules.ksc.core.policy_index import policy_objects, profile_enabled
from api.modules.ksc.core.policy_model import Exclusion, exclusion_key


def _disabled_profiles(idx: ExportIndex, policy_id: str) -> set[str]:
    """Имена выключенных профилей политики (`KLSSPOL_PRF_ENABLED`, как в `policy_index.profile_rows`)."""
    entry = (idx.export.policy_profiles or {}).get(policy_id) or {}
    return {_str(pr.get("name")) for pr in entry.get("profiles") or [] if not profile_enabled((pr.get("attrs") or {}).get("KLSSPOL_PRF_ENABLED", True))}


def check_policy_exclusion_risky(idx: ExportIndex, cfg: KscConfig) -> list[Finding]:
    """Исключения и доверенные программы активной политики и её включённых профилей, у которых есть риски. Ключ — политика,
    профиль и `exclusion_key`; записи с одним ключом (тот же вид и значение) — одна находка с объединением кодов,
    серьёзность — старшая из кодов. Копия в профиле исключения самой политики своей находки не даёт."""
    out: list[Finding] = []
    contents = idx.export.policy_contents
    for policy in idx.export.policies:
        policy_id = _str(policy.get("KLPOL_ID"))
        if not bool(unwrap(policy.get("KLPOL_ACTIVE"))) or policy_id not in contents:
            continue
        objs, _ = policy_objects(idx.export, policy_id)
        disabled = _disabled_profiles(idx, policy_id)
        target = _str(policy.get("KLPOL_DN")) or policy_id
        # Записи самой политики идут первыми (`policy_objects`), поэтому её ключи известны до профилей.
        own: set[str] = set()
        found: dict[str, tuple[Exclusion, set[str]]] = {}
        for e in objs.exclusions:
            risks = exclusion_risks(e, cfg)
            key = exclusion_key(e)
            if not risks or e.profile in disabled or (e.profile and key in own):
                continue
            if not e.profile:
                own.add(key)
            found.setdefault(f"{policy_id}|{e.profile}|{key}", (e, set()))[1].update(risks)
        for key_extra, (e, codes) in found.items():
            risks = [code for code in RISKS if code in codes]
            severity = min((RISKS[code].severity for code in risks), key=SEVERITY_RANK.__getitem__)
            details: dict[str, Any] = {"policy_id": _int(policy.get("KLPOL_ID")), "profile": e.profile, "kind": e.kind, "value": e.value,
                                       "risks": risks, "why": [RISKS[code].title for code in risks], "comment": e.comment}
            out.append(finalize(Finding(check="POLICY_EXCLUSION_RISKY", severity=severity, target=target, details=details, key_extra=key_extra), cfg))
    return out
