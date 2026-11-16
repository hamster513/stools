"""Shared additive-priority explanation for host and image findings."""
from __future__ import annotations

from typing import Any

from api.modules.vm.core.priority import PriorityScore, priority_policy
from api.modules.vm.core.risk import LEVEL_WORD, CveInputs
from api.modules.vm.core.risk import level as risk_level
from api.modules.vm.models import VmCve
from api.modules.vm.services.settings import VmSettings

LABELS = {"exploitation": "Эксплуатация", "severity": "Последствия", "exposure": "Доступность", "asset": "Значимость актива"}
REASONS = {
    "epss_unknown": "EPSS не измерен", "epss_band": "Баллы по диапазону EPSS",
    "public_exploit": "Опубликованный эксплойт ExploitDB или Metasploit",
    "ready_metasploit": "Metasploit good/great/excellent", "recorded_exploitation_kev": "Эксплуатация отмечена в CISA KEV",
    "cvss_unknown": "CVSS отсутствует", "cvss": "CVSS × 2,5",
    "network_zone_unknown": "Сетевой вектор; зона не размечена", "network_external_zone": "Сетевой вектор; внешняя зона",
    "network_internal_zone": "Сетевой вектор; внутренняя зона", "adjacent_vector": "Смежная сеть",
    "local_vector": "Локальный или физический вектор", "vector_unknown": "Вектор атаки неизвестен",
    "criticality": "Критичность актива", "criticality_and_confidentiality": "Критичность и конфиденциальные данные",
}
MISSING = {"epss": "EPSS", "kev_catalog": "сведения KEV", "cvss": "CVSS", "exposure": "разметка зоны",
           "attack_vector": "вектор атаки", "criticality": "критичность актива", "confidentiality": "конфиденциальность"}
RULES = {"kev_minimum": "KEV: не ниже High", "kev_network_external_zone": "Сетевой KEV во внешней зоне",
         "ready_exploit_critical_asset": "Готовый Metasploit, CVSS ≥9 и критичный актив"}


def cve_inputs(cve: VmCve, *, kev_loaded: bool) -> CveInputs:
    return CveInputs(epss=cve.epss, cvss=cve.cvss, av=cve.v3_av or cve.v2_av,
                     exploitdb_type=cve.exploitdb_type, msf_rank=cve.msf_rank,
                     kev=cve.kev, kev_added=cve.kev_added, kev_loaded=kev_loaded)


def risk_view(e: PriorityScore, settings: VmSettings, score: int, raw: float) -> dict[str, Any]:
    """Stored score drives lists; computed_score exposes any pending recalculation."""
    policy = priority_policy()
    lvl = risk_level(score, settings.weights.levels)
    return {
        "score": score, "raw": raw, "level": lvl, "level_word": LEVEL_WORD[lvl],
        "threshold": settings.threshold, "model": "additive", "model_version": e.version,
        "levels": policy["levels"], "base_score": e.base_score, "computed_score": e.score,
        "blocks": {key: {"label": LABELS[key], "points": block.points, "maximum": block.maximum,
                          "source": REASONS[block.reason], "assumed": block.assumed} for key, block in e.blocks.items()},
        "floor": e.floor, "rules": [{"code": code, "label": RULES[code], "minimum": policy["floors"][code]} for code in e.rules],
        "missing": [MISSING[key] for key in e.missing],
    }
