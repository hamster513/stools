"""Карточка расчёта риска: одинаковый вид для пары хост–CVE и для находки образа.

Расчёт — `core/risk.explain`; здесь только сборка входов из строки витрины `vm_cve` и
разбор объяснения в словарь ответа.
"""
from __future__ import annotations

from typing import Any

from api.modules.vm.core.risk import LEVEL_WORD, CveInputs, RiskExplanation
from api.modules.vm.core.risk import level as risk_level
from api.modules.vm.models import VmCve
from api.modules.vm.services.settings import VmSettings


def factor(fac: Any) -> dict[str, Any]:
    return {"value": fac.value, "source": fac.source, "substituted": fac.substituted}


def cve_inputs(cve: VmCve, *, kev_loaded: bool) -> CveInputs:
    """Входы формулы из витрины; `kev_loaded` — загружен ли справочник KEV (без него «нет в KEV» — незнание)."""
    return CveInputs(
        epss=cve.epss,
        cvss=cve.cvss,
        av=cve.v3_av or cve.v2_av,
        exploitdb_type=cve.exploitdb_type,
        msf_rank=cve.msf_rank,
        kev=cve.kev,
        kev_added=cve.kev_added,
        kev_loaded=kev_loaded,
    )


def risk_view(e: RiskExplanation, settings: VmSettings, score: int, raw: float) -> dict[str, Any]:
    """Балл и уровень — сохранённые (по ним список и фильтры); части — расчёт по текущим весам:
    после смены весов до пересчёта они могут разойтись с баллом."""
    lvl = risk_level(score, settings.weights.levels)
    return {
        "score": score,
        "raw": raw,
        "level": lvl,
        "level_word": LEVEL_WORD[lvl],
        "threshold": settings.threshold,
        "likelihood": factor(e.likelihood),
        "likelihood_parts": {k: factor(v) for k, v in e.likelihood_parts.items()},
        "severity": factor(e.severity),
        "severity_parts": {k: factor(v) for k, v in e.severity_parts.items()},
        "value": factor(e.value),
        "value_parts": {k: factor(v) for k, v in e.value_parts.items()},
    }
