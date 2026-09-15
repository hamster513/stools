"""Формула риска (спека §4), чистые функции.

    Risk  = EPSS × (CVSS ÷ 10) × Impact × CVE_param × ExDB_param × MSF_param
    score = round(min(1, Risk) × 100)

Раскладывается на множитель CVE (`cve_factor`) и множитель хоста
(`host_impact`): первый зависит только от справочников, второй — только
от критичности и зоны. Это и позволяет пересчитывать миллионы пар одним
запросом (спека §3).

Каждая подстановка при отсутствии данных возвращается флагом в
`RiskExplanation`: карточка обязана показывать, что число не измерено,
а взято по умолчанию.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Literal

from api.modules.vm.core.weights import EPSS_FALLBACK, MSF_RANKS, Weights

Level = Literal["low", "medium", "high", "critical"]

LEVEL_WORD: dict[Level, str] = {
    "low": "низкий",
    "medium": "средний",
    "high": "высокий",
    "critical": "критический",
}


@dataclass(frozen=True)
class CveInputs:
    epss: float | None = None
    cvss: float | None = None
    v3_av: str | None = None
    v3_pr: str | None = None
    v3_ui: str | None = None
    v2_av: str | None = None
    v2_ac: str | None = None
    v2_au: str | None = None
    exploitdb_type: str | None = None
    msf_rank: str | None = None


@dataclass
class Factor:
    """Один множитель формулы: значение и откуда оно."""

    value: float
    #: Что стояло на входе (метрика, тип, ранг) — для карточки.
    source: str
    #: Данных не было, значение взято по умолчанию.
    substituted: bool = False


@dataclass
class RiskExplanation:
    epss: Factor
    cvss: Factor
    cve_param: Factor
    exdb_param: Factor
    msf_param: Factor
    impact: Factor
    impact_parts: dict[str, Factor] = field(default_factory=dict)
    raw: float = 0.0
    score: int = 0
    level: Level = "low"


def score(raw: float) -> int:
    return round(min(1.0, max(0.0, raw)) * 100)


def level(value: int) -> Level:
    if value >= 70:
        return "critical"
    if value >= 40:
        return "high"
    if value >= 20:
        return "medium"
    return "low"


def rank_name(rank: int) -> str:
    """Имя ранга Metasploit по числу; неизвестные числа — `unknown`."""
    return MSF_RANKS.get(rank, "unknown")


def best_exploit_type(types: Iterable[str], w: Weights) -> str | None:
    """Тип эксплойта с наибольшим весом: у CVE может быть несколько."""
    known = [t.lower() for t in types if t]
    if not known:
        return None
    return max(known, key=lambda t: w.exploitdb.get(t, 1.0))


def best_msf_rank(ranks: Iterable[int], w: Weights) -> str | None:
    names = [rank_name(r) for r in ranks]
    if not names:
        return None
    return max(names, key=lambda n: w.msf.get(n, 1.0))


def _epss(c: CveInputs) -> Factor:
    if c.epss is None:
        return Factor(EPSS_FALLBACK, "нет в EPSS", substituted=True)
    return Factor(float(c.epss), "EPSS")


def _cvss(c: CveInputs) -> Factor:
    if c.cvss is None:
        return Factor(1.0, "нет CVSS", substituted=True)
    return Factor(float(c.cvss) / 10.0, f"CVSS {c.cvss:g}")


def _cve_param(c: CveInputs, w: Weights) -> Factor:
    if c.v3_av:
        av = w.cvss_v3.av.get(c.v3_av, 1.0)
        pr = w.cvss_v3.pr.get(c.v3_pr or "", 1.0)
        ui = w.cvss_v3.ui.get(c.v3_ui or "", 1.0)
        return Factor(av * pr * ui, f"v3 AV={c.v3_av} PR={c.v3_pr} UI={c.v3_ui}")
    if c.v2_av:
        av = w.cvss_v2.av.get(c.v2_av, 1.0)
        ac = w.cvss_v2.ac.get(c.v2_ac or "", 1.0)
        au = w.cvss_v2.au.get(c.v2_au or "", 1.0)
        return Factor(av * ac * au, f"v2 AV={c.v2_av} AC={c.v2_ac} Au={c.v2_au}")
    return Factor(1.0, "нет метрик CVSS", substituted=True)


def _exdb_param(c: CveInputs, w: Weights) -> Factor:
    if not c.exploitdb_type:
        return Factor(1.0, "нет в ExploitDB", substituted=True)
    return Factor(w.exploitdb.get(c.exploitdb_type, 1.0), f"ExploitDB {c.exploitdb_type}")


def _msf_param(c: CveInputs, w: Weights) -> Factor:
    if not c.msf_rank:
        return Factor(1.0, "нет модуля Metasploit", substituted=True)
    return Factor(w.msf.get(c.msf_rank, 1.0), f"Metasploit {c.msf_rank}")


def cve_factor(c: CveInputs, w: Weights) -> float:
    return (
        _epss(c).value
        * _cvss(c).value
        * _cve_param(c, w).value
        * _exdb_param(c, w).value
        * _msf_param(c, w).value
    )


def host_impact(
    criticality: str | None, internet: bool, confidential: bool, w: Weights
) -> float:
    crit = criticality if criticality is not None and criticality in w.impact.criticality else "None"
    return (
        w.impact.criticality[crit]
        + w.impact.confidential["yes" if confidential else "no"]
        + w.impact.internet["yes" if internet else "no"]
    )


def explain(
    c: CveInputs,
    criticality: str | None,
    internet: bool,
    confidential: bool,
    zone_marked: bool,
    w: Weights,
) -> RiskExplanation:
    crit_known = criticality is not None and criticality in w.impact.criticality
    crit: str = criticality if crit_known and criticality is not None else "None"
    parts = {
        "criticality": Factor(
            w.impact.criticality[crit],
            crit if crit_known else "критичность не задана",
            substituted=not crit_known,
        ),
        "confidential": Factor(
            w.impact.confidential["yes" if confidential else "no"],
            "есть" if confidential else "нет",
            substituted=not zone_marked,
        ),
        "internet": Factor(
            w.impact.internet["yes" if internet else "no"],
            "доступен" if internet else "недоступен",
            substituted=not zone_marked,
        ),
    }
    impact_value = sum(p.value for p in parts.values())
    e = RiskExplanation(
        epss=_epss(c),
        cvss=_cvss(c),
        cve_param=_cve_param(c, w),
        exdb_param=_exdb_param(c, w),
        msf_param=_msf_param(c, w),
        impact=Factor(impact_value, "сумма слагаемых", substituted=not zone_marked),
        impact_parts=parts,
    )
    e.raw = (
        e.epss.value
        * e.cvss.value
        * e.cve_param.value
        * e.exdb_param.value
        * e.msf_param.value
        * e.impact.value
    )
    e.score = score(e.raw)
    e.level = level(e.score)
    return e
