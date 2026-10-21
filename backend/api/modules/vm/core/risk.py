"""Формула риска (спека 2026-10-21 §9), чистые функции.

    Risk = round(100 × L × S × V), от 0 до 100

    L — вероятность эксплуатации, 0..1:
        1.0, если CVE в каталоге CISA KEV (эксплуатация — факт, а не прогноз);
        иначе 1 − (1 − EPSS') × (1 − p_exdb[тип лучшего эксплойта]) × (1 − p_msf[лучший ранг])
        EPSS' = EPSS или prior_epss («не измерено»)
    S — тяжесть, 0..1: CVSS ÷ 10 (или cvss_missing) × reach[вектор атаки, доступ из интернета]
    V — ценность хоста, 0.4..1: min(1, crit[критичность] + conf_bonus × конф. + inet_bonus × интернет)

    Уровень — из балла по порогам настроек (`Weights.levels`), при чтении.

Свидетельства эксплуатации объединяются как независимые вероятности: любое
из них поднимает L, ни одно не обнуляет остальные (EPSS множителем в первой
итерации обнулял и CVSS, и хост, и эксплойты).

Раскладка для массового пересчёта: L зависит только от CVE (`vm_cve.likelihood`),
V — только от хоста (`vm_host.value`), S — от CVE (`cvss10`, `av_class`) и
доступа хоста из интернета (`vm_host.internet`); reach считается в SQL `CASE`.
Так пересчёт миллионов пар остаётся одним UPDATE (`services/scoring.rescore_pairs`).

Каждая подстановка при отсутствии данных возвращается флагом в
`RiskExplanation`: карточка обязана показывать, что число не измерено,
а взято по умолчанию.
"""
from __future__ import annotations

import datetime as dt
import math
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Literal

from api.modules.vm.core.weights import MSF_RANKS, Levels, Weights

Level = Literal["low", "medium", "high", "critical"]
LEVELS: tuple[Level, ...] = ("low", "medium", "high", "critical")

LEVEL_WORD: dict[Level, str] = {
    "low": "низкий",
    "medium": "средний",
    "high": "высокий",
    "critical": "критический",
}

#: Классы вектора атаки: v3 и v2 называют их по-разному, формуле важен только класс.
AV_CLASSES = ("network", "adjacent", "local", "none")
_AV_CLASS = {
    "NETWORK": "network",
    "ADJACENT_NETWORK": "adjacent",
    "ADJACENT": "adjacent",
    "LOCAL": "local",
    "PHYSICAL": "local",
}


@dataclass(frozen=True)
class CveInputs:
    epss: float | None = None
    cvss: float | None = None
    #: Вектор атаки как в NVD: v3, а если его нет — v2.
    av: str | None = None
    exploitdb_type: str | None = None
    msf_rank: str | None = None
    kev: bool = False
    kev_added: dt.date | None = None
    #: Справочник KEV загружен: без него «нет в KEV» — не факт, а незнание.
    kev_loaded: bool = True


@dataclass
class Factor:
    """Один член формулы: значение и откуда оно."""

    value: float
    #: Что стояло на входе (метрика, тип, ранг) — для карточки.
    source: str
    #: Данных не было, значение взято по умолчанию.
    substituted: bool = False


@dataclass
class RiskExplanation:
    likelihood: Factor
    severity: Factor
    value: Factor
    likelihood_parts: dict[str, Factor] = field(default_factory=dict)
    severity_parts: dict[str, Factor] = field(default_factory=dict)
    value_parts: dict[str, Factor] = field(default_factory=dict)
    raw: float = 0.0
    score: int = 0
    level: Level = "low"


def score(raw: float) -> int:
    """Округление половинок вверх — как `FLOOR(x + 0.5)` в пересчёте пар: Python `round`
    округлял бы до чётного, и карточка расходилась бы со списком на единицу."""
    return math.floor(min(1.0, max(0.0, raw)) * 100.0 + 0.5)


def level(value: int, levels: Levels) -> Level:
    if value >= levels.critical:
        return "critical"
    if value >= levels.high:
        return "high"
    if value >= levels.medium:
        return "medium"
    return "low"


def rank_name(rank: int) -> str:
    """Имя ранга Metasploit по числу; неизвестные числа — `unknown`."""
    return MSF_RANKS.get(rank, "unknown")


def best_exploit_type(types: Iterable[str], w: Weights) -> str | None:
    """Тип эксплойта с наибольшей вероятностью: у CVE может быть несколько."""
    known = [t.lower() for t in types if t]
    if not known:
        return None
    return max(known, key=lambda t: w.p_exdb.get(t, 0.0))


def best_msf_rank(ranks: Iterable[int], w: Weights) -> str | None:
    names = [rank_name(r) for r in ranks]
    if not names:
        return None
    return max(names, key=lambda n: w.p_msf.get(n, 0.0))


def av_class(v3_av: str | None, v2_av: str | None) -> str:
    """network | adjacent | local | none — по v3, а без него по v2."""
    av = v3_av or v2_av
    return _AV_CLASS.get((av or "").upper(), "none")


def reach(cls: str, internet: bool, w: Weights) -> float:
    if cls == "network":
        return w.reach.network_internet if internet else w.reach.network_internal
    if cls == "adjacent":
        return w.reach.adjacent
    if cls == "local":
        return w.reach.local
    return w.reach_unknown


def _likelihood_parts(c: CveInputs, w: Weights) -> dict[str, Factor]:
    if not c.kev_loaded:
        kev = Factor(0.0, "справочник KEV не загружен", substituted=True)
    elif c.kev:
        kev = Factor(1.0, f"CISA KEV, с {c.kev_added:%d.%m.%Y}" if c.kev_added else "CISA KEV")
    else:
        # Отсутствие в каталоге — факт о CVE, а не подстановка (спека §8).
        kev = Factor(0.0, "нет в KEV")
    if c.epss is None:
        epss = Factor(w.prior_epss, "нет в EPSS — не измерено", substituted=True)
    else:
        epss = Factor(float(c.epss), "EPSS")
    if c.exploitdb_type:
        exploit = Factor(w.p_exdb.get(c.exploitdb_type, 0.0), f"ExploitDB {c.exploitdb_type}")
    else:
        exploit = Factor(0.0, "нет в ExploitDB")
    if c.msf_rank:
        msf = Factor(w.p_msf.get(c.msf_rank, 0.0), f"Metasploit {c.msf_rank}")
    else:
        msf = Factor(0.0, "нет модуля Metasploit")
    return {"kev": kev, "epss": epss, "exploit": exploit, "msf": msf}


def likelihood(c: CveInputs, w: Weights) -> tuple[Factor, dict[str, Factor]]:
    """L и его части (KEV, EPSS, эксплойт, Metasploit) — для витрины и карточки."""
    parts = _likelihood_parts(c, w)
    if c.kev:
        return Factor(1.0, "в каталоге KEV — эксплуатируется"), parts
    miss = (1.0 - parts["epss"].value) * (1.0 - parts["exploit"].value) * (1.0 - parts["msf"].value)
    total = Factor(
        1.0 - miss,
        "1 − (1 − EPSS) × (1 − ExploitDB) × (1 − Metasploit)",
        substituted=parts["epss"].substituted,
    )
    return total, parts


def host_value(criticality: str | None, internet: bool, confidential: bool, w: Weights) -> float:
    crit = criticality if criticality is not None and criticality in w.value.criticality else "None"
    return min(
        1.0,
        w.value.criticality[crit]
        + (w.value.conf_bonus if confidential else 0.0)
        + (w.value.inet_bonus if internet else 0.0),
    )


def _severity_parts(c: CveInputs, internet: bool, zone_marked: bool, w: Weights) -> dict[str, Factor]:
    if c.cvss is None:
        cvss = Factor(w.cvss_missing, "нет CVSS", substituted=True)
    else:
        cvss = Factor(float(c.cvss) / 10.0, f"CVSS {c.cvss:g}")
    cls = av_class(c.av, None)
    if cls == "none":
        r = Factor(w.reach_unknown, "нет вектора атаки", substituted=True)
    elif cls == "network":
        # Сетевой вектор зависит от доступа из интернета; у неразмеченной зоны его не знают.
        where = "хост из интернета" if internet else "хост внутри"
        r = Factor(reach(cls, internet, w), f"вектор {c.av}, {where}", substituted=not zone_marked)
    else:
        r = Factor(reach(cls, internet, w), f"вектор {c.av}")
    return {"cvss": cvss, "reach": r}


def explain(
    c: CveInputs,
    criticality: str | None,
    internet: bool,
    confidential: bool,
    zone_marked: bool,
    w: Weights,
) -> RiskExplanation:
    l_total, l_parts = likelihood(c, w)
    s_parts = _severity_parts(c, internet, zone_marked, w)
    s_total = Factor(
        s_parts["cvss"].value * s_parts["reach"].value,
        "CVSS ÷ 10 × достижимость",
        substituted=any(p.substituted for p in s_parts.values()),
    )
    crit_known = criticality is not None and criticality in w.value.criticality
    crit: str = criticality if crit_known and criticality is not None else "None"
    v_parts = {
        "criticality": Factor(
            w.value.criticality[crit],
            crit if crit_known else "критичность не задана",
            substituted=not crit_known,
        ),
        "confidential": Factor(
            w.value.conf_bonus if confidential else 0.0,
            "есть" if confidential else "нет",
            substituted=not zone_marked,
        ),
        "internet": Factor(
            w.value.inet_bonus if internet else 0.0,
            "доступен" if internet else "недоступен",
            substituted=not zone_marked,
        ),
    }
    v_total = Factor(
        host_value(criticality, internet, confidential, w),
        "сумма слагаемых, не больше 1",
        substituted=not zone_marked,
    )
    e = RiskExplanation(
        likelihood=l_total,
        severity=s_total,
        value=v_total,
        likelihood_parts=l_parts,
        severity_parts=s_parts,
        value_parts=v_parts,
    )
    # Тот же порядок умножения, что в SQL пересчёта (L × CVSS × reach × V):
    # иначе на границе половинки карточка и список могли бы разойтись.
    e.raw = l_total.value * s_parts["cvss"].value * s_parts["reach"].value * v_total.value
    e.score = score(e.raw)
    e.level = level(e.score, w.levels)
    return e
