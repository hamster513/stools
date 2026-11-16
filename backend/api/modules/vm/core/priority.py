"""Additive remediation priority; never interpreted as probability.

The same policy is used by SQL persistence, API explanations and offline comparison.
"""
from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass

from api.modules.vm.core.risk import CveInputs, av_class, rank_name, score

MODEL_VERSION = "priority-v2"
CAPS = {"exploitation": 40, "severity": 25, "exposure": 20, "asset": 15}
LEVELS = {"medium": 40, "high": 80, "critical": 85}
READY_MSF = frozenset({"good", "great", "excellent"})


def strongest_msf_rank(ranks: Iterable[int]) -> str | None:
    """Select ready exploit evidence independently of legacy probability weights."""
    rank = max(ranks, key=lambda value: (rank_name(value) in READY_MSF, value), default=None)
    return rank_name(rank) if rank is not None else None


@dataclass(frozen=True)
class AssetContext:
    criticality: str | None = None
    internet: bool | None = None
    confidential: bool | None = None


@dataclass(frozen=True)
class Block:
    points: float
    maximum: int
    reason: str
    assumed: bool = False


@dataclass(frozen=True)
class PriorityScore:
    score: int
    base_score: int
    level: str
    blocks: dict[str, Block]
    floor: int
    rules: tuple[str, ...]
    missing: tuple[str, ...]
    version: str = MODEL_VERSION


def _validate(value: float | None, maximum: float, name: str) -> None:
    if value is not None and (not math.isfinite(value) or not 0 <= value <= maximum):
        raise ValueError(f"Invalid {name}: expected 0..{maximum}")


def priority_policy(high_threshold: int | None = None) -> dict:
    threshold = LEVELS["high"] if high_threshold is None else high_threshold
    if type(threshold) is not int or not LEVELS["medium"] < threshold < LEVELS["critical"]:
        raise ValueError("High threshold must be an integer between Medium (40) and Critical (85)")
    return {"version": f"{MODEL_VERSION}-h{threshold}", "caps": dict(CAPS),
            "levels": dict(LEVELS, high=threshold),
            "floors": {"kev_minimum": max(70, threshold), "kev_network_external_zone": 90,
                       "ready_exploit_critical_asset": 85}}


def priority_score(c: CveInputs, context: AssetContext, *, high_threshold: int | None = None) -> PriorityScore:
    policy = priority_policy(high_threshold)
    _validate(c.cvss, 10, "CVSS")
    _validate(c.epss, 1, "EPSS")
    missing: list[str] = []
    if c.epss is None:
        missing.append("epss")
        epss_points = 8
        epss_reason = "epss_unknown"
    else:
        epss_points = next((points for upper, points in (
            (.001, 2), (.01, 6), (.1, 12), (.5, 20), (float("inf"), 30),
        ) if c.epss < upper), 30)
        epss_reason = "epss_band"
    if not c.kev_loaded and not c.kev:
        missing.append("kev_catalog")
    signals = [(epss_points, epss_reason, c.epss is None)]
    if c.exploitdb_type or c.msf_rank:
        signals.append((24, "public_exploit", False))
    if c.msf_rank in READY_MSF:
        signals.append((32, "ready_metasploit", False))
    if c.kev:
        signals.append((40, "recorded_exploitation_kev", False))
    threat, reason, assumed = max(signals, key=lambda item: item[0])
    blocks = {"exploitation": Block(threat, CAPS["exploitation"], reason, assumed)}
    if c.cvss is None:
        missing.append("cvss")
    blocks["severity"] = Block(12.5 if c.cvss is None else c.cvss * 2.5,
                               CAPS["severity"], "cvss_unknown" if c.cvss is None else "cvss", c.cvss is None)
    vector = av_class(c.av, None)
    if vector == "network":
        if context.internet is None:
            exposure, exposure_reason = 12, "network_zone_unknown"
            missing.append("exposure")
        elif context.internet:
            exposure, exposure_reason = 20, "network_external_zone"
        else:
            exposure, exposure_reason = 10, "network_internal_zone"
    elif vector in {"local", "adjacent"}:
        exposure = 4 if vector == "local" else 8
        exposure_reason = vector + "_vector"
    else:
        exposure, exposure_reason = 12, "vector_unknown"
        missing.append("attack_vector")
    blocks["exposure"] = Block(exposure, CAPS["exposure"], exposure_reason,
                               "exposure" in missing or "attack_vector" in missing)
    values = {"Critical": 15, "High": 12, "Medium": 8, "Low": 4}
    asset = values.get(context.criticality, 8)
    if context.criticality not in values:
        missing.append("criticality")
    if context.confidential is None:
        missing.append("confidentiality")
    if context.confidential:
        asset = min(15, asset + 2)
    blocks["asset"] = Block(asset, CAPS["asset"],
                            "criticality_and_confidentiality" if context.confidential else "criticality",
                            "criticality" in missing or "confidentiality" in missing)
    floors: dict[str, int] = {}
    if c.kev:
        floors["kev_minimum"] = policy["floors"]["kev_minimum"]
    if c.kev and vector == "network" and context.internet is True:
        floors["kev_network_external_zone"] = policy["floors"]["kev_network_external_zone"]
    if c.msf_rank in READY_MSF and c.cvss is not None and c.cvss >= 9 and context.criticality == "Critical":
        floors["ready_exploit_critical_asset"] = policy["floors"]["ready_exploit_critical_asset"]
    floor = max(floors.values(), default=0)
    base = score(sum(block.points for block in blocks.values()) / 100)
    result = max(base, floor)
    level = next((name for name in ("critical", "high", "medium") if result >= policy["levels"][name]), "low")
    return PriorityScore(result, base, level, blocks, floor, tuple(floors), tuple(missing), policy["version"])
