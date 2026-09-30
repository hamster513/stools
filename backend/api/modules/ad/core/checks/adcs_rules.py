"""AD CS: кто заявитель — безопасный, широкая группа или прочий; серьёзность.

Правило перевёрнуто относительно остальных проверок: безопасны только
заведомые администраторы (adcs_safe_*), любой другой субъект — под вопросом.
Широкие группы (low_priv_*) дают базовую серьёзность ESC, прочие — на ступень
ниже: состав такой группы надо смотреть руками.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Literal

from api.modules.ad.core import sd
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex
from api.modules.ad.core.findings import SEVERITIES, short_name
from api.modules.ad.core.sd import SecurityDescriptor

Kind = Literal["safe", "broad", "other"]

WRITE_RIGHTS = sd.GENERIC_ALL | sd.GENERIC_WRITE | sd.WRITE_DACL | sd.WRITE_OWNER | sd.WRITE_PROPERTY

CHECK_MEMBERS_NOTE = "проверьте состав группы"


def _forest_rid(sid: str) -> int | None:
    """RID доменного SID любого домена леса (S-1-5-21-…); у прочих — None."""
    if not sid.startswith("S-1-5-21-"):
        return None
    try:
        return int(sid.rsplit("-", 1)[1])
    except ValueError:
        return None


def _name_in(name: str, names: list[str]) -> bool:
    wanted = {n.upper().strip() for n in names}
    return name.upper().strip() in wanted or short_name(name) in wanted


def requester_kind(idx: ExportIndex, cfg: AdConfig, sid: str) -> Kind:
    """safe — из adcs_safe_* (RID — для любого домена S-1-5-21-…); broad — low_priv_sids,
    low_priv_rids любого домена, low_priv_groups по имени; иначе other."""
    rid = _forest_rid(sid)
    name = idx.principal_name(sid)
    if sid in cfg.adcs_safe_sids or (rid is not None and rid in cfg.adcs_safe_rids) or _name_in(name, cfg.adcs_safe_principals):
        return "safe"
    if sid in cfg.low_priv_sids or (rid is not None and rid in cfg.low_priv_rids) or _name_in(name, cfg.low_priv_groups):
        return "broad"
    return "other"


def step_down(severity: str) -> str:
    """Critical→High→Medium→Low→Low; Info остаётся Info."""
    if severity not in SEVERITIES or severity in ("Low", "Info"):
        return severity
    return SEVERITIES[SEVERITIES.index(severity) + 1]


def severity_for(base: str, kinds: Iterable[Kind]) -> str:
    """base, если среди заявителей есть broad; иначе на ступень ниже."""
    return base if "broad" in kinds else step_down(base)


def unsafe_writers(idx: ExportIndex, cfg: AdConfig, desc: SecurityDescriptor) -> list[tuple[str, Kind]]:
    """(sid, kind) небезопасных субъектов с любым из WRITE_RIGHTS в разрешающих ACE."""
    out: dict[str, Kind] = {}
    for ace in desc.dacl:
        # inherit-only ACE действует только на потомков, не на сам объект.
        if not ace.allow or ace.inherit_only or not (ace.mask & WRITE_RIGHTS) or ace.sid in out:
            continue
        kind = requester_kind(idx, cfg, ace.sid)
        if kind != "safe":
            out[ace.sid] = kind
    return list(out.items())


def principals_details(idx: ExportIndex, principals: list[tuple[str, Kind]], text: str, base: str) -> tuple[str, dict[str, object]]:
    """Серьёзность по худшему заявителю и общие поля деталей находки."""
    kinds = [k for _, k in principals]
    broad = "broad" in kinds
    if not broad:
        text = f"{text}; {CHECK_MEMBERS_NOTE}"
    return severity_for(base, kinds), {
        "details": text,
        "requesters": sorted({idx.principal_name(s) for s, _ in principals}),
        "requesters_broad": broad,
    }
