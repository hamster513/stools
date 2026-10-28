"""Проверка пакета движком сетевого экрана (спека §4.7, §5.3): сторона источника и, если назначение — хост снапшота,
сторона назначения; пакетная проверка той же связи у списка источников.

Способ наложения профиля на список политики — настройка модуля `firewall_profile_mode` (`KscConfig`).
"""
from __future__ import annotations

import ipaddress
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.ksc.core.firewall.evaluate import Branch, SideResult, Step, evaluate_side
from api.modules.ksc.core.firewall.model import Packet, Protocol, RuleView, Verdict
from api.modules.ksc.models import KscHost, KscSnapshot
from api.modules.ksc.services.firewall import load_host_firewall
from api.modules.ksc.services.host_scope import find_host
from api.modules.ksc.services.policy_store import ensure_policy_tables
from api.modules.ksc.services.settings import load_config
from api.settings import Settings, get_settings

router = APIRouter(tags=["ksc"])

#: Источников в пакетной проверке не больше (спека §5.3).
MAX_SOURCES = 50
PROTOCOLS: dict[str, int | None] = {"tcp": Protocol.TCP, "udp": Protocol.UDP, "icmp": Protocol.ICMP, "icmpv6": Protocol.ICMPV6, "any": None}
NOTE_OUTSIDE = "назначение не из хостов снапшота: проверена только сторона источника"
ERROR_NO_HOST = "хост не найден"


def note_several(n: int) -> str:
    return f"адрес совпал с {n} хостами снапшота: сторона назначения не проверялась"


class Destination(BaseModel):
    """Ровно одно: хост снапшота или адрес."""
    host_id: str | None = None
    address: str | None = None

    @model_validator(mode="after")
    def _one(self) -> Destination:
        if (self.host_id is None) == (self.address is None):
            raise ValueError("назначение — либо host_id, либо address")
        if self.address is not None:
            try:
                self.address = str(ipaddress.ip_address(self.address.strip()))
            except ValueError:
                raise ValueError("адрес назначения не разобран") from None
        return self


class _Check(BaseModel):
    destination: Destination
    protocol: Literal["tcp", "udp", "icmp", "icmpv6", "any"] = "any"
    port: int | None = Field(default=None, ge=0, le=65535)
    icmp_type: int | None = Field(default=None, ge=0, le=255)


class CheckRequest(_Check):
    source_host_id: str


class BatchRequest(_Check):
    sources: list[str]

    @field_validator("sources")
    @classmethod
    def _limit(cls, sources: list[str]) -> list[str]:
        if len(sources) > MAX_SOURCES:
            raise ValueError(f"не больше {MAX_SOURCES} хостов за запрос")
        return sources


# --- ответ ----------------------------------------------------------------------------------------------------------


def rule_out(r: RuleView) -> dict[str, Any]:
    return {"row_id": r.row_id, "position": r.position, "name": r.name, "policy_id": r.policy_id, "profile": r.profile,
            "action": r.action, "enabled": r.enabled, "layer": r.layer}


def step_out(s: Step) -> dict[str, Any]:
    m = s.match
    return {
        "rule": rule_out(m.rule), "status": s.status, "result": m.result.value,
        "criteria": [{"name": c.name, "result": c.result.value, "text": c.text} for c in m.criteria],
        "almost": {"name": m.almost.name, "text": m.almost.text} if m.almost is not None else None,
        "assumption": m.assumption,
    }


def branch_out(b: Branch) -> dict[str, Any]:
    return {
        "assumptions": list(b.assumptions), "verdict": b.verdict.value, "decided_by": rule_out(b.decided_by) if b.decided_by else None,
        "layer": b.layer, "note": b.note, "steps": [step_out(s) for s in b.steps], "reply_steps": [step_out(s) for s in b.reply_steps],
        "app_candidates": [rule_out(r) for r in b.app_candidates], "trust_groups": [{"name": n, "allow": a} for n, a in b.trust_groups],
    }


def _host(h: KscHost) -> dict[str, Any]:
    return {"host_id": h.host_id, "name": h.name, "ip": h.ip}


def side_out(h: KscHost, outbound: bool, res: SideResult) -> dict[str, Any]:
    return {
        "host": _host(h), "direction": "out" if outbound else "in", "verdict": res.verdict.value, "depends_on": list(res.depends_on),
        "mode": res.mode, "notes": list(res.notes), "effective_sources": list(res.effective_sources),
        "branches": [branch_out(b) for b in res.branches],
    }


def overall(verdicts: list[Verdict]) -> Verdict:
    """«Разрешено» — обе стороны разрешают («правила не применяются» не блокирует); иначе запрет любой стороны, затем
    «зависит», затем «по правилам программ», иначе «не определено»."""
    passing = [Verdict.ALLOW if v is Verdict.NOT_APPLIED else v for v in verdicts]
    if all(v is Verdict.ALLOW for v in passing):
        return Verdict.ALLOW
    for v in (Verdict.DENY, Verdict.DEPENDS, Verdict.APP):
        if v in passing:
            return v
    return Verdict.UNDETERMINED


def _decided_by(res: SideResult) -> RuleView | None:
    """Решающее правило, если оно одно на все ветви."""
    rules = {b.decided_by.row_id: b.decided_by for b in res.branches if b.decided_by is not None}
    if len(rules) == 1 and all(b.decided_by is not None for b in res.branches):
        return next(iter(rules.values()))
    return None


# --- маршруты -------------------------------------------------------------------------------------------------------


def _snapshot(db: Session, snapshot_id: int, settings: Settings) -> None:
    """Снапшот с заполненными таблицами политик (старый дозаполняется из файла при первом чтении)."""
    snap = db.get(KscSnapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    ensure_policy_tables(db, snap, settings.data_dir)


def _remote_name(h: KscHost) -> str:
    return h.fqdn or h.name


def _destination(db: Session, snapshot_id: int, d: Destination) -> tuple[str | None, str, list[KscHost]]:
    """Адрес и имя назначения для пакета источника и хосты снапшота, которыми назначение может быть."""
    if d.host_id is not None:
        h = find_host(db, snapshot_id, d.host_id)
        return h.ip or None, _remote_name(h), [h]
    hosts = list(db.execute(
        select(KscHost).where(KscHost.snapshot_id == snapshot_id, KscHost.ip == d.address).order_by(KscHost.name, KscHost.host_id)
    ).scalars())
    return d.address, "", hosts


def _source_packet(req: _Check, ip: str | None, name: str) -> Packet:
    return Packet(outbound=True, protocol=PROTOCOLS[req.protocol], local_port=None, remote_port=req.port, remote_ip=ip, remote_host=name,
                  icmp_type=req.icmp_type)


@router.post("/snapshots/{snapshot_id}/firewall/check")
def check(
    snapshot_id: int,
    req: CheckRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Пакет от хоста-источника к назначению: вердикт каждой стороны с трассой и общий итог."""
    _snapshot(db, snapshot_id, settings)
    mode = load_config(db).firewall_profile_mode
    src = find_host(db, snapshot_id, req.source_host_id)
    ip, name, hosts = _destination(db, snapshot_id, req.destination)
    source = evaluate_side(load_host_firewall(db, snapshot_id, src.host_id), _source_packet(req, ip, name), profile_mode=mode)
    sides = [source]
    out: dict[str, Any] = {"source": side_out(src, True, source), "destination": None, "destination_hosts": [_host(h) for h in hosts]}
    notes: list[str] = []
    if len(hosts) == 1:
        dst = hosts[0]
        packet = Packet(outbound=False, protocol=PROTOCOLS[req.protocol], local_port=req.port, remote_port=None, remote_ip=src.ip or None,
                        remote_host=_remote_name(src), icmp_type=req.icmp_type)
        result = evaluate_side(load_host_firewall(db, snapshot_id, dst.host_id), packet, profile_mode=mode)
        sides.append(result)
        out["destination"] = side_out(dst, False, result)
    else:
        notes.append(note_several(len(hosts)) if hosts else NOTE_OUTSIDE)
    depends = [p for s in sides for p in s.depends_on]
    return {**out, "overall": overall([s.verdict for s in sides]).value, "depends_on": list(dict.fromkeys(depends)), "notes": notes}


@router.post("/snapshots/{snapshot_id}/firewall/check/batch")
def check_batch(
    snapshot_id: int,
    req: BatchRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """Та же связь у списка источников — только сторона источника, вердикт одной строкой; неизвестный хост — строка с ошибкой."""
    _snapshot(db, snapshot_id, settings)
    mode = load_config(db).firewall_profile_mode
    ip, name, _ = _destination(db, snapshot_id, req.destination)
    packet = _source_packet(req, ip, name)
    out: list[dict[str, Any]] = []
    for host_id in req.sources:
        try:
            fw = load_host_firewall(db, snapshot_id, host_id)
        except HTTPException as e:
            if e.status_code != status.HTTP_404_NOT_FOUND:
                raise
            out.append({"host_id": host_id, "name": "", "verdict": Verdict.UNDETERMINED.value, "decided_by": None, "depends_on": [],
                        "error": ERROR_NO_HOST})
            continue
        res = evaluate_side(fw, packet, profile_mode=mode)
        rule = _decided_by(res)
        out.append({"host_id": host_id, "name": fw.host_name, "verdict": res.verdict.value, "decided_by": rule_out(rule) if rule else None,
                    "depends_on": list(res.depends_on)})
    return out
