"""Инвентарь хостов снапшота с фасетами; карточка хоста с его находками."""
from __future__ import annotations

import datetime as dt
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.ksc.core.checks import CHECK_BY_CODE
from api.modules.ksc.models import KscFinding, KscHost, KscSnapshot
from api.modules.ksc.services.settings import load_config
from api.platform.findings import service as finding_svc
from api.platform.findings.core import STATUS_TITLES

router = APIRouter(tags=["ksc"])

MAX_LIMIT = 1000
AGENT = ("none", "silent", "alive")
PROTECTION = ("none", "off", "on")
BASES = ("fresh", "old", "unknown")


def _agent(h: KscHost, now: dt.datetime, silent_days: int) -> str:
    if not h.agent_installed:
        return "none"
    if h.last_seen_at is None or (now - h.last_seen_at).days > silent_days:
        return "silent"
    return "alive"


def _bases(h: KscHost, now: dt.datetime, old_days: int) -> str:
    if h.bases_at is None:
        return "unknown"
    return "old" if (now - h.bases_at).days > old_days else "fresh"


def _item(h: KscHost, agent: str, bases: str, findings: int) -> dict[str, Any]:
    return {
        "id": h.id, "host_id": h.host_id, "name": h.name, "fqdn": h.fqdn, "domain": h.domain, "group": h.group_path, "os": h.os, "ip": h.ip,
        "agent": agent, "agent_version": h.agent_version, "last_seen_at": h.last_seen_at.isoformat() if h.last_seen_at else None,
        "product": h.product, "product_version": h.product_version, "protection": h.protection, "rtp_state": h.rtp_state,
        "bases_at": h.bases_at.isoformat() if h.bases_at else None, "bases": bases,
        "last_fullscan_at": h.last_fullscan_at.isoformat() if h.last_fullscan_at else None,
        "status": h.status, "threats": h.threats, "unassigned": h.unassigned, "in_ad": h.in_ad,
        "components": json.loads(h.components_json or "[]"), "extra": json.loads(h.extra_json or "{}"), "findings": findings,
    }


def _snapshot(db: Session, snapshot_id: int) -> KscSnapshot:
    snap = db.get(KscSnapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    return snap


def _host_key(h: KscHost) -> str:
    """Тот же ключ, что у находки: имя (KLHST_WKS_DN) не уникально."""
    return h.fqdn or h.name.lower()


def _findings_per_host(db: Session, snap: KscSnapshot) -> dict[str, int]:
    """Сколько у хоста находок, которые учитываются (настройка платформы `counted`)."""
    counted = finding_svc.counted_statuses(db)
    states = finding_svc.state_map(db, "ksc", snap.server_id)
    rows = db.execute(select(KscFinding.host_key, KscFinding.key).where(KscFinding.snapshot_id == snap.id, KscFinding.host_key != "")).all()
    per_host: dict[str, int] = {}
    for host, key in rows:
        if finding_svc.is_counted(states.get(key), counted):
            per_host[host] = per_host.get(host, 0) + 1
    return per_host


@router.get("/snapshots/{snapshot_id}/hosts")
def list_hosts(
    snapshot_id: int,
    group: str | None = None,
    product: str | None = None,
    agent: str | None = None,
    protection: str | None = None,
    bases: str | None = None,
    in_ad: str | None = None,
    status_: str | None = Query(default=None, alias="status"),
    q: str | None = None,
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    snap = _snapshot(db, snapshot_id)
    for value, allowed in ((agent, AGENT), (protection, PROTECTION), (bases, BASES), (in_ad, ("both", "ksc_only")), (status_, ("ok", "warning", "critical"))):
        if value is not None and value not in allowed:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"неизвестное значение фильтра «{value}»")
    cfg = load_config(db)
    per_host = _findings_per_host(db, snap)
    rows = list(db.execute(select(KscHost).where(KscHost.snapshot_id == snapshot_id)).scalars())
    # Хостов у сервера тысячи: фасеты и фильтры считаются в памяти, как находки в AD.
    derived = {h.id: (_agent(h, snap.collected_at, cfg.agent_silent_days), _bases(h, snap.collected_at, cfg.bases_old_days)) for h in rows}

    def keep(h: KscHost) -> bool:
        a, b = derived[h.id]
        if group and h.group_path != group:
            return False
        if product and h.product != product:
            return False
        if agent and a != agent:
            return False
        if protection and h.protection != protection:
            return False
        if bases and b != bases:
            return False
        if in_ad and h.in_ad != in_ad:
            return False
        if status_ and h.status != status_:
            return False
        if q:
            needle = q.lower()
            if needle not in h.name.lower() and needle not in h.fqdn and needle not in h.ip and needle not in h.os.lower():
                return False
        return True

    filtered = sorted((h for h in rows if keep(h)), key=lambda h: (h.group_path.lower(), h.name.lower()))
    facets: dict[str, dict[str, int]] = {"group": {}, "product": {}, "agent": dict.fromkeys(AGENT, 0), "protection": dict.fromkeys(PROTECTION, 0), "bases": dict.fromkeys(BASES, 0), "in_ad": {}, "status": {"ok": 0, "warning": 0, "critical": 0}}
    for h in filtered:
        a, b = derived[h.id]
        facets["group"][h.group_path] = facets["group"].get(h.group_path, 0) + 1
        if h.product:
            facets["product"][h.product] = facets["product"].get(h.product, 0) + 1
        facets["agent"][a] += 1
        facets["protection"][h.protection] += 1
        facets["bases"][b] += 1
        if h.in_ad:
            facets["in_ad"][h.in_ad] = facets["in_ad"].get(h.in_ad, 0) + 1
        facets["status"][h.status] = facets["status"].get(h.status, 0) + 1
    page = filtered[offset : offset + limit]
    return {"total": len(filtered), "items": [_item(h, *derived[h.id], per_host.get(_host_key(h), 0)) for h in page], "facets": facets if offset == 0 else None}


@router.get("/snapshots/{snapshot_id}/hosts/{host_id}")
def host_detail(snapshot_id: int, host_id: str, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    snap = _snapshot(db, snapshot_id)
    h = db.execute(select(KscHost).where(KscHost.snapshot_id == snapshot_id, KscHost.host_id == host_id)).scalars().first()
    if h is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="хост не найден")
    cfg = load_config(db)
    findings = list(db.execute(select(KscFinding).where(KscFinding.snapshot_id == snapshot_id, KscFinding.host_key == _host_key(h))).scalars())
    states = finding_svc.state_map(db, "ksc", snap.server_id, [f.key for f in findings])
    items = []
    for f in findings:
        status_ = finding_svc.effective_status(states.get(f.key))
        items.append({"key": f.key, "check": f.check, "check_title": CHECK_BY_CODE[f.check].title if f.check in CHECK_BY_CODE else f.check,
                      "severity": f.severity, "status": status_, "status_title": STATUS_TITLES[status_], "details": json.loads(f.details_json or "{}")})
    return {**_item(h, _agent(h, snap.collected_at, cfg.agent_silent_days), _bases(h, snap.collected_at, cfg.bases_old_days), len(items)), "findings": items}
