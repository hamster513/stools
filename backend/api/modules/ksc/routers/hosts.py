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
from api.modules.ksc.core.checks.hosts import COMPONENT_OFF_STATES
from api.modules.ksc.models import KscFinding, KscHost, KscPolicy, KscPolicyScope, KscSnapshot
from api.modules.ksc.services.settings import load_config
from api.platform.findings import service as finding_svc
from api.platform.findings.core import STATUS_TITLES

router = APIRouter(tags=["ksc"])

MAX_LIMIT = 1000
AGENT = ("none", "silent", "alive")
PROTECTION = ("none", "off", "on")
BASES = ("fresh", "old", "unknown")
COMPONENT_STATES = ("on", "off", "other", "none")
#: Худшее состояние побеждает, если хост перечисляет компонент дважды (две версии продукта): выключен > прочее > работает.
_COMPONENT_RANK = {"on": 0, "other": 1, "off": 2}
NO_TAGS = "-"


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


def _component_state(status: Any) -> str:
    if status == 4:
        return "on"
    return "off" if status in COMPONENT_OFF_STATES else "other"


def _components(h: KscHost) -> dict[str, str]:
    """Состояние каждого компонента защиты хоста: on | off | other."""
    out: dict[str, str] = {}
    for name, code in json.loads(h.components_json or "[]"):
        state = _component_state(code)
        if name not in out or _COMPONENT_RANK[state] > _COMPONENT_RANK[out[name]]:
            out[name] = state
    return out


def _tags(h: KscHost, collected: bool) -> list[str] | None:
    """Теги хоста; None — сборщик секцию тегов не присылал (не собрано, а не «без тегов»)."""
    if not collected:
        return None
    return list(json.loads(h.extra_json or "{}").get("tags", []))


def _tags_collected(rows: list[KscHost]) -> bool:
    """Секция тегов в выгрузке была, если ключ `tags` есть хотя бы у одного хоста снапшота."""
    return any("tags" in json.loads(h.extra_json or "{}") for h in rows)


def _item(h: KscHost, agent: str, bases: str, findings: int, tags: list[str] | None) -> dict[str, Any]:
    return {
        "id": h.id, "host_id": h.host_id, "name": h.name, "fqdn": h.fqdn, "domain": h.domain, "group": h.group_path, "os": h.os, "ip": h.ip,
        "agent": agent, "agent_version": h.agent_version, "last_seen_at": h.last_seen_at.isoformat() if h.last_seen_at else None,
        "product": h.product, "product_version": h.product_version, "protection": h.protection, "rtp_state": h.rtp_state,
        "bases_at": h.bases_at.isoformat() if h.bases_at else None, "bases": bases,
        "last_fullscan_at": h.last_fullscan_at.isoformat() if h.last_fullscan_at else None,
        "status": h.status, "threats": h.threats, "unassigned": h.unassigned, "in_ad": h.in_ad,
        "components": json.loads(h.components_json or "[]"), "extra": json.loads(h.extra_json or "{}"), "tags": tags, "findings": findings,
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


def _host_policies(db: Session, snapshot_id: int, h: KscHost) -> list[dict[str, Any]]:
    """Политики, действующие на группу хоста; `own` — политика создана в этой группе, а не унаследована."""
    if h.group_id is None:
        return []
    rows = db.execute(
        select(KscPolicy, KscPolicyScope.own)
        .join(KscPolicyScope, (KscPolicyScope.snapshot_id == KscPolicy.snapshot_id) & (KscPolicyScope.policy_id == KscPolicy.policy_id))
        .where(KscPolicy.snapshot_id == snapshot_id, KscPolicyScope.group_id == h.group_id)
    ).all()
    out = [{"id": p.policy_id, "name": p.name, "product": p.product, "active": p.active, "own": own} for p, own in rows]
    return sorted(out, key=lambda p: (p["name"].lower(), p["id"]))


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
    component: str | None = None,
    component_state: str | None = None,
    tag: str | None = None,
    policy: int | None = None,
    q: str | None = None,
    limit: int = Query(default=200, ge=1, le=MAX_LIMIT),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    _user: AppUser = Depends(get_current_user),
) -> dict[str, Any]:
    snap = _snapshot(db, snapshot_id)
    for value, allowed in ((agent, AGENT), (protection, PROTECTION), (bases, BASES), (in_ad, ("both", "ksc_only")), (status_, ("ok", "warning", "critical")), (component_state, COMPONENT_STATES)):
        if value is not None and value not in allowed:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=f"неизвестное значение фильтра «{value}»")
    if component_state and not component:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="состояние компонента задаётся вместе с названием компонента")
    cfg = load_config(db)
    per_host = _findings_per_host(db, snap)
    rows = list(db.execute(select(KscHost).where(KscHost.snapshot_id == snapshot_id)).scalars())
    tags_collected = _tags_collected(rows)
    tags = {h.id: _tags(h, tags_collected) for h in rows}
    comps = {h.id: _components(h) for h in rows}
    policy_groups = {g for (g,) in db.execute(select(KscPolicyScope.group_id).where(KscPolicyScope.snapshot_id == snapshot_id, KscPolicyScope.policy_id == policy))} if policy is not None else set()
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
        if component:
            state = comps[h.id].get(component, "none")
            if state != component_state if component_state else state == "none":  # без состояния — хосты, у которых компонент есть
                return False
        if tag:
            own = tags[h.id]
            if own is None or (bool(own) if tag == NO_TAGS else tag not in own):
                return False
        if policy is not None and (h.group_id is None or h.group_id not in policy_groups):
            return False
        if q:
            needle = q.lower()
            if (needle not in h.name.lower() and needle not in h.fqdn and needle not in h.ip and needle not in h.os.lower()
                    and not any(needle in t.lower() for t in tags[h.id] or [])):
                return False
        return True

    filtered = sorted((h for h in rows if keep(h)), key=lambda h: (h.group_path.lower(), h.name.lower()))
    facets: dict[str, dict[str, Any]] = {"group": {}, "product": {}, "agent": dict.fromkeys(AGENT, 0), "protection": dict.fromkeys(PROTECTION, 0), "bases": dict.fromkeys(BASES, 0), "in_ad": {}, "status": {"ok": 0, "warning": 0, "critical": 0}, "component": {}}
    if tags_collected:
        facets["tag"] = {}
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
        for name, state in comps[h.id].items():
            facets["component"].setdefault(name, {"on": 0, "off": 0, "other": 0})[state] += 1
        for t in tags[h.id] or []:
            facets["tag"][t] = facets["tag"].get(t, 0) + 1
    page = filtered[offset : offset + limit]
    return {"total": len(filtered), "items": [_item(h, *derived[h.id], per_host.get(_host_key(h), 0), tags[h.id]) for h in page],
            "facets": facets if offset == 0 else None, "tags_collected": tags_collected}


@router.get("/snapshots/{snapshot_id}/hosts/{host_id}")
def host_detail(snapshot_id: int, host_id: str, db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    snap = _snapshot(db, snapshot_id)
    h = db.execute(select(KscHost).where(KscHost.snapshot_id == snapshot_id, KscHost.host_id == host_id)).scalars().first()
    if h is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="хост не найден")
    cfg = load_config(db)
    findings = list(db.execute(select(KscFinding).where(KscFinding.snapshot_id == snapshot_id, KscFinding.host_key == _host_key(h))).scalars())
    states = finding_svc.state_map(db, "ksc", snap.server_id, [f.key for f in findings])
    counted = finding_svc.counted_statuses(db)
    items = []
    for f in findings:
        status_ = finding_svc.effective_status(states.get(f.key))
        items.append({"key": f.key, "check": f.check, "check_title": CHECK_BY_CODE[f.check].title if f.check in CHECK_BY_CODE else f.check,
                      "severity": f.severity, "status": status_, "status_title": STATUS_TITLES[status_], "details": json.loads(f.details_json or "{}")})
    # `findings` — все находки хоста со статусами; `findings_counted` — по тому же правилу, что счётчик в списке хостов.
    n_counted = sum(1 for i in items if i["status"] in counted)
    tags_collected = _tags_collected(list(db.execute(select(KscHost).where(KscHost.snapshot_id == snapshot_id)).scalars()))
    return {**_item(h, _agent(h, snap.collected_at, cfg.agent_silent_days), _bases(h, snap.collected_at, cfg.bases_old_days), n_counted, _tags(h, tags_collected)),
            "findings": items, "findings_counted": n_counted, "policies": _host_policies(db, snapshot_id, h)}
