"""Контроллеры домена из сводки, связанные с другими модулями: актив Assets и его адреса,
попадание адресов в подсети AD, уязвимости VM, хост антивируса (KSC).

Связки читаются при показе, анализ AD от Assets, VM и KSC не зависит. Чтение каждого модуля —
в своей точке сохранения: сбой (нет таблиц, ошибка запроса) даёт пустое поле, а не ошибку
запроса и не сорванную транзакцию для остальных полей.
"""
from __future__ import annotations

import ipaddress
import json
import logging
from collections.abc import Callable, Iterable
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from api.modules.ad.services.snapshots import latest_snapshot

log = logging.getLogger("stools.ad")

#: Критичная уязвимость VM — как уровень critical в модуле VM (`vm/services/query.level_expr`).
VM_CRITICAL_RISK = 70


def _safe[T](db: Session, fn: Callable[..., T], *args: Any) -> T | None:
    try:
        with db.begin_nested():
            return fn(*args)
    except Exception as exc:  # noqa: BLE001 — чужой модуль не должен ронять сводку AD
        log.debug("связка контроллеров: %s не прочитано: %s", fn.__name__, exc)
        return None


def _names(dc: dict[str, Any]) -> tuple[set[str], str]:
    """(короткие имена, FQDN) контроллера в нижнем регистре."""
    fqdn = str(dc.get("dns") or "").strip().lower().rstrip(".")
    shorts = {s for s in (str(dc.get("name") or "").strip().lower(), fqdn.split(".", 1)[0]) if s}
    return shorts, fqdn


def _asset_of(db: Session, shorts: set[str], fqdn: str) -> tuple[int, list[str]] | None:
    """Актив контроллера (сначала по FQDN, потом по короткому имени) и его адреса: адрес карточки
    и адреса живых наблюдений без повторов."""
    from api.modules.assets.models import Asset, AssetObservation

    conds: list[ColumnElement[bool]] = [Asset.name_key.in_(sorted(shorts))]
    if fqdn:
        conds.append(func.lower(Asset.fqdn) == fqdn)
    found = list(db.execute(select(Asset).where(Asset.merged_into.is_(None), or_(*conds)).order_by(Asset.id)).scalars())
    if not found:
        return None
    asset = next((a for a in found if fqdn and a.fqdn.lower() == fqdn), found[0])
    ips: list[str] = [asset.ip]
    for ip, more in db.execute(
        select(AssetObservation.ip, AssetObservation.ips)
        .where(AssetObservation.asset_id == asset.id, AssetObservation.gone_at.is_(None)).order_by(AssetObservation.id)
    ).tuples():
        ips += [ip, *(more or [])]
    return asset.id, [ip for ip in dict.fromkeys(ips) if ip]


def _in_subnets(ips: Iterable[str], subnets: list[dict[str, Any]]) -> bool | None:
    """Входит ли хоть один адрес в подсеть AD; None — адресов или подсетей нет."""
    nets = []
    for s in subnets:
        try:
            nets.append(ipaddress.ip_network(str(s.get("name") or ""), strict=False))
        except ValueError:
            continue
    addrs = []
    for ip in ips:
        try:
            addrs.append(ipaddress.ip_address(ip))
        except ValueError:
            continue
    if not nets or not addrs:
        return None
    return any(a in n for a in addrs for n in nets)


def _vm_counts(db: Session, names: set[str]) -> dict[str, int] | None:
    """Уязвимости хостов VM с этим именем (короткое или FQDN): критичные и с эксплойтом; None — хоста нет."""
    from api.modules.vm.models import VmCve, VmHost, VmHostCve

    host_ids = list(db.scalars(select(VmHost.id).where(func.lower(VmHost.hostname).in_(sorted(names)))))
    if not host_ids:
        return None
    pairs = select(VmHostCve.cve_id).where(VmHostCve.host_id.in_(host_ids))
    critical = db.scalar(select(func.count(func.distinct(VmHostCve.cve_id))).where(VmHostCve.host_id.in_(host_ids), VmHostCve.risk >= VM_CRITICAL_RISK))
    exploitable = db.scalar(select(func.count()).select_from(VmCve).where(VmCve.cve_id.in_(pairs), VmCve.exploits_count > 0))
    return {"critical": int(critical or 0), "exploitable": int(exploitable or 0)}


def _ksc_names(db: Session) -> set[str] | None:
    """Имена и FQDN хостов последних снапшотов серверов KSC в нижнем регистре; None — данных KSC нет."""
    from api.modules.ksc.models import KscHost, KscServer
    from api.modules.ksc.services.snapshots import latest_snapshot as latest_ksc

    snaps = [s.id for s in (latest_ksc(db, sid) for sid in db.scalars(select(KscServer.id))) if s is not None]
    if not snaps:
        return None
    names: set[str] = set()
    for name, fqdn in db.execute(select(KscHost.name, KscHost.fqdn).where(KscHost.snapshot_id.in_(snaps))).tuples():
        names |= {n.strip().lower().rstrip(".") for n in (name, fqdn) if n}
    return names


def dc_links(db: Session, domain_id: int) -> list[dict[str, Any]]:
    """Контроллеры последнего снапшота домена со связками; нет снапшота или сводки — пусто."""
    snap = latest_snapshot(db, domain_id)
    if snap is None or not snap.summary_json:
        return []
    summary: dict[str, Any] = json.loads(snap.summary_json)
    dcs: list[dict[str, Any]] = summary.get("dcs") or []
    if not dcs:
        return []
    subnets: list[dict[str, Any]] = summary.get("subnets") or []
    ksc = _safe(db, _ksc_names, db)
    out = []
    for dc in dcs:
        shorts, fqdn = _names(dc)
        names = shorts | ({fqdn} if fqdn else set())
        asset = _safe(db, _asset_of, db, shorts, fqdn) if names else None
        ips = asset[1] if asset else []
        out.append({
            "name": dc.get("name") or "",
            "asset_id": asset[0] if asset else None,
            "ips": ips,
            "in_ad_subnet": _in_subnets(ips, subnets),
            "vm": _safe(db, _vm_counts, db, names) if names else None,
            "ksc_agent": None if ksc is None else bool(names & ksc),
        })
    return out
