"""Сети и справочник зон: CIDR, зона, площадка, настройки сканирования; привязка активов
к самой узкой сети, содержащей их адрес.

Пересечение сетей разрешено (вложенность — потом), поэтому привязка выбирает сеть с
самым длинным префиксом. Ручная сеть актива (`network_manual`) пересчёт не трогает.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from typing import Any

from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.orm import Session

from api.modules.assets.models import Asset, AssetObservation, AssetZone, Network
from api.platform.scheduler import PlatformSchedule, delete_schedule

NetworkList = list[tuple[int, ipaddress.IPv4Network | ipaddress.IPv6Network]]

#: Шире /16 — 65 тысяч адресов на проход сканера; такую сеть описывают частями.
MAX_IPV4_PREFIX = 16
TOO_WIDE = "сеть шире /16 не принимается — разбейте на несколько"


class NetworkNotFound(LookupError):
    pass


class NetworkConflict(Exception):
    """Дубликат CIDR или имени зоны, зона занята сетями."""


def normalize_cidr(value: str) -> str:
    """'10.10.0.7/24' → '10.10.0.0/24'; ValueError с русским текстом на мусор и IPv4 шире /16."""
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        raise ValueError(f"«{value}» — не адрес сети CIDR, например 10.10.0.0/24") from None
    if net.version == 4 and net.prefixlen < MAX_IPV4_PREFIX:
        raise ValueError(TOO_WIDE)
    return str(net)


def normalize_exclude(value: str) -> str:
    """Исключение — адрес или сеть; адрес остаётся адресом, а не превращается в /32."""
    text = value.strip()
    try:
        return str(ipaddress.ip_network(text, strict=False)) if "/" in text else str(ipaddress.ip_address(text))
    except ValueError:
        raise ValueError(f"исключение «{value}» — не адрес и не сеть CIDR") from None


# ---- Привязка активов -----------------------------------------------------


def load_networks(db: Session) -> NetworkList:
    out: NetworkList = []
    for network_id, cidr in db.execute(select(Network.id, Network.cidr)):
        try:
            out.append((network_id, ipaddress.ip_network(cidr, strict=False)))
        except ValueError:
            continue
    return out


def network_for_ip(source: Session | NetworkList, ip: str) -> int | None:
    """Id самой узкой сети, содержащей `ip`; `source` — база или заранее прочитанный список
    (синхронизация привязывает тысячи активов и читает сети один раз)."""
    networks = load_networks(source) if isinstance(source, Session) else source
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    best: tuple[int, int] | None = None
    for network_id, net in networks:
        if addr.version == net.version and addr in net and (best is None or net.prefixlen > best[1]):
            best = (network_id, net.prefixlen)
    return best[0] if best else None


def reassign_assets(db: Session) -> int:
    """Сети изменились — пересчитать `network_id` у всех активов без ручной сети; число изменённых."""
    networks = load_networks(db)
    changed = 0
    for asset in db.execute(select(Asset).where(Asset.network_manual.is_(False))).scalars():
        network_id = network_for_ip(networks, asset.ip)
        if asset.network_id != network_id:
            asset.network_id = network_id
            changed += 1
    db.flush()
    return changed


# ---- Сети -----------------------------------------------------------------


def get_network(db: Session, network_id: int) -> Network:
    network = db.get(Network, network_id)
    if network is None:
        raise NetworkNotFound("сеть не найдена")
    return network


def _check_zone(db: Session, zone: str | None) -> None:
    if zone is not None and db.get(AssetZone, zone) is None:
        raise ValueError(f"зоны «{zone}» нет в справочнике")


def _check_unique(db: Session, cidr: str, network_id: int | None = None) -> None:
    stmt = select(Network.id).where(Network.cidr == cidr)
    if network_id is not None:
        stmt = stmt.where(Network.id != network_id)
    if db.execute(stmt).first() is not None:
        raise NetworkConflict(f"сеть {cidr} уже описана")


def create_network(db: Session, data: dict[str, Any]) -> Network:
    """`data` — проверенные поля `NetworkIn`; CIDR уже нормализован схемой."""
    _check_unique(db, data["cidr"])
    _check_zone(db, data.get("zone"))
    network = Network(**data)
    db.add(network)
    db.flush()
    reassign_assets(db)
    return network


def update_network(db: Session, network: Network, data: dict[str, Any]) -> Network:
    """Меняются только переданные поля; смена CIDR пересчитывает сети активов."""
    if "cidr" in data:
        if data["cidr"] is None:
            raise ValueError("CIDR сети обязателен")
        _check_unique(db, data["cidr"], network.id)
    if "zone" in data:
        _check_zone(db, data["zone"])
    cidr_changed = "cidr" in data and data["cidr"] != network.cidr
    for name, value in data.items():
        setattr(network, name, value)
    db.flush()
    if cidr_changed:
        reassign_assets(db)
    return network


def delete_network(db: Session, network: Network) -> None:
    """Расписание сканов сети уходит вместе с ней. Активы, привязанные к сети руками, теряют
    выбор и возвращаются к расчёту — как и остальные: самая узкая из оставшихся сетей или никакой."""
    schedule_ids = set(db.execute(
        select(PlatformSchedule.id).where(
            PlatformSchedule.module == "assets", PlatformSchedule.kind == "scan", PlatformSchedule.target_id == network.id,
        )
    ).scalars())
    if network.schedule_id is not None:
        schedule_ids.add(network.schedule_id)
    for asset in db.execute(select(Asset).where(Asset.network_id == network.id)).scalars():
        asset.network_id = None
        asset.network_manual = False
    db.delete(network)
    db.flush()
    for schedule_id in schedule_ids:
        delete_schedule(db, schedule_id)
    reassign_assets(db)


def _unknown_host_filter() -> Any:
    """Актив, который видел только сканер (и, возможно, обратная запись DNS) — код `unknown_host`."""
    live = AssetObservation.gone_at.is_(None)
    mine = AssetObservation.asset_id == Asset.id
    scanned = exists().where(mine, live, AssetObservation.source == "scan")
    described = exists().where(mine, live, or_(
        AssetObservation.source.in_(("vm", "ksc", "ad")),
        and_(AssetObservation.source == "dns", func.coalesce(AssetObservation.extra["record_type"].as_string(), "") != "PTR"),
    ))
    return and_(scanned, ~described)


def network_stats(db: Session, network: Network) -> dict[str, Any]:
    """Активов в сети, живых при последнем скане, найденных только сканером."""
    return all_network_stats(db, [network])[network.id]


def all_network_stats(db: Session, networks: Iterable[Network]) -> dict[int, dict[str, Any]]:
    """То же для списка сетей — двумя запросами, а не двумя на сеть."""
    networks = list(networks)
    ids = [n.id for n in networks]
    in_registry = and_(Asset.network_id.in_(ids), Asset.merged_into.is_(None))
    counts = dict(db.execute(select(Asset.network_id, func.count()).where(in_registry).group_by(Asset.network_id)).tuples().all())
    unknown = dict(db.execute(
        select(Asset.network_id, func.count()).where(in_registry, _unknown_host_filter()).group_by(Asset.network_id)
    ).tuples().all())
    return {
        n.id: {"assets": counts.get(n.id, 0), "alive_last_scan": n.last_scan_alive, "unknown_hosts": unknown.get(n.id, 0)}
        for n in networks
    }


# ---- Справочник зон -------------------------------------------------------


def list_zones(db: Session) -> list[dict[str, Any]]:
    used = dict(db.execute(select(Network.zone, func.count()).where(Network.zone.is_not(None)).group_by(Network.zone)).tuples().all())
    return [
        {"name": z.name, "title": z.title, "description": z.description, "networks": used.get(z.name, 0)}
        for z in db.execute(select(AssetZone).order_by(AssetZone.name)).scalars()
    ]


def create_zone(db: Session, name: str, title: str, description: str) -> AssetZone:
    if db.get(AssetZone, name) is not None:
        raise NetworkConflict(f"зона «{name}» уже есть")
    zone = AssetZone(name=name, title=title, description=description)
    db.add(zone)
    db.flush()
    return zone


def delete_zone(db: Session, name: str) -> None:
    """Зону, на которую ссылается сеть, удалить нельзя: сначала сетям выбирают другую."""
    zone = db.get(AssetZone, name)
    if zone is None:
        raise NetworkNotFound("зона не найдена")
    cidrs = list(db.execute(select(Network.cidr).where(Network.zone == name).order_by(Network.cidr)).scalars())
    if cidrs:
        raise NetworkConflict(f"зона «{name}» задана у сетей: {', '.join(cidrs)} — сначала смените им зону")
    db.delete(zone)
    db.flush()
