"""Сети и справочник зон: CIDR, зона, площадка, настройки сканирования; привязка активов
к самой узкой сети, содержащей их адрес.

Пересечение сетей разрешено (вложенность — потом), поэтому привязка выбирает сеть с
самым длинным префиксом. Ручная сеть актива (`network_manual`) пересчёт не трогает.
"""
from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable
from dataclasses import replace
from typing import Any

from sqlalchemy import and_, exists, func, or_, select
from sqlalchemy.orm import Session

from api.modules.assets.core import scanner
from api.modules.assets.core.zone_rules import (
    SOURCE_MANUAL,
    Rule,
    broken_regex,
    normalize_value,
    pick_zone,
    validate_rule,
)
from api.modules.assets.models import (
    EXTERNAL_ZONE,
    Asset,
    AssetObservation,
    AssetZone,
    Network,
    NetworkZoneRule,
)
from api.platform.scheduler import PlatformSchedule, delete_schedule

log = logging.getLogger("stools.assets")

NetworkList = list[tuple[int, ipaddress.IPv4Network | ipaddress.IPv6Network]]

#: Шире /16 — 65 тысяч адресов на проход сканера; такую сеть описывают частями.
MAX_IPV4_PREFIX = 16
TOO_WIDE = "сеть шире /16 не принимается — разбейте на несколько"
#: Параллельность × порты — столько соединений проход открыл бы разом; больше не принимается.
MAX_PARALLEL_SOCKETS = 2048
SCAN_FIELDS = ("cidr", "scan_enabled", "ports", "concurrency")


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


def check_scan_settings(cidr: str, scan_enabled: bool, ports: list[int], concurrency: int) -> None:
    """Итоговые настройки сети (после правки): ValueError с русским текстом, если скан был бы
    слишком тяжёлым — параллельность × порты больше 2048 или IPv6-сеть больше 2^16 адресов."""
    if concurrency * len(ports) > MAX_PARALLEL_SOCKETS:
        raise ValueError(
            f"параллельность × число портов = {concurrency * len(ports)}, больше {MAX_PARALLEL_SOCKETS} — "
            "уменьшите параллельность или число портов"
        )
    net = ipaddress.ip_network(cidr, strict=False)
    if scan_enabled and net.version == 6 and net.num_addresses > scanner.MAX_ADDRESSES:
        raise ValueError(f"IPv6-сеть больше {scanner.MAX_ADDRESSES} адресов не сканируется — опишите её частями (/112 и уже)")


def estimated_seconds(network: Network) -> int | None:
    """Сколько секунд займёт скан, если никто не ответит: каждый адрес ждёт оба таймаута,
    `concurrency` адресов разом, но не быстрее темпа (echo и SYN на каждый порт). None —
    сеть сканеру не по силам (широкая IPv6)."""
    try:
        count = scanner.count_addresses(scan_target(network))
    except ValueError:
        return None
    by_timeouts = count * (network.icmp_timeout_ms + network.tcp_timeout_ms) / 1000 / max(1, network.concurrency)
    by_rate = count * (1 + len(network.ports or [])) / max(1, network.rate_per_s)
    return round(max(by_timeouts, by_rate))


def scan_target(network: Network) -> scanner.ScanTarget:
    return scanner.ScanTarget(
        cidr=network.cidr, exclude=list(network.exclude or []), ports=list(network.ports or []),
        concurrency=network.concurrency, icmp_timeout=network.icmp_timeout_ms / 1000,
        tcp_timeout=network.tcp_timeout_ms / 1000, rate_per_s=network.rate_per_s,
    )


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
    """`data` — проверенные поля `NetworkIn`; CIDR уже нормализован схемой. Группа указана — выбор
    человека (`manual`), иначе (или `zone_mode="rules"`) группу назначают правила."""
    data = dict(data)
    zone_mode = data.pop("zone_mode", None)
    _check_unique(db, data["cidr"])
    _check_zone(db, data.get("zone"))
    check_scan_settings(data["cidr"], data["scan_enabled"], data["ports"], data["concurrency"])
    manual = zone_mode == "manual" or (zone_mode is None and data.get("zone") is not None)
    if zone_mode == "rules":
        data["zone"] = None
    network = Network(**data, zone_source=SOURCE_MANUAL if manual else "")
    db.add(network)
    db.flush()
    if not manual:
        apply_zone_rules(db, [network.id])
    reassign_assets(db)
    return network


def update_network(db: Session, network: Network, data: dict[str, Any]) -> Network:
    """Меняются только переданные поля; смена CIDR пересчитывает сети активов.

    Группа: `zone_mode="rules"` — сеть возвращается под правила (`zone` из тела не берётся);
    `zone_mode="manual"` — закрепить группу (из тела или текущую); `zone`, отличная от текущей, —
    выбор человека. Та же группа, присланная повторно (форма шлёт все поля), выбором не считается."""
    data = dict(data)
    zone_mode = data.pop("zone_mode", None)
    if "cidr" in data:
        if data["cidr"] is None:
            raise ValueError("CIDR сети обязателен")
        _check_unique(db, data["cidr"], network.id)
    if zone_mode == "rules":
        data.pop("zone", None)
    elif "zone" in data:
        _check_zone(db, data["zone"])
        if data["zone"] == network.zone and network.zone_source != SOURCE_MANUAL and zone_mode != "manual":
            del data["zone"]
    check_scan_settings(*(data[f] if f in data else getattr(network, f) for f in SCAN_FIELDS))
    cidr_changed = "cidr" in data and data["cidr"] != network.cidr
    if zone_mode == "rules":
        network.zone_source = ""
    elif zone_mode == "manual" or "zone" in data:
        network.zone_source, network.zone_rule_id = SOURCE_MANUAL, None
    for name, value in data.items():
        setattr(network, name, value)
    db.flush()
    if network.zone_source != SOURCE_MANUAL:
        apply_zone_rules(db, [network.id])
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


ZONE_ATTRS = ("title", "description", "placement", "internet_facing", "confidential")


def zone_view(zone: AssetZone, networks: int) -> dict[str, Any]:
    return {"name": zone.name, **{a: getattr(zone, a) for a in ZONE_ATTRS}, "networks": networks}


def list_zones(db: Session) -> list[dict[str, Any]]:
    used = dict(db.execute(select(Network.zone, func.count()).where(Network.zone.is_not(None)).group_by(Network.zone)).tuples().all())
    return [zone_view(z, used.get(z.name, 0)) for z in db.execute(select(AssetZone).order_by(AssetZone.name)).scalars()]


def create_zone(
    db: Session, name: str, title: str, description: str, *, placement: str = "", internet_facing: bool = False, confidential: bool = False,
) -> AssetZone:
    if db.get(AssetZone, name) is not None:
        raise NetworkConflict(f"зона «{name}» уже есть")
    zone = AssetZone(
        name=name, title=title, description=description, placement=placement, internet_facing=internet_facing, confidential=confidential,
    )
    db.add(zone)
    db.flush()
    return zone


def update_zone(db: Session, name: str, data: dict[str, Any]) -> dict[str, Any]:
    """Заголовок, описание и признаки группы; меняются только переданные поля."""
    zone = db.get(AssetZone, name)
    if zone is None:
        raise NetworkNotFound("зона не найдена")
    for attr, value in data.items():
        setattr(zone, attr, value)
    db.flush()
    used = db.execute(select(func.count()).select_from(Network).where(Network.zone == name)).scalar_one()
    return zone_view(zone, used)


def delete_zone(db: Session, name: str) -> None:
    """Зону, на которую ссылается сеть, удалить нельзя: сначала сетям выбирают другую."""
    zone = db.get(AssetZone, name)
    if zone is None:
        raise NetworkNotFound("зона не найдена")
    cidrs = list(db.execute(select(Network.cidr).where(Network.zone == name).order_by(Network.cidr)).scalars())
    if cidrs:
        raise NetworkConflict(f"зона «{name}» задана у сетей: {', '.join(cidrs)} — сначала смените им зону")
    positions = list(db.execute(select(NetworkZoneRule.position).where(NetworkZoneRule.zone == name).order_by(NetworkZoneRule.position)).scalars())
    if positions:
        raise NetworkConflict(f"зона «{name}» задана в правилах групп: {', '.join(f'№{p}' for p in positions)} — сначала смените их")
    db.delete(zone)
    db.flush()


# ---- Правила групп сетей --------------------------------------------------


class RuleNotFound(NetworkNotFound):
    """Правила нет — ручки отвечают 404, как на пропавшую сеть."""


#: То же, что `services.racktables.ORIGIN` (тот модуль импортирует этот).
RT_ORIGIN = "racktables"


def _rules(db: Session) -> list[Rule]:
    """Правила по порядку без тех, чей regex не компилируется (записан в обход проверки): такое правило
    не срабатывает, предупреждение — одно на пересчёт."""
    rules = [
        Rule(id=r.id, position=r.position, enabled=r.enabled, zone=r.zone, match=r.match, value=r.value)
        for r in db.execute(select(NetworkZoneRule).order_by(NetworkZoneRule.position, NetworkZoneRule.id)).scalars()
    ]
    broken = [r for r in rules if broken_regex(r)]
    if broken:
        log.warning("правила групп сетей с неверным regex пропущены: %s", ", ".join(f"№{r.position} (id {r.id})" for r in broken))
    return [r for r in rules if r not in broken]


def _is_public(cidr: str) -> bool:
    """Публичный адрес — как `RtNetwork.external`."""
    try:
        return ipaddress.ip_network(cidr, strict=False).is_global
    except ValueError:
        return False


def _decide(rules: list[Rule], network: Network, external: bool) -> tuple[str | None, str, int | None]:
    """Запасной External — только у сетей RackTables (спека §4); описанная вручную без правила — без группы."""
    return pick_zone(
        rules, title=network.title or "", tags=[*(network.tags or []), *(network.implicit_tags or [])], cidr=network.cidr,
        public=external and network.origin == RT_ORIGIN and _is_public(network.cidr),
    )


def apply_zone_rules(db: Session, network_ids: Iterable[int] | None = None, *, origin: str | None = None) -> int:
    """Группы не ручных сетей (всех, указанных или с данным `origin`) по правилам; пишет только изменения,
    возвращает их число. External — запасная группа публичных сетей RackTables, пока зона есть в справочнике."""
    stmt = select(Network).where(Network.zone_source != SOURCE_MANUAL)
    if origin is not None:
        stmt = stmt.where(Network.origin == origin)
    if network_ids is not None:
        ids = list(network_ids)
        if not ids:
            return 0
        stmt = stmt.where(Network.id.in_(ids))
    rules = _rules(db)
    external = db.get(AssetZone, EXTERNAL_ZONE) is not None
    changed = 0
    for network in db.execute(stmt).scalars():
        decided = _decide(rules, network, external)
        if (network.zone, network.zone_source, network.zone_rule_id) != decided:
            network.zone, network.zone_source, network.zone_rule_id = decided
            changed += 1
    db.flush()
    return changed


def get_rule(db: Session, rule_id: int) -> NetworkZoneRule:
    rule = db.get(NetworkZoneRule, rule_id)
    if rule is None:
        raise RuleNotFound("правило не найдено")
    return rule


def list_rules(db: Session) -> list[dict[str, Any]]:
    """Правила по порядку и сколько сетей сейчас в группе по каждому."""
    used = dict(db.execute(
        select(Network.zone_rule_id, func.count()).where(Network.zone_rule_id.is_not(None)).group_by(Network.zone_rule_id)
    ).tuples().all())
    return [
        rule_view(r, used.get(r.id, 0))
        for r in db.execute(select(NetworkZoneRule).order_by(NetworkZoneRule.position, NetworkZoneRule.id)).scalars()
    ]


def rule_view(rule: NetworkZoneRule, networks: int) -> dict[str, Any]:
    return {
        "id": rule.id, "position": rule.position, "enabled": rule.enabled, "zone": rule.zone, "match": rule.match, "value": rule.value,
        "note": rule.note, "networks": networks, "created_at": rule.created_at, "updated_at": rule.updated_at,
    }


def rule_networks(db: Session, rule_id: int) -> int:
    return db.execute(select(func.count()).select_from(Network).where(Network.zone_rule_id == rule_id)).scalar_one()


def _checked_rule(db: Session, data: dict[str, Any]) -> dict[str, Any]:
    validate_rule(data["match"], data["value"])
    _check_zone(db, data["zone"])
    return {**data, "value": normalize_value(data["match"], data["value"])}


def create_rule(db: Session, data: dict[str, Any]) -> NetworkZoneRule:
    """Новое правило — в конец списка; группы не ручных сетей пересчитываются."""
    data = _checked_rule(db, data)
    last = db.execute(select(func.max(NetworkZoneRule.position))).scalar()
    rule = NetworkZoneRule(**data, position=(last or 0) + 1)
    db.add(rule)
    db.flush()
    apply_zone_rules(db)
    return rule


def update_rule(db: Session, rule: NetworkZoneRule, data: dict[str, Any]) -> NetworkZoneRule:
    for name, value in _checked_rule(db, data).items():
        setattr(rule, name, value)
    db.flush()
    apply_zone_rules(db)
    return rule


def _renumber(rules: Iterable[NetworkZoneRule]) -> None:
    for i, rule in enumerate(rules, 1):
        rule.position = i


def delete_rule(db: Session, rule: NetworkZoneRule) -> None:
    """Сети правила пересчитываются по оставшимся; номера правил — снова подряд."""
    db.delete(rule)
    db.flush()
    _renumber(db.execute(select(NetworkZoneRule).order_by(NetworkZoneRule.position, NetworkZoneRule.id)).scalars())
    apply_zone_rules(db)


def reorder_rules(db: Session, ids: list[int]) -> None:
    """`ids` — все правила в новом порядке, каждое ровно один раз."""
    rules = {r.id: r for r in db.execute(select(NetworkZoneRule)).scalars()}
    if len(ids) != len(set(ids)) or set(ids) != set(rules):
        raise ValueError("порядок должен перечислять все правила, каждое по одному разу")
    _renumber(rules[i] for i in ids)
    db.flush()
    apply_zone_rules(db)


PREVIEW_SAMPLE = 20


def preview_rule(db: Session, data: dict[str, Any]) -> dict[str, Any]:
    """Какие не ручные сети забрало бы правило на месте `position` (по умолчанию — в конце), с учётом
    правил выше него; база не меняется. Правило с тем же номером встаёт перед существующим — так
    проверяется и правка правила."""
    position = data.get("position")
    data = _checked_rule(db, {k: data[k] for k in ("match", "value", "zone")})
    rules = _rules(db)
    at = len(rules) if position is None else sum(1 for r in rules if r.position < position)
    candidate = Rule(id=0, position=0, enabled=True, **data)
    ordered = [replace(r, position=i) for i, r in enumerate([*rules[:at], candidate, *rules[at:]], 1)]
    external = db.get(AssetZone, EXTERNAL_ZONE) is not None
    count = 0
    sample: list[dict[str, Any]] = []
    for network in db.execute(select(Network).where(Network.zone_source != SOURCE_MANUAL).order_by(Network.cidr)).scalars():
        if _decide(ordered, network, external)[2] == 0:
            count += 1
            if len(sample) < PREVIEW_SAMPLE:
                sample.append({"id": network.id, "cidr": network.cidr, "title": network.title, "zone_before": network.zone})
    return {"count": count, "sample": sample}
