"""Сопоставление пакета с правилом сетевого экрана по критериям (спека §4.3): да, нет, возможно.

Чистые функции без БД. Каждый критерий даёт `Tri` и короткую подпись со значением правила и значением пакета.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

from api.modules.ksc.core.firewall.model import Packet, Protocol, RuleView, ZoneView
from api.modules.ksc.core.policy_model import Address, PortRange


class Tri(Enum):
    YES = "yes"
    NO = "no"
    MAYBE = "maybe"


@dataclass(frozen=True)
class Criterion:
    #: direction | protocol | icmp_type | local_ports | remote_ports | address | local_address | enabled
    name: str
    result: Tri
    text: str


@dataclass(frozen=True)
class RuleMatch:
    rule: RuleView
    result: Tri
    criteria: tuple[Criterion, ...]
    #: Ровно один критерий NO, остальные YES (только у включённого правила, не у правила потока в ответном пакете).
    almost: Criterion | None
    #: Тексты допущений при MAYBE через «; »; иначе "".
    assumption: str


_PROTOCOLS: dict[int, str] = {Protocol.TCP: "TCP", Protocol.UDP: "UDP", Protocol.ICMP: "ICMP", Protocol.ICMPV6: "ICMPv6"}
_DIRECTIONS = {0: "входящий (пакет)", 1: "исходящий (пакет)", 2: "входящий/исходящий", 3: "входящий (поток)", 4: "исходящий (поток)"}
_NETWORKS = {0: "доверенные сети", 1: "локальные сети", 2: "публичные сети"}
_HIDDEN = {"secret": "адрес скрыт: обновите выгрузку сборщиком 1.3+", "unparsed": "адрес не разобран"}

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network


@lru_cache(maxsize=4096)
def _ip(ip: str) -> IPAddress:
    return ipaddress.ip_address(ip)


@lru_cache(maxsize=4096)
def _network(ip: str, mask: int | None) -> IPNetwork | None:
    """Сеть адреса правила; None — маска не подходит к адресу."""
    try:
        return ipaddress.ip_network(ip if mask is None else f"{ip}/{mask}", strict=False)
    except ValueError:
        return None


def _either(results: Iterable[Criterion], none: Criterion) -> Criterion:
    """Любой из вариантов: первый YES, иначе первый MAYBE, иначе первый NO (или `none`, если вариантов нет)."""
    found = list(results)
    for want in (Tri.YES, Tri.MAYBE, Tri.NO):
        if hit := next((c for c in found if c.result is want), None):
            return hit
    return none


def _crit(name: str, ok: bool, text: str) -> Criterion:
    return Criterion(name, Tri.YES if ok else Tri.NO, text)


def zone_of(ip: str, zones: tuple[ZoneView, ...]) -> int | None:
    """Код вида первой описанной зоны, в сеть которой входит адрес; None — не в описанных сетях."""
    addr = _ip(ip)
    return next((z.kind for z in zones if z.network is not None and z.network.version == addr.version and addr in z.network), None)


def _direction(rule: RuleView, outbound: bool, reply: bool) -> Criterion:
    name, code = "direction", rule.scope.direction
    if "direction" in rule.scope.unread:
        return Criterion(name, Tri.MAYBE, "направление правила не прочитано")
    if code is None:
        return Criterion(name, Tri.YES, "направление не задано")
    if code == 2:
        return Criterion(name, Tri.YES, "входящий/исходящий: любое направление")
    if code in (3, 4) and reply:
        return Criterion(name, Tri.NO, "правило потока не участвует в ответном пакете")
    if code not in _DIRECTIONS:
        return Criterion(name, Tri.MAYBE, f"код направления {code} неизвестен")
    # «(пакет)» — по направлению пакета (у ответного обратное), «(поток)» — по направлению соединения.
    out = outbound != reply if code in (0, 1) else outbound
    side = "исходящий" if out else "входящий"
    ok = (code in (1, 4)) == out
    return _crit(name, ok, f"{_DIRECTIONS[code]} {'=' if ok else '≠'} {side}")


def _protocol_text(code: int) -> str:
    return _PROTOCOLS.get(code, str(code))


def _protocol(rule: RuleView, packet: Packet) -> Criterion:
    name, code = "protocol", rule.scope.protocol
    if "protocol" in rule.scope.unread:
        return Criterion(name, Tri.MAYBE, "протокол правила не прочитан")
    if code is None:
        return Criterion(name, Tri.YES, "любой протокол")
    if packet.protocol is None:
        return Criterion(name, Tri.MAYBE, f"протокол пакета не задан, в правиле {_protocol_text(code)}")
    ok = code == packet.protocol
    return _crit(name, ok, f"{_protocol_text(packet.protocol)} {'=' if ok else '≠'} {_protocol_text(code)}")


def _icmp_type(rule: RuleView, packet: Packet) -> Criterion:
    name, kind = "icmp_type", rule.scope.icmp_type
    unread = "icmp_type" in rule.scope.unread
    if kind is None and not unread:
        return Criterion(name, Tri.YES, "вид ICMP любой")
    if packet.icmp_type is None:
        # Вид ICMP при проверке может не вводиться: правило с видом подходит с пометкой (спека §4.3).
        return Criterion(name, Tri.YES, f"вид ICMP {kind if kind is not None else 'правила'} не проверялся")
    if unread:
        return Criterion(name, Tri.MAYBE, "вид ICMP правила не прочитан")
    ok = kind == packet.icmp_type
    return _crit(name, ok, f"вид ICMP {packet.icmp_type} {'=' if ok else '≠'} {kind}")


def _ranges_text(ranges: Sequence[PortRange]) -> str:
    parts = [str(b) if b == e else f"{b}-{e}" for b, e in ranges[:4]]
    return ", ".join(parts) + (", …" if len(ranges) > 4 else "")


def _ports(name: str, label: str, ranges: tuple[PortRange, ...], port: int | None, unread: bool) -> Criterion:
    """Пустой список — любой порт; пары включительно; при пропущенной паре (`unread` `ports`) непопадание — MAYBE."""
    if not ranges and not unread:
        return Criterion(name, Tri.YES, f"{label} любой")
    if port is None:
        return Criterion(name, Tri.MAYBE, f"{label} пакета не задан")
    if any(b <= port <= e for b, e in ranges):
        return Criterion(name, Tri.YES, f"{label} {port} ∈ {_ranges_text(ranges)}")
    if unread:
        return Criterion(name, Tri.MAYBE, f"{label} {port}: порты правила прочитаны не полностью")
    return Criterion(name, Tri.NO, f"{label} {port} ∉ {_ranges_text(ranges)}")


def _same_host(rule_host: str, host: str) -> bool:
    """Имена без учёта регистра; если у одного имени нет домена — сравниваются первые метки (с FQDN и без)."""
    a, b = rule_host.lower().rstrip("."), host.lower().rstrip(".")
    if "." in a and "." in b:
        return a == b
    return a.split(".", 1)[0] == b.split(".", 1)[0]


def _address(name: str, a: Address, ip: str | None, host: str, what: str) -> Criterion:
    """Один адрес правила против адреса (`ip`) и имени (`host`) стороны пакета: `ips`, иначе имя, иначе адрес с маской."""
    if a.hidden:
        return Criterion(name, Tri.MAYBE, _HIDDEN.get(a.hidden, "адрес не разобран"))
    if a.ips:
        return _either((_address(name, i, ip, host, what) for i in a.ips), Criterion(name, Tri.NO, ""))
    if a.host:
        if not host:
            return Criterion(name, Tri.MAYBE, f"имя узла {a.host} не проверено")
        ok = _same_host(a.host, host)
        return _crit(name, ok, f"имя {host} {'=' if ok else '≠'} {a.host}")
    if not a.ip:
        return Criterion(name, Tri.MAYBE, "адрес не разобран")
    shown = a.ip if a.mask is None else f"{a.ip}/{a.mask}"
    if ip is None:
        return Criterion(name, Tri.MAYBE, f"{what} не задан")
    network = _network(a.ip, a.mask)
    if network is None:
        return Criterion(name, Tri.MAYBE, f"адрес {shown}: маска не читается")
    addr = _ip(ip)
    if addr.version != network.version:
        return Criterion(name, Tri.NO, f"адрес {ip}: другая версия IP, чем {shown}")
    ok = addr in network
    return _crit(name, ok, f"адрес {ip} {'∈' if ok else '∉'} {shown}")


def _zone(code: int, ip: str | None, zones: tuple[ZoneView, ...]) -> Criterion:
    """Адрес в зоне правила: входит в одну из описанных сетей этого вида; не входит ни в одну — зона неизвестна."""
    name, label = "address", _NETWORKS.get(code, f"зона {code}")
    if ip is None:
        return Criterion(name, Tri.MAYBE, "адрес назначения не задан")
    addr = _ip(ip)
    kinds = {z.kind for z in zones if z.network is not None and z.network.version == addr.version and addr in z.network}
    if code in kinds:
        return Criterion(name, Tri.YES, f"адрес {ip} в зоне «{label}»")
    hidden = any(z.network is None and z.kind in (code, None) for z in zones)
    if not kinds or None in kinds or hidden:
        return Criterion(name, Tri.MAYBE, f"зона адреса {ip} неизвестна")
    return Criterion(name, Tri.NO, f"адрес {ip} не в зоне «{label}»")


def _remote(rule: RuleView, packet: Packet, zones: tuple[ZoneView, ...]) -> Criterion:
    """Удалённый адрес: любой из адресов правила или зона правила; нечитаемые зона или маска делают NO возможным."""
    s, name = rule.scope, "address"
    unread = "networks" in s.unread or "mask" in s.unread
    if not s.remote and s.networks is None and not unread:
        return Criterion(name, Tri.YES, "любой адрес")
    options = [_address(name, a, packet.remote_ip, packet.remote_host, "адрес назначения") for a in s.remote]
    if s.networks is not None:
        options.append(_zone(s.networks, packet.remote_ip, zones))
    found = _either(options, Criterion(name, Tri.NO, ""))
    if found.result is Tri.NO and unread:
        return Criterion(name, Tri.MAYBE, "зона правила не прочитана" if "networks" in s.unread else "маска адреса правила не прочитана")
    return found


def _local(rule: RuleView, host_ip: str) -> Criterion:
    name = "local_address"
    if not rule.scope.local:
        return Criterion(name, Tri.YES, "любой локальный адрес")
    found = _either((_address(name, a, host_ip or None, "", "адрес хоста") for a in rule.scope.local), Criterion(name, Tri.NO, ""))
    if found.result is Tri.NO and "mask" in rule.scope.unread:
        return Criterion(name, Tri.MAYBE, "маска адреса правила не прочитана")
    return Criterion(name, found.result, f"локальный: {found.text}")


def match_rule(rule: RuleView, packet: Packet, zones: tuple[ZoneView, ...], host_ip: str, *, reply: bool = False) -> RuleMatch:
    """Критерии правила для пакета стороны хоста. `reply` — ответный пакет: направление обратное, правила «(поток)» в нём не
    участвуют. Итог: NO, если есть NO; иначе MAYBE, если есть MAYBE; иначе YES.
    Порты считаются со стороны компьютера и в ответном пакете не меняются местами (Ruling 6, поправка к спеке §4.3)."""
    ports_unread = "ports" in rule.scope.unread
    enabled = _crit("enabled", rule.enabled, "правило включено" if rule.enabled else "правило выключено")
    direction = _direction(rule, packet.outbound, reply)
    criteria = (
        enabled,
        direction,
        _protocol(rule, packet),
        _icmp_type(rule, packet),
        _ports("local_ports", "лок. порт", rule.scope.local_ports, packet.local_port, ports_unread),
        _ports("remote_ports", "уд. порт", rule.scope.remote_ports, packet.remote_port, ports_unread),
        _remote(rule, packet, zones),
        _local(rule, host_ip),
    )
    results = {c.result for c in criteria}
    result = Tri.NO if Tri.NO in results else Tri.MAYBE if Tri.MAYBE in results else Tri.YES
    stream_on_reply = reply and rule.scope.direction in (3, 4)
    noes = [c for c in criteria[1:] if c.result is Tri.NO]
    almost = noes[0] if rule.enabled and not stream_on_reply and len(noes) == 1 and Tri.MAYBE not in results else None
    assumption = "; ".join(c.text for c in criteria if c.result is Tri.MAYBE) if result is Tri.MAYBE else ""
    return RuleMatch(rule, result, criteria, almost, assumption)
