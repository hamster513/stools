"""Правила в тени и дубли (спека §4.6): более раннее включённое правило того же слоя полностью покрывает позднее.

Чистые функции без БД. Покрытие консервативное: где множество пакетов не сравнить уверенно (зона против адреса, скрытый
или нечитаемый критерий), правило не покрывает и не покрывается — метка «в тени» не ставится.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from api.modules.ksc.core.firewall.match import IPNetwork, network_of
from api.modules.ksc.core.firewall.model import RuleView
from api.modules.ksc.core.policy_model import Address, PortRange


@dataclass(frozen=True)
class Shadow:
    """Более раннее правило, покрывающее данное: `same_action` — действие то же (дубль), иначе правило никогда не сработает."""
    by_row_id: int
    by_position: int
    by_name: str
    same_action: bool


@dataclass(frozen=True)
class _Side:
    """Адреса одной стороны правила: сети (адрес с маской и каждый адрес из `ips`) и имена узлов без `ips` в нижнем регистре."""
    networks: tuple[IPNetwork, ...]
    hosts: frozenset[str]


@dataclass(frozen=True)
class _Footprint:
    """Правило с разобранными адресами; `remote`/`local` None — среди адресов есть скрытый или неразобранный."""
    rule: RuleView
    remote: _Side | None
    local: _Side | None


def _side(addresses: Iterable[Address]) -> _Side | None:
    networks: list[IPNetwork] = []
    hosts: set[str] = set()
    for a in addresses:
        if a.hidden:
            return None
        if a.ips:
            # Имя с разрешёнными адресами сопоставляется по адресам (как в `match`), имя не учитывается.
            for i in a.ips:
                if i.hidden or not i.ip or (n := network_of(i.ip, i.mask)) is None:
                    return None
                networks.append(n)
        elif a.host:
            hosts.add(a.host.lower())
        elif a.ip and (n := network_of(a.ip, a.mask)) is not None:
            networks.append(n)
        else:
            return None
    return _Side(tuple(networks), frozenset(hosts))


def _footprint(rule: RuleView) -> _Footprint:
    return _Footprint(rule, _side(rule.scope.remote), _side(rule.scope.local))


def _side_covers(outer: _Side, inner: _Side) -> bool:
    """Каждая сеть `inner` — подсеть какой-то сети `outer` той же версии IP; каждое имя `inner` есть у `outer`."""
    return inner.hosts <= outer.hosts and all(
        any(n.version == o.version and n.subnet_of(o) for o in outer.networks)  # type: ignore[arg-type]
        for n in inner.networks)


def _ports_cover(outer: tuple[PortRange, ...], inner: tuple[PortRange, ...]) -> bool:
    """Пустой `outer` — любой порт; иначе каждая пара `inner` внутри какой-то пары `outer` (пустой `inner` — не внутри)."""
    if not outer:
        return True
    if not inner:
        return False
    for ib, ie in inner:
        for ob, oe in outer:
            if ob <= ib and ie <= oe:
                break
        else:
            return False
    return True


def _covers(outer: _Footprint, inner: _Footprint) -> bool:
    o, i = outer.rule.scope, inner.rule.scope
    if outer.rule.layer != inner.rule.layer or o.unread or i.unread:
        return False
    if outer.remote is None or outer.local is None or inner.remote is None or inner.local is None:
        return False
    # «Вх./исх.» и не заданное направление покрывают всё; «(пакет)» и «(поток)» — разные направления.
    if o.direction not in (None, 2) and o.direction != i.direction:
        return False
    if o.protocol is not None and o.protocol != i.protocol:
        return False
    if o.icmp_type is not None and o.icmp_type != i.icmp_type:
        return False
    if not (_ports_cover(o.local_ports, i.local_ports) and _ports_cover(o.remote_ports, i.remote_ports)):
        return False
    if o.remote or o.networks is not None:
        # Зоны — по равенству; зона и адрес друг друга не покрывают.
        if not i.remote and i.networks is None:
            return False
        if i.networks is not None and i.networks != o.networks:
            return False
        if i.remote and not _side_covers(outer.remote, inner.remote):
            return False
    return not o.local or (bool(i.local) and _side_covers(outer.local, inner.local))


def covers(outer: RuleView, inner: RuleView) -> bool:
    """Множество пакетов `outer` полностью покрывает множество пакетов `inner` (того же слоя) по каждому критерию.
    Включённость не учитывается — её проверяет `shadows`."""
    return _covers(_footprint(outer), _footprint(inner))


def shadows(rules: Sequence[RuleView]) -> dict[int, Shadow]:
    """`row_id` правила → первое более раннее включённое правило того же слоя, покрывающее его. `rules` — правила одного
    набора (политика или профиль) уже в порядке позиций: функция не сортирует, «раньше» — раньше в последовательности.
    Выключенные правила тени не дают, но сами бывают в тени. O(n²) на список, адреса разбираются один раз на правило."""
    found: dict[int, Shadow] = {}
    #: Более ранние включённые правила: срез списка на каждом правиле был бы ещё одним квадратичным копированием.
    earlier: list[_Footprint] = []
    for rule in rules:
        inner = _footprint(rule)
        outer = next((f for f in earlier if _covers(f, inner)), None)
        if outer is not None:
            s = outer.rule
            found[rule.row_id] = Shadow(s.row_id, s.position, s.name, s.action == rule.action)
        if rule.enabled:
            earlier.append(inner)
    return found
