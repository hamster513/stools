"""Модель движка сетевого экрана: пакет, правила с разобранной структурой, зоны, действующие списки хоста.

Только данные (frozen dataclass), без БД: из таблиц снапшота их собирает `services/firewall`.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from ipaddress import IPv4Network, IPv6Network

from api.modules.ksc.core.policy_model import AppGroupDefault, Scope


class Verdict(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    #: Решают правила программ.
    APP = "app"
    #: Зависит от профиля, активация которого не определена, или от нечитаемого критерия.
    DEPENDS = "depends"
    #: Правила не применяются (экрана или политики нет).
    NOT_APPLIED = "not_applied"
    UNDETERMINED = "undetermined"


class Protocol(IntEnum):
    """Коды протокола (`unique_id`) как в выгрузке."""
    TCP = 969930675
    UDP = 2001472323
    ICMP = -1238929178
    ICMPV6 = -1356346777


@dataclass(frozen=True)
class Packet:
    #: Сторона: True — исходящее соединение.
    outbound: bool
    #: Код протокола; None — любой или не задан.
    protocol: int | None
    local_port: int | None
    remote_port: int | None
    #: Канонический адрес; None — неизвестен.
    remote_ip: str | None
    #: Имя хоста назначения (для `hostName`); "" — нет.
    remote_host: str
    icmp_type: int | None = None


@dataclass(frozen=True)
class RuleView:
    """Правило из `ksc_net_rule` с разобранной структурой адресов; `*_text` — подписи словами, как на экране."""
    row_id: int
    policy_id: int
    #: Имя профиля; "" — сама политика.
    profile: str
    #: packet | app
    layer: str
    position: int
    name: str
    action: str
    enabled: bool
    scope: Scope
    direction_text: str
    protocol_text: str
    local_ports_text: str
    remote_ports_text: str
    addresses_text: str


@dataclass(frozen=True)
class ZoneView:
    """Зона сети; `network` None — адрес скрыт или не разобран."""
    name: str
    #: Код вида зоны (`type`) как в выгрузке.
    kind: int | None
    network: IPv4Network | IPv6Network | None


@dataclass(frozen=True)
class SourceSet:
    """Список правил одного источника: политики (`profile` "", `priority` None) или профиля."""
    policy_id: int
    profile: str
    #: Приоритет профиля (меньше — выше); None — сама политика.
    priority: int | None
    #: Замок листа списка у источника; None — признака замка нет.
    locked: bool | None
    rules: tuple[RuleView, ...]


@dataclass(frozen=True)
class HostFirewall:
    """Сетевой экран хоста: действующие списки по замкам профилей, зоны, состояние и оговорки."""
    host_id: str
    host_name: str
    host_ip: str
    #: Действующая политика KES; None — у хоста её нет.
    policy_id: int | None
    policy_name: str
    #: Пакетные правила политики.
    packet: SourceSet | None
    #: Активные профили с замком на пакетных правилах, по приоритету: каждый перекрывает список политики.
    packet_profiles: tuple[SourceSet, ...]
    #: Профили с замком на пакетных правилах, активацию которых не определить.
    packet_undetermined: tuple[SourceSet, ...]
    app: SourceSet | None
    app_profiles: tuple[SourceSet, ...]
    app_undetermined: tuple[SourceSet, ...]
    #: Действующие зоны сетей по замку: профиля либо политики.
    zones: tuple[ZoneView, ...]
    firewall_enabled: bool | None
    notify_only: bool | None
    hips_enabled: bool | None
    hips_notify_only: bool | None
    #: Компонент «Сетевой экран» на хосте работает; None — статус неизвестен.
    component_running: bool | None
    trust_groups: tuple[AppGroupDefault, ...]
    #: Оговорки к выводам движка.
    notes: tuple[str, ...]
    #: Чьи зоны сетей действуют: имя профиля с замком зон; "" — политика.
    zones_profile: str = ""
