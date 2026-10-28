"""Сборка сетевого экрана хоста из политики и её профилей (без БД; строки снапшота читает `services/firewall`).

Перекрытие профилем (спец. §4.1). Справка Kaspersky Security Center, «Профили политик»
(https://support.kaspersky.com/KSC/15.1/en-US/92434.htm): в профиле действуют настройки с закрытым замком; если
несколько активных профилей задают одну настройку, действует профиль выше в списке приоритетов (меньшее `priority`).
Поэтому лист профиля учитывается, только если его замок в сырых секциях профиля закрыт (`locks.<лист> is True`):
открытый замок или его отсутствие — копия настроек политики, она ничего не перекрывает; профиль без строки
`ksc_policy_firewall` замков не имеет. Каждый лист (пакетные правила, правила программ, зоны сетей, флаг компонента
Firewall) — независимо.
Заменяет ли список профиля список политики или дополняет его, решает движок (настройка `firewall_profile_mode`): здесь
перечисляются все перекрывающие профили по приоритету.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from api.modules.ksc.core.checks.hosts import COMPONENT_OFF_STATES
from api.modules.ksc.core.firewall.model import HostFirewall, RuleView, SourceSet, ZoneView
from api.modules.ksc.core.policy_model import FirewallSettings, NetworkZone

NOTE_NO_POLICY = "политики KES у хоста нет"
NOTE_INACTIVE_POLICY = "политика для автономных пользователей / неактивная политика не проверялась"
NOTE_NO_SCOPE = "правило без структуры адресов"
NOTE_COMPONENT_OFF = "компонент „Сетевой экран“ выключен в политике"
NOTE_NO_POLICY_FIREWALL = "настроек сетевого экрана у политики нет в выгрузке"
#: Названия компонента сетевого экрана на хосте (подстрока без учёта регистра).
FIREWALL_COMPONENT = ("firewall", "сетевой экран")


def note_zones_undetermined(profile: str) -> str:
    return f"зоны сетей могут перекрываться профилем „{profile}“ (активация не определена)"


def note_state_undetermined(section: str, profile: str) -> str:
    """`section` — «сетевого экрана» или «HIPS»."""
    return f"состояние {section} может перекрываться профилем „{profile}“ (активация не определена)"


def note_component_off_profile(profile: str) -> str:
    return f"компонент „Сетевой экран“ выключен профилем „{profile}“"


def note_component_undetermined(profile: str) -> str:
    return f"компонент Firewall может быть выключен профилем „{profile}“ (активация не определена)"


@dataclass(frozen=True)
class Source:
    """Политика или профиль на входе сборки."""
    #: Имя профиля; "" — сама политика.
    profile: str
    #: Приоритет профиля; None — политика.
    priority: int | None
    #: Активация на хосте (None — не определена); у политики — True.
    active: bool | None
    #: Сетевой экран источника; None — строки `ksc_policy_firewall` нет.
    firewall: FirewallSettings | None
    packet: tuple[RuleView, ...]
    app: tuple[RuleView, ...]


def zone_view(z: NetworkZone) -> ZoneView:
    """Адрес с маской — сеть; без маски — один узел (/32, /128); скрытый, не разобранный или неверный — без сети."""
    a = z.address
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    if a.ip and not a.hidden:
        try:
            network = ipaddress.ip_network(f"{a.ip}/{a.mask}" if a.mask is not None else a.ip, strict=False)
        except ValueError:
            network = None
    return ZoneView(z.name, z.kind, network)


def component_running(components: Iterable[tuple[str, int]]) -> bool | None:
    """Компонент сетевого экрана на хосте: выключен — False (если хост перечисляет его дважды — худшее), иначе True;
    компонента нет или список пуст — None (статус неизвестен)."""
    codes = [code for name, code in components if any(n in name.lower() for n in FIREWALL_COMPONENT)]
    if not codes:
        return None
    return not any(code in COMPONENT_OFF_STATES for code in codes)


def _lock(s: Source, leaf: str) -> bool | None:
    return getattr(s.firewall.locks, leaf) if s.firewall is not None else None


def _set(policy_id: int, s: Source, leaf: str, rules: tuple[RuleView, ...]) -> SourceSet:
    return SourceSet(policy_id, s.profile, s.priority, _lock(s, leaf), rules)


def _flag(policy: Source, overriding: Sequence[Source], name: str) -> tuple[bool | None, Source]:
    """Значение политики, перекрытое первым по приоритету профилем, где флаг задан; второе — чьё значение действует."""
    for s in overriding:
        value: bool | None = getattr(s.firewall, name)
        if value is not None:
            return value, s
    return (getattr(policy.firewall, name) if policy.firewall is not None else None), policy


def _above(s: Source, source: Source) -> bool:
    """Профиль `s` выше по приоритету, чем действующий источник (политику перекрывает любой профиль)."""
    return source.priority is None or (s.priority or 0) < source.priority


def _may_change(policy: Source, on: Sequence[Source], maybe: Sequence[Source], names: Sequence[str]) -> list[Source]:
    """Неопределённые профили, которые, окажись они активны, поменяли бы хотя бы один из флагов `names`."""
    out: list[Source] = []
    for s in maybe:
        for name in names:
            value, source = _flag(policy, on, name)
            own = getattr(s.firewall, name)
            if own is not None and own != value and _above(s, source):
                out.append(s)
                break
    return out


def host_firewall(host_id: str, host_name: str, host_ip: str, policy_id: int | None, policy_name: str, policy: Source | None,
                  profiles: Sequence[Source], components: Iterable[tuple[str, int]], notes: Sequence[str]) -> HostFirewall:
    """Сетевой экран хоста. `profiles` — профили политики с активацией на хосте (выключенный — `active` False).

    Флаги экрана (`firewall_enabled`, `notify_only`) профиль перекрывает при замке на пакетных правилах, флаги HIPS
    (`hips_enabled`, `hips_notify_only`) — при замке на группах доверия: замки самих флагов не читаются, это приближение
    по гранулярности замков секции HIPS, которая есть. Флаг компонента Firewall (`KLPRSS_Components`) профиль перекрывает
    при замке `component`; выключен — экран выключен, с оговоркой. Профиль с неопределённой активацией, который поменял бы
    зоны, флаги или компонент, ничего не перекрывает, а попадает в оговорки."""
    running = component_running(components)
    if policy_id is None or policy is None:
        return HostFirewall(host_id, host_name, host_ip, None, "", None, (), (), None, (), (), (), None, None, None, None, running, (),
                            tuple(notes))
    out = list(notes)
    if policy.firewall is None:
        out.append(NOTE_NO_POLICY_FIREWALL)
    ordered = sorted(profiles, key=lambda s: s.priority if s.priority is not None else 0)

    def overriding(leaf: str, active: bool | None) -> list[Source]:
        return [s for s in ordered if s.active is active and _lock(s, leaf) is True]

    packet_on, packet_maybe = overriding("packet", True), overriding("packet", None)
    app_on, app_maybe = overriding("app", True), overriding("app", None)
    networks_on, networks_maybe = overriding("networks", True), overriding("networks", None)
    component_on, component_maybe = overriding("component", True), overriding("component", None)
    zones_source = networks_on[0] if networks_on else policy
    out += [note_zones_undetermined(s.profile) for s in networks_maybe if _above(s, zones_source)]
    out += [note_state_undetermined("сетевого экрана", s.profile) for s in _may_change(policy, packet_on, packet_maybe, ("enabled", "notify_only"))]
    out += [note_state_undetermined("HIPS", s.profile) for s in _may_change(policy, app_on, app_maybe, ("hips_enabled", "hips_notify_only"))]
    zones = tuple(zone_view(z) for z in zones_source.firewall.zones) if zones_source.firewall is not None else ()
    app_source = app_on[0] if app_on else policy
    trust_groups = app_source.firewall.app_groups if app_source.firewall is not None else ()
    firewall_enabled, _ = _flag(policy, packet_on, "enabled")
    component, component_source = _flag(policy, component_on, "component_enabled")
    if component is False:
        firewall_enabled = False
        out.append(NOTE_COMPONENT_OFF if component_source is policy else note_component_off_profile(component_source.profile))
    else:
        out += [note_component_undetermined(s.profile) for s in component_maybe
                if s.firewall is not None and s.firewall.component_enabled is False and _above(s, component_source)]
    return HostFirewall(
        host_id=host_id, host_name=host_name, host_ip=host_ip, policy_id=policy_id, policy_name=policy_name,
        packet=_set(policy_id, policy, "packet", policy.packet),
        packet_profiles=tuple(_set(policy_id, s, "packet", s.packet) for s in packet_on),
        packet_undetermined=tuple(_set(policy_id, s, "packet", s.packet) for s in packet_maybe),
        app=_set(policy_id, policy, "app", policy.app),
        app_profiles=tuple(_set(policy_id, s, "app", s.app) for s in app_on),
        app_undetermined=tuple(_set(policy_id, s, "app", s.app) for s in app_maybe),
        zones=zones, firewall_enabled=firewall_enabled, notify_only=_flag(policy, packet_on, "notify_only")[0],
        hips_enabled=_flag(policy, app_on, "hips_enabled")[0], hips_notify_only=_flag(policy, app_on, "hips_notify_only")[0],
        component_running=running, trust_groups=trust_groups, notes=tuple(out),
    )
