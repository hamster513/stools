"""Извлекатель KES для Windows (`KLPOL_PRODUCT` = `KES`): исключения, доверенные программы и сетевые правила.

Секции читаются в «голом» виде (`bare_sections`): уровень контейнеров `KLPRSS_Val` в выгрузке не важен. Элемент списка
неожиданной формы (не словарь, нет нужного ключа) пропускается. Коды перечислений — только подтверждённые калибровкой,
неизвестный код показывается «код N». Запись выключена только явным `enabled: false` (нет ключа или скрыто — включена).

`position` правила — сквозной номер среди оставленных (не пропущенных) правил своего слоя: `packet` — по списку
`firewall.networkPacketRules`, `app` — по всем группам доверия (сначала правила группы, затем её программ). `log` и
`networkAdapters` пакетных правил в записи не переносятся.

Кроме записей — `firewall`: состояние сетевого экрана и HIPS, зоны сетей, группы доверия (без программ) и замки листов;
значения из «голых» секций, замки — из сырых (`find_setting`). Булевы — только `bool`, коды — только int (не bool), иначе None.
"""
from __future__ import annotations

import base64
import ipaddress
from typing import Any

from api.modules.ksc.core.policy_contents import bare_sections, find_setting, truncate_value
from api.modules.ksc.core.policy_model import (
    OBJECT,
    Address,
    AppGroupDefault,
    Exclusion,
    FirewallSettings,
    Locks,
    NetRule,
    NetworkZone,
    PolicyObjects,
    Scope,
)
from api.modules.ksc.core.secrets import HIDDEN

TRUSTED_ZONE = "852d0287"
HIPS = "cf9370d5"
_ZONE = "scanExclusionsAndTrustedZone"

#: Листья (`flat_settings`), из которых получены записи: журнал изменений не считает их настройками. `hips.appGroups` сюда не
#: входит: в нём же правила доступа к сети, привилегии, ресурсы и пути программ — их правки журнал должен видеть.
CONSUMED = frozenset({
    (TRUSTED_ZONE, f"{_ZONE}.scanExclusions"),
    (TRUSTED_ZONE, f"{_ZONE}.scanExclusions_merging_crutch"),
    (TRUSTED_ZONE, f"{_ZONE}.trustedApplications"),
    (TRUSTED_ZONE, f"{_ZONE}.trustedApplications_merging_crutch"),
    (HIPS, "firewall.networkPacketRules"),
})

#: Подписи флагов доверенной программы, на которые опираются правила рисков (`core/exclusion_risks`).
OPEN_FILES = "не проверять открываемые файлы"
BEHAVIOR = "не контролировать активность"
CHILDREN = "не контролировать дочерние процессы"
CHILDREN_RECURSIVE = "не контролировать дочерние процессы рекурсивно"
NET = "не проверять сетевой трафик"
NET_ENCRYPTED = "не проверять сетевой трафик (только зашифрованный)"

#: Флаги доверенной программы → подпись; `excludeNet` — вложенный словарь, разбирается отдельно (на своём месте в порядке).
_TRUSTED_FLAGS = (
    ("excludeOpenFiles", OPEN_FILES),
    ("excludeBehavior", BEHAVIOR),
    ("excludeChildsBehavior", CHILDREN),
    ("excludeChildsBehaviorRecursive", CHILDREN_RECURSIVE),
    ("excludeHipsNoInherit", "не наследовать ограничения родителя"),
    ("excludeNet", ""),
    ("excludeSelfProt", "разрешить взаимодействие с интерфейсом программы"),
    ("excludeAmsiScan", "не проверять через AMSI"),
    ("excludeXDRTelemetry", "не передавать телеметрию XDR"),
    ("excludeFileIntegrityMonitoring", "не контролировать целостность файлов"),
    ("excludeRegistryIntegrityMonitoring", "не контролировать целостность реестра"),
    ("excludeConsoleInputMonitoring", "не контролировать ввод в консоли"),
)

_ACTIONS = {0: "разрешить", 1: "запретить", 2: "по правилам программ"}
_DIRECTIONS = {0: "входящий (пакет)", 1: "исходящий (пакет)", 2: "входящий/исходящий", 3: "входящий (поток)", 4: "исходящий (поток)"}
_PROTOCOLS = {969930675: "TCP", 2001472323: "UDP", -1238929178: "ICMP", -1356346777: "ICMPv6"}
_NETWORKS = {0: "доверенные сети", 1: "локальные сети", 2: "публичные сети"}


def _at(node: Any, path: str) -> Any:
    for key in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def _items(value: Any) -> list[dict[str, Any]]:
    """Элементы-словари списка; не список — пусто, не словарь — пропуск."""
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _enabled(item: dict[str, Any]) -> bool:
    return item.get("enabled") is not False


def _scalars(value: Any) -> str:
    """Непустой список скаляров через запятую, иначе ""."""
    if not isinstance(value, list) or not value or not all(isinstance(v, str | int | float) for v in value):
        return ""
    return ", ".join(str(v) for v in value)


def _code(labels: dict[int, str], value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, int) and not isinstance(value, bool) and value in labels:
        return labels[value]
    return f"код {value}"


def _scan_exclusion(item: dict[str, Any]) -> Exclusion | None:
    mask = _dict(item.get("objectMask"))
    path, name, file_hash = _text(mask.get("objectPath")), _text(item.get("objectName")), _text(item.get("fileHash"))
    raw_components = item.get("components")
    components = [c if isinstance(c, str) else truncate_value(c) for c in raw_components] if isinstance(raw_components, list) else []
    if file_hash:
        kind, value = "hash", file_hash
    elif path:
        kind, value = ("mask" if "*" in path or "?" in path else "path"), path
    elif name:
        kind, value = "threat", name
    else:
        return None
    if name and kind != "threat":
        components.append(f"{OBJECT}{name}")
    if mask.get("recursive") is True:
        components.append("рекурсивно")
    return Exclusion(kind, value, tuple(components), _enabled(item), _text(item.get("comment")))


def _trusted_app(item: dict[str, Any]) -> Exclusion | None:
    path = _text(item.get("filePath"))
    if not path:
        return None
    components: list[str] = []
    for key, label in _TRUSTED_FLAGS:
        if key == "excludeNet":
            net = _dict(item.get(key))
            if net.get("enabled") is True:
                only_encrypted = net.get("encryptedTrafficOnly") is True
                components.append(NET_ENCRYPTED if only_encrypted else NET)
                for title, values in (("узлы", net.get("hosts")), ("порты", net.get("ports"))):
                    if listed := _scalars(values):
                        components.append(f"{title}: {listed}")
        elif item.get(key) is True:
            components.append(label)
    return Exclusion("trusted_app", path, tuple(components), _enabled(item), _text(item.get("comment")))


def _ports(value: Any) -> str:
    out = []
    for p in _items(value):
        begin, end = p.get("begin"), p.get("end")
        if isinstance(begin, int) and isinstance(end, int):
            out.append(str(begin) if begin == end else f"{begin}-{end}")
    return ", ".join(out)


def _canonical(octets: Any) -> str:
    """Канонический адрес из `octets` (base64); "" — не разобран."""
    try:
        packed = base64.b64decode(octets, validate=True) if isinstance(octets, str) else b""
    except ValueError:  # binascii.Error и не-ASCII строка
        packed = b""
    return str(ipaddress.ip_address(packed)) if len(packed) in (4, 16) else ""


def _octets_address(octets: Any, mask: Any = None) -> Address:
    """Адрес из `octets`: скрытый сборщиком, не разобранный или канонический с маской (только int, не bool)."""
    if octets == HIDDEN:
        return Address(hidden="secret")
    ip = _canonical(octets)
    if not ip:
        return Address(hidden="unparsed")
    return Address(ip=ip, mask=mask if isinstance(mask, int) and not isinstance(mask, bool) else None)


def _address(item: dict[str, Any]) -> Address | None:
    """Имя узла, иначе адрес из `octets` с маской, иначе адреса, в которые разрешено имя (`hostNameIPs`, по одному, в порядке
    выгрузки); пустой — None."""
    if host := _text(item.get("hostName")):
        return Address(host=host)
    if "octets" in item:
        return _octets_address(item["octets"], item.get("mask"))
    ips = tuple(_octets_address(ip.get("octets")) for ip in _items(item.get("hostNameIPs")))
    return Address(ips=ips) if ips else None


def _icmp_type(proto: dict[str, Any], label: str) -> int | None:
    kind = _dict(proto.get("type")).get("value")
    return kind if label in ("ICMP", "ICMPv6") and isinstance(kind, int) and not isinstance(kind, bool) else None


def _addresses(items: Any) -> tuple[Address, ...]:
    return tuple(a for a in map(_address, _items(items)) if a is not None)


def _scope(proto: dict[str, Any], scope: dict[str, Any]) -> Scope:
    networks = scope.get("networks")
    return Scope(
        networks=networks if isinstance(networks, int) and not isinstance(networks, bool) else None,
        remote=_addresses(scope.get("remoteAddresses")), local=_addresses(scope.get("localAddresses")),
        icmp_type=_icmp_type(proto, _code(_PROTOCOLS, proto.get("unique_id"))),
    )


def _address_text(a: Address) -> str:
    if a.host:
        return a.host
    if a.ip:
        return f"{a.ip}/{a.mask}" if a.mask is not None else a.ip
    if a.hidden:
        return "адрес скрыт (сборщик до 1.3)" if a.hidden == "secret" else "адрес не разобран"
    return ", ".join(map(_address_text, a.ips))


def addresses_text(scope: Scope) -> str:
    """Подпись адресов правила: зона, удалённые адреса, затем локальные с префиксом «локальный: »."""
    parts = [_code(_NETWORKS, scope.networks)] if scope.networks is not None else []
    parts += [t for t in map(_address_text, scope.remote) if t]
    parts += [f"локальный: {t}" for t in map(_address_text, scope.local) if t]
    return "; ".join(parts)


def _protocol(proto: dict[str, Any]) -> str:
    uid = proto.get("unique_id")
    if uid is None:
        return "любой"
    label = _code(_PROTOCOLS, uid)
    kind = _icmp_type(proto, label)
    return f"{label} (вид {kind})" if kind is not None else label


def _net_rule(item: dict[str, Any], layer: str, position: int, owner: str = "") -> NetRule | None:
    name = item.get("name")
    if not isinstance(name, str) or "action" not in item:
        return None
    proto = _dict(item.get("protocol"))
    scope = _scope(proto, _dict(item.get("scope")))
    return NetRule(
        layer=layer, position=position, name=f"{owner}: {name}" if owner else name, action=_code(_ACTIONS, item["action"]),
        direction=_code(_DIRECTIONS, item.get("packetDirection")), protocol=_protocol(proto), local_ports=_ports(proto.get("localPorts")),
        remote_ports=_ports(proto.get("remotePorts")), addresses=addresses_text(scope), enabled=_enabled(item), scope=scope,
    )


def _rules(items: list[dict[str, Any]], layer: str, start: int, owner: str = "") -> list[NetRule]:
    out: list[NetRule] = []
    for item in items:
        rule = _net_rule(item, layer, start + len(out), owner)
        if rule is not None:
            out.append(rule)
    return out


def _bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _zone(item: dict[str, Any]) -> NetworkZone:
    address = _dict(item.get("address"))
    return NetworkZone(name=_text(item.get("name")), kind=_int(item.get("type")),
                       address=_octets_address(address.get("octets"), address.get("mask")))


def _app_groups(groups: list[dict[str, Any]]) -> tuple[AppGroupDefault, ...]:
    """Группы доверия в порядке выгрузки. `parent` — номер родителя в том же списке с 1, 0 — корень (прочтение по разведке
    `recon.md` задачи 1: у групп нет id, стандартные идут цепочкой `parent` 0,1,2,3, своя группа — с `parent` 0); ссылка вне
    списка или не int — верхний уровень. Правило доступа к сети — первое из `networkAccessRules`."""
    parents = [_int(g.get("parent")) for g in groups]
    out: list[AppGroupDefault] = []
    for group, parent in zip(groups, parents, strict=True):
        depth, seen, node = 0, set(), parent
        while node is not None and 1 <= node <= len(groups) and node not in seen:  # seen — защита от цикла
            seen.add(node)
            depth += 1
            node = parents[node - 1]
        rule = next(iter(_items(group.get("networkAccessRules"))), {})
        out.append(AppGroupDefault(name=_text(group.get("name")), parent=parent, depth=depth, allow=_bool(rule.get("allow")),
                                   networks=_int(rule.get("networks")), inherited=_bool(rule.get("inherited"))))
    return tuple(out)


def _lock(sections: dict[str, Any], path: str) -> bool | None:
    setting = find_setting(sections, HIPS, path)
    return setting.locked if setting is not None else None


def _firewall(sections: dict[str, Any], bare: dict[str, Any]) -> FirewallSettings | None:
    """Сетевой экран и HIPS; None — секции HIPS нет (или она не словарь)."""
    hips = bare.get(HIPS)
    if not isinstance(hips, dict):
        return None
    return FirewallSettings(
        enabled=_bool(_at(hips, "firewall.enabled")), notify_only=_bool(_at(hips, "firewall.notifyOnly")),
        hips_enabled=_bool(_at(hips, "hips.enabled")), hips_notify_only=_bool(_at(hips, "hips.notifyOnly")),
        zones=tuple(map(_zone, _items(_at(hips, "firewall.availableNetworks")))),
        app_groups=_app_groups(_items(_at(hips, "hips.appGroups"))),
        locks=Locks(packet=_lock(sections, "firewall.networkPacketRules"), networks=_lock(sections, "firewall.availableNetworks"),
                    app=_lock(sections, "hips.appGroups")),
    )


def extract_kes(sections: dict[str, Any]) -> PolicyObjects:
    """Записи политики или профиля KES для Windows: исключения (`scanExclusions`), доверенные программы
    (`trustedApplications`), пакетные правила сетевого экрана (слой `packet`), правила групп доверия и программ (слой `app`) и `firewall`."""
    bare = bare_sections(sections)
    zone, hips = _dict(_at(bare, f"{TRUSTED_ZONE}.{_ZONE}")), bare.get(HIPS)
    exclusions = [e for e in map(_scan_exclusion, _items(zone.get("scanExclusions"))) if e is not None]
    exclusions += [e for e in map(_trusted_app, _items(zone.get("trustedApplications"))) if e is not None]

    net_rules = _rules(_items(_at(hips, "firewall.networkPacketRules")), "packet", 0)
    app_rules: list[NetRule] = []
    for group in _items(_at(hips, "hips.appGroups")):
        app_rules += _rules(_items(group.get("networkPacketRules")), "app", len(app_rules), _text(group.get("name")))
        for app in _items(group.get("applications")):
            app_rules += _rules(_items(app.get("networkPacketRules")), "app", len(app_rules), _text(app.get("name")))
    return PolicyObjects(exclusions, net_rules + app_rules, set(CONSUMED), _firewall(sections, bare))
