"""Извлекатель KES для Windows (`KLPOL_PRODUCT` = `KES`): исключения, доверенные программы и сетевые правила.

Секции читаются в «голом» виде (`bare_sections`): уровень контейнеров `KLPRSS_Val` в выгрузке не важен. Элемент списка
неожиданной формы (не словарь, нет нужного ключа) пропускается. Коды перечислений — только подтверждённые калибровкой,
неизвестный код показывается «код N».
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
from typing import Any

from api.modules.ksc.core.policy_contents import bare_sections, truncate_value
from api.modules.ksc.core.policy_model import Exclusion, NetRule, PolicyObjects
from api.modules.ksc.core.secrets import HIDDEN

TRUSTED_ZONE = "852d0287"
HIPS = "cf9370d5"
_ZONE = "scanExclusionsAndTrustedZone"

#: Листья (`flat_settings`), из которых получены записи: журнал изменений не считает их настройками.
CONSUMED = frozenset({
    (TRUSTED_ZONE, f"{_ZONE}.scanExclusions"),
    (TRUSTED_ZONE, f"{_ZONE}.scanExclusions_merging_crutch"),
    (TRUSTED_ZONE, f"{_ZONE}.trustedApplications"),
    (TRUSTED_ZONE, f"{_ZONE}.trustedApplications_merging_crutch"),
    (HIPS, "firewall.networkPacketRules"),
    (HIPS, "hips.appGroups"),
})

#: Флаги доверенной программы → подпись; `excludeNet` — вложенный словарь, разбирается отдельно (на своём месте в порядке).
_TRUSTED_FLAGS = (
    ("excludeOpenFiles", "не проверять открываемые файлы"),
    ("excludeBehavior", "не контролировать активность"),
    ("excludeChildsBehavior", "не контролировать дочерние процессы"),
    ("excludeChildsBehaviorRecursive", "не контролировать дочерние процессы рекурсивно"),
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
        components.append(f"объект: {name}")
    if mask.get("recursive") is True:
        components.append("рекурсивно")
    return Exclusion(kind, value, tuple(components), bool(item.get("enabled", True)), _text(item.get("comment")))


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
                components.append("не проверять сетевой трафик (только зашифрованный)" if only_encrypted else "не проверять сетевой трафик")
        elif item.get(key) is True:
            components.append(label)
    return Exclusion("trusted_app", path, tuple(components), bool(item.get("enabled", True)), _text(item.get("comment")))


def _ports(value: Any) -> str:
    out = []
    for p in _items(value):
        begin, end = p.get("begin"), p.get("end")
        if isinstance(begin, int) and isinstance(end, int):
            out.append(str(begin) if begin == end else f"{begin}-{end}")
    return ", ".join(out)


def _ip(octets: Any, mask: Any = None) -> str:
    if octets == HIDDEN:
        return "адрес скрыт (сборщик до 1.3)"
    try:
        packed = base64.b64decode(octets, validate=True) if isinstance(octets, str) else b""
    except binascii.Error:
        packed = b""
    if len(packed) not in (4, 16):
        return "адрес не разобран"
    address = str(ipaddress.ip_address(packed))
    return f"{address}/{mask}" if isinstance(mask, int) and not isinstance(mask, bool) else address


def _address(item: dict[str, Any]) -> str:
    """Имя узла, иначе адрес из `octets` с маской, иначе адреса, в которые разрешено имя (`hostNameIPs`)."""
    if host := _text(item.get("hostName")):
        return host
    if "octets" in item:
        return _ip(item["octets"], item.get("mask"))
    return ", ".join(_ip(ip.get("octets")) for ip in _items(item.get("hostNameIPs")))


def _addresses(scope: dict[str, Any]) -> str:
    parts = [_code(_NETWORKS, scope["networks"])] if "networks" in scope else []
    parts += [a for a in map(_address, _items(scope.get("remoteAddresses"))) if a]
    parts += [f"локальный: {a}" for a in map(_address, _items(scope.get("localAddresses"))) if a]
    return "; ".join(parts)


def _protocol(proto: dict[str, Any]) -> str:
    if "unique_id" not in proto:
        return "любой"
    label = _code(_PROTOCOLS, proto["unique_id"])
    kind = _dict(proto.get("type")).get("value")
    return f"{label} (вид {kind})" if isinstance(kind, int) and not isinstance(kind, bool) else label


def _net_rule(item: dict[str, Any], layer: str, position: int, owner: str = "") -> NetRule | None:
    name = item.get("name")
    if not isinstance(name, str) or "action" not in item:
        return None
    proto, scope = _dict(item.get("protocol")), _dict(item.get("scope"))
    return NetRule(
        layer=layer, position=position, name=f"{owner}: {name}" if owner else name, action=_code(_ACTIONS, item["action"]),
        direction=_code(_DIRECTIONS, item.get("packetDirection")), protocol=_protocol(proto), local_ports=_ports(proto.get("localPorts")),
        remote_ports=_ports(proto.get("remotePorts")), addresses=_addresses(scope), enabled=bool(item.get("enabled", True)),
    )


def _rules(items: list[dict[str, Any]], layer: str, start: int, owner: str = "") -> list[NetRule]:
    out: list[NetRule] = []
    for item in items:
        rule = _net_rule(item, layer, start + len(out), owner)
        if rule is not None:
            out.append(rule)
    return out


def extract_kes(sections: dict[str, Any]) -> PolicyObjects:
    """Записи политики или профиля KES для Windows: исключения (`scanExclusions`), доверенные программы
    (`trustedApplications`), пакетные правила сетевого экрана (слой `packet`) и правила групп доверия и программ (слой `app`)."""
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
    return PolicyObjects(exclusions, net_rules + app_rules, set(CONSUMED))
