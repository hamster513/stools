"""Explicit, non-cascading value replacements; no database access or implicit PII guesses."""

from __future__ import annotations

import base64
import ipaddress
import json
import re
from pathlib import Path
from xml.dom import Node, minidom
from xml.parsers.expat import ExpatError


class MaskError(Exception):
    """Default messages are safe to log. Only parsed IPs have opt-in details."""

    def __init__(self, message, *, ip_details=None):
        super().__init__(message)
        self.context = []
        self.path = []
        self.ip_details = ip_details

    def __str__(self):
        parts = [super().__str__(), *reversed(self.context)]
        if self.path:
            parts.append("Путь в значении: $" + "".join(reversed(self.path)))
        return "\n".join(parts)

    def render(self, show_ips=False):
        if self.ip_details is None:
            return str(self)
        detail = (
            self.ip_details
            if show_ips
            else "Чтобы увидеть IP и подсети локально, добавьте --show-conflicting-ips."
        )
        return f"{self}\n{detail}"


class Number(str):
    """Keep the original JSON numeric literal, including decimal precision."""


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise MaskError(
                "JSON содержит повторяющиеся ключи; молчаливое удаление значений запрещено."
            )
        result[key] = value
    return result


def loads(value):
    try:
        return json.loads(
            value,
            object_pairs_hook=pairs,
            parse_int=Number,
            parse_float=Number,
            parse_constant=lambda _: (_ for _ in ()).throw(
                MaskError("Некорректное число JSON.")
            ),
        )
    except (ValueError, RecursionError):
        raise MaskError(
            "Не удалось разобрать структурированное значение JSON."
        ) from None


def dumps(value):
    if isinstance(value, Number):
        return str(value)
    if isinstance(value, dict):
        return (
            "{"
            + ",".join(
                json.dumps(k, ensure_ascii=False) + ":" + dumps(v)
                for k, v in value.items()
            )
            + "}"
        )
    if isinstance(value, list):
        return "[" + ",".join(dumps(v) for v in value) + "]"
    return json.dumps(value, ensure_ascii=False, allow_nan=False)


IP4 = r"(?:\d{1,3}\.){3}\d{1,3}"
IP6 = r"(?:[0-9a-fA-F]*:){2,}[0-9a-fA-F:.]*"
ADDRESS = (
    r"(?<![\w.:])(?:"
    + IP4
    + r"(?:/\d{1,3})?(?![\w.])|"
    + IP6
    + r"(?:/\d{1,3})?(?![\w.:]))"
)
RANGE = re.compile(r"(?<![\w.])(" + IP4 + r")\s*[-–]\s*(" + IP4 + r")(?![\w.])")
TECHNICAL = re.compile(r"version|build|cvss|cve|cpe|package_version", re.IGNORECASE)
CONTROL = re.compile(
    r"^(?:action|protocol|direction|mode|status|severity|operator|rule_type|package_type|version|build)$",
    re.IGNORECASE,
)
STRUCTURAL = {
    "enabled",
    "action",
    "protocol",
    "direction",
    "mode",
    "status",
    "type",
    "kind",
    "version",
    "port",
    "ports",
    "operator",
    "value",
    "values",
    "name",
    "id",
    "rules",
    "settings",
    "children",
}
# Arbitrary object keys can themselves be logins, hostnames or tokens.
DIAGNOSTIC_FIELDS = STRUCTURAL | {
    "address",
    "addresses",
    "ip",
    "ips",
    "host",
    "hosts",
    "fqdn",
    "url",
    "local",
    "remote",
    "local_address",
    "remote_address",
    "networks",
    "octets",
    "payload",
    "data",
    "items",
    "entries",
    "interfaces",
    "from",
    "to",
}
SECRET = re.compile(
    r"^(?:.*[_.])?(?:password|passwd|password_hash|api_key|api_token|access_token|refresh_token|client_secret|"
    r"robot_secret|totp_secret|secret|token|token_encrypted|private_key|session_secret|authorization)$",
    re.IGNORECASE,
)


def load_config(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise MaskError("Конфиг должен быть обычным JSON-файлом размером до 8 МиБ.")
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)
    except json.JSONDecodeError as error:
        raise MaskError(
            f"Некорректный JSON конфига, строка {error.lineno}, столбец {error.colno}."
        ) from None
    except (ValueError, UnicodeError):
        raise MaskError("Конфиг должен содержать корректный UTF-8 JSON.") from None
    return Rules(data)


class Rules:
    def __init__(self, config):
        allowed = {"format", "replacements", "networks", "case_sensitive"}
        if (
            not isinstance(config, dict)
            or set(config) - allowed
            or config.get("format") != "stools-db-anonymize/1"
        ):
            raise MaskError("Некорректный формат конфига или неизвестные параметры.")
        self.case_sensitive = config.get("case_sensitive", True)
        if type(self.case_sensitive) is not bool:
            raise MaskError("case_sensitive должен быть true или false.")
        for field in ("replacements", "networks"):
            if not isinstance(config.get(field, []), list):
                raise MaskError("replacements и networks должны быть массивами JSON.")
        self.flags = 0 if self.case_sensitive else re.IGNORECASE
        self.replacements = []
        for index, row in enumerate(config.get("replacements", [])):
            if not isinstance(row, dict) or set(row) != {"from", "to"}:
                raise MaskError(
                    f"В replacements[{index}] должны быть только from и to."
                )
            a, b = row["from"], row["to"]
            if (
                not isinstance(a, str)
                or not isinstance(b, str)
                or not a
                or not b
                or any(ord(c) < 32 for c in a + b)
            ):
                raise MaskError(
                    f"В replacements[{index}] нужны непустые строки без управляющих символов."
                )
            self.replacements.append((a, b))
        fold = (lambda x: x) if self.case_sensitive else str.casefold
        for side, field in enumerate(("from", "to")):
            seen = {}
            for index, pair in enumerate(self.replacements):
                key = fold(pair[side])
                if key in seen:
                    raise MaskError(
                        f"Значения replacements[{seen[key]}].{field} и replacements[{index}].{field} совпадают. "
                        "Для каждой записи нужно уникальное значение."
                    )
                seen[key] = index
        for source_index, (source, _) in enumerate(self.replacements):
            for target_index, (_, dest) in enumerate(self.replacements):
                if re.search(re.escape(source), dest, self.flags):
                    raise MaskError(
                        f"Псевдоним replacements[{target_index}].to содержит исходное значение "
                        f"replacements[{source_index}].from. Выберите другой псевдоним."
                    )
        self.config_targets = [target for _, target in self.replacements]
        self.replacements.sort(key=lambda pair: len(pair[0]), reverse=True)
        self.networks = []
        for index, row in enumerate(config.get("networks", [])):
            try:
                if not isinstance(row, dict) or set(row) != {"from", "to"}:
                    raise ValueError
                if not isinstance(row["from"], str) or not isinstance(row["to"], str):
                    raise TypeError
                source = ipaddress.ip_network(row["from"], strict=True)
                target = ipaddress.ip_network(row["to"], strict=True)
                if (
                    source.version != target.version
                    or source.prefixlen != target.prefixlen
                    or source == target
                ):
                    raise ValueError
            except (ValueError, TypeError, KeyError):
                raise MaskError(
                    f"В networks[{index}] from и to должны быть разными подсетями одной версии и длины префикса."
                ) from None
            self.networks.append((source, target))
        for side, field in enumerate(("from", "to")):
            for i, pair in enumerate(self.networks):
                for j, other in enumerate(self.networks[:i]):
                    if pair[side].version == other[side].version and pair[
                        side
                    ].overlaps(other[side]):
                        raise MaskError(
                            f"Подсети networks[{j}].{field} и networks[{i}].{field} пересекаются."
                        )
        if not self.replacements and not self.networks:
            raise MaskError("Укажите хотя бы одну замену или одну пару подсетей.")
        literals = [re.escape(a) for a, _ in self.replacements]
        self.literal = re.compile("|".join(literals), self.flags) if literals else None
        self.pattern = re.compile("|".join(literals + [ADDRESS]), self.flags)
        self.destinations = (
            re.compile("|".join(re.escape(b) for _, b in self.replacements), self.flags)
            if literals
            else None
        )
        self.changed_values = 0

    def _literal(self, value):
        for source, target in self.replacements:
            if re.fullmatch(re.escape(source), value, self.flags):
                return target
        return None

    def _network_error(self, message, index, observed):
        # Numeric forms exclude arbitrary interface scope labels from diagnostics.
        source, target = (
            type(net)((int(net.network_address), net.prefixlen))
            for net in self.networks[index]
        )
        return MaskError(
            message,
            ip_details=f"Значение {observed}. Правило networks[{index}]: {source} → {target}.",
        )

    def _interval(self, low, high, interface=None):
        version = low.version
        a, b = int(low), int(high)
        for source, target in self.networks:
            if source.version != version:
                continue
            if low in source and high in source:
                offset = int(target.network_address) - int(source.network_address)
                return type(low)(int(low) + offset), type(high)(int(high) + offset)
        for index, (source, target) in enumerate(self.networks):
            if source.version != version:
                continue
            intersects = lambda net: (
                a <= int(net.broadcast_address) and b >= int(net.network_address)
            )
            contains = lambda net: (
                a <= int(net.network_address) and b >= int(net.broadcast_address)
            )
            if (intersects(source) or intersects(target)) and not (
                contains(source) and contains(target)
            ):
                side = "from" if intersects(source) else "to"
                raise self._network_error(
                    f"Диапазон или подсеть пересекает networks[{index}].{side}. "
                    "Сверьте границы диапазона с from и to: замена изменила бы охват адресов.",
                    index,
                    f"{interface.ip}/{interface.network.prefixlen}"
                    if interface is not None
                    else f"{low}–{high}",
                )
        return low, high

    def address(self, value):
        try:
            interface = ipaddress.ip_interface(value) if "/" in value else None
            address = interface.ip if interface else ipaddress.ip_address(value)
        except ValueError:
            return value
        if interface:
            low, _high = self._interval(
                interface.network.network_address,
                interface.network.broadcast_address,
                interface,
            )
            mapped = type(address)(
                int(low) + int(address) - int(interface.network.network_address)
            )
            return str(mapped) + "/" + str(interface.network.prefixlen)
        for source, target in self.networks:
            if address.version == source.version and address in source:
                return str(
                    type(address)(
                        int(target.network_address)
                        + int(address)
                        - int(source.network_address)
                    )
                )
        for index, (_, target) in enumerate(self.networks):
            if address.version == target.version and address in target:
                raise self._network_error(
                    f"Адрес из исходной базы уже входит в целевую подсеть networks[{index}].to "
                    "и не охвачен ни одной подсетью from. Выберите для to свободную подсеть "
                    "с той же длиной префикса, чтобы два объекта не получили один адрес.",
                    index,
                    type(address)(int(address)),
                )
        return value

    def text(self, value, addresses=True, *, advisory_prose=False):
        match = self.destinations.search(value) if self.destinations else None
        if match:
            index = next(
                i
                for i, target in enumerate(self.config_targets)
                if re.fullmatch(re.escape(target), match.group(), self.flags)
            )
            raise MaskError(
                f"Псевдоним из replacements[{index}].to уже встречается в исходных данных. Выберите уникальную замену."
            )
        if addresses:
            for item in RANGE.finditer(value):
                try:
                    lo, hi = (
                        ipaddress.ip_address(item[1]),
                        ipaddress.ip_address(item[2]),
                    )
                except ValueError:
                    continue
                if lo > hi:
                    continue
                # A public advisory can quote a broad range without naming a mapped address.
                if advisory_prose and all(
                    lo not in net and hi not in net
                    for pair in self.networks
                    for net in pair
                ):
                    continue
                self._interval(lo, hi)

        def replace(match):
            original = match.group()
            literal = self._literal(original)
            return literal if literal is not None else self.address(original)

        result = (
            self.pattern.sub(replace, value)
            if addresses
            else (
                self.literal.sub(lambda m: self._literal(m.group()), value)
                if self.literal
                else value
            )
        )
        if self.literal and self.literal.search(result):
            raise MaskError(
                "После замены осталось исходное значение; уточните пересекающиеся правила."
            )
        if result != value:
            self.changed_values += 1
        return result

    def walk(self, value, key="", secrets=False, *, advisory_prose=False):
        if isinstance(value, Number):
            return value
        if isinstance(value, str):
            if secrets and SECRET.fullmatch(key):
                return ""
            if value.startswith("enc:"):
                raise MaskError(
                    "Неизвестное зашифрованное содержимое: экспорт без расшифровки запрещён."
                )
            if CONTROL.fullmatch(key) or TECHNICAL.search(key):
                if self.literal and self.literal.search(value):
                    raise MaskError(
                        "Правило затрагивает техническое значение политики или версию ПО; уточните замену."
                    )
                return value
            stripped = value.lstrip()
            if stripped.startswith(("{", "[")):
                try:
                    parsed = loads(value)
                except MaskError:
                    pass
                else:
                    if isinstance(parsed, (dict, list)):
                        return dumps(self.walk(parsed, secrets=secrets))
            if stripped.startswith("<"):
                if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", value, re.IGNORECASE):
                    raise MaskError("XML с DTD/ENTITY не поддерживается.")
                try:
                    minidom.parseString(value)
                except (ExpatError, ValueError):
                    pass
                else:
                    return self.xml(value, secrets=secrets)
            return self.text(value, advisory_prose=advisory_prose)
        if isinstance(value, list):
            result = []
            for index, item in enumerate(value):
                try:
                    result.append(self.walk(item, key, secrets))
                except MaskError as error:
                    error.path.append(f"[{index}]")
                    raise
            return result
        if isinstance(value, dict):
            if set(value) == {"type", "value"} and value["type"] == "binary":
                if secrets and SECRET.fullmatch(key):
                    return {"type": "binary", "value": ""}
                if key.casefold() != "octets":
                    raise MaskError(
                        "Непрозрачное binary-значение KSC требует отдельного обработчика; экспорт остановлен."
                    )
                try:
                    address = ipaddress.ip_address(
                        base64.b64decode(value["value"], validate=True)
                    )
                except (ValueError, TypeError):
                    raise MaskError("Некорректный двоичный адрес KSC.") from None
                try:
                    mapped = ipaddress.ip_address(self.address(str(address)))
                except MaskError as error:
                    error.path.append(".value")
                    raise
                self.changed_values += address != mapped
                return {
                    "type": "binary",
                    "value": base64.b64encode(mapped.packed).decode("ascii"),
                }
            if set(value) == {"type", "value"} and value["type"] in (
                "string",
                "wstring",
                "params",
                "long",
                "int",
                "int64",
                "bool",
                "boolean",
                "datetime",
                "date",
            ):
                try:
                    return {
                        "type": value["type"],
                        "value": self.walk(value["value"], key, secrets),
                    }
                except MaskError as error:
                    error.path.append(".value")
                    raise
            result = {}
            for number, (field, item) in enumerate(value.items(), 1):
                try:
                    new_key = self.text(field)
                    if field.lower() in STRUCTURAL and field != new_key:
                        raise MaskError(
                            "Правило меняет структурный ключ JSON; уточните замену."
                        )
                    if new_key in result:
                        raise MaskError("Замена создаёт повторяющиеся ключи JSON.")
                    result[new_key] = self.walk(item, field, secrets)
                except MaskError as error:
                    error.path.append(
                        "." + field if field in DIAGNOSTIC_FIELDS else f"[#{number}]"
                    )
                    raise
            return result
        return value

    def json(self, value, secrets=False):
        return dumps(self.walk(loads(value), secrets=secrets))

    def xml(self, value, secrets=False):
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", value, re.IGNORECASE):
            raise MaskError(
                "XML с DTD/ENTITY не поддерживается; внешние сущности запрещены."
            )
        try:
            document = minidom.parseString(value)
        except (ExpatError, ValueError):
            raise MaskError("Не удалось разобрать XML.") from None

        def visit(node, key=""):
            if node.nodeType == Node.ELEMENT_NODE:
                key = node.tagName
                for name in list(node.attributes.keys()):
                    original = node.getAttribute(name)
                    if name == "xmlns" or name.startswith("xmlns:"):
                        if self.literal and self.literal.search(original):
                            raise MaskError(
                                "Правило затрагивает пространство имён XML; это может изменить смысл политики."
                            )
                    else:
                        node.setAttribute(name, self.walk(original, name, secrets))
            if node.nodeType in (
                Node.TEXT_NODE,
                Node.CDATA_SECTION_NODE,
                Node.COMMENT_NODE,
            ):
                node.data = self.walk(node.data, key, secrets)
            for child in list(node.childNodes):
                visit(child, key)

        visit(document)
        return document.toxml()

    def array(self, value, element):
        supported = {
            "text",
            "varchar",
            "bpchar",
            "name",
            "citext",
            "json",
            "jsonb",
            "xml",
            "bool",
            "int2",
            "int4",
            "int8",
            "oid",
            "numeric",
            "float4",
            "float8",
            "date",
            "time",
            "timetz",
            "timestamp",
            "timestamptz",
            "interval",
            "uuid",
            "inet",
            "cidr",
            "macaddr",
            "macaddr8",
            "tsvector",
            "tsquery",
        }
        if element not in supported:
            raise MaskError(
                "Неподдерживаемый тип элемента ARRAY; непрозрачные данные не экспортируются."
            )
        record = loads(value)
        dims = record["dims"] or ""
        if dims and not re.fullmatch(r"(?:\[-?\d+:-?\d+\])+", dims):
            raise MaskError("Некорректная размерность PostgreSQL ARRAY.")
        depth = dims.count("[") or 1

        def encode(item, level):
            if level:
                if not isinstance(item, list):
                    raise MaskError("Некорректная вложенность PostgreSQL ARRAY.")
                items = []
                for offset, child in enumerate(item):
                    try:
                        items.append(encode(child, level - 1))
                    except MaskError as error:
                        bounds = re.findall(r"\[(-?\d+):", dims)
                        lower = int(bounds[depth - level]) if bounds else 1
                        error.path.append(f"[{lower + offset}]")
                        raise
                return "{" + ",".join(items) + "}"
            if item is None:
                return "NULL"
            transformed = self.walk(item, secrets=True)
            text = (
                dumps(transformed)
                if element in ("json", "jsonb") or not isinstance(transformed, str)
                else str(transformed)
            )
            return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'

        return (dims + "=" if dims else "") + encode(record["values"], depth)
