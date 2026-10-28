"""Записи политики, которые нужны отдельно от дерева настроек: исключения и сетевые правила.

Извлекатель по продукту (`EXTRACTORS`, код `KLPOL_PRODUCT`) получает секции политики или профиля
и возвращает записи. Реестр заполняет пакет `core/extractors` при импорте модуля `api.modules.ksc` (сейчас — KES
для Windows); для продукта без извлекателя записи не строятся — он «не описан». Ключи записей не включают политику
и профиль — по ним ищутся дубли.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

log = logging.getLogger(__name__)

#: Виды исключений, которые сравниваются как пути: каталог или маска покрывает файл.
PATH_KINDS = {"path", "mask"}
#: Префикс компонента исключения с путём или хешем и именем объекта: «объект: <маска>» (ставит извлекатель KES).
OBJECT = "объект: "


@dataclass(frozen=True)
class Exclusion:
    kind: str
    value: str
    components: tuple[str, ...] = ()
    enabled: bool = True
    comment: str = ""
    #: Имя профиля; "" — сама политика.
    profile: str = ""


@dataclass(frozen=True)
class Address:
    """Один адрес правила: имя узла, адрес с маской или адреса, в которые разрешено имя; заполнена одна из форм."""
    #: Имя узла (`hostName`).
    host: str = ""
    #: Канонический адрес (`ipaddress`); "" — адреса нет.
    ip: str = ""
    #: Длина маски; только int, не bool.
    mask: int | None = None
    #: Адреса, в которые разрешено имя (`hostNameIPs`), по одному в порядке выгрузки: у каждого заполнен `ip` или `hidden`.
    ips: tuple[Address, ...] = ()
    #: "secret" — адрес скрыт сборщиком до 1.3; "unparsed" — `octets` не разобран; "" — адрес разобран.
    hidden: str = ""


@dataclass(frozen=True)
class Scope:
    """Адреса правила в виде, пригодном для проверки пакета (рядом с текстом `NetRule.addresses`)."""
    #: Код зоны 0/1/2 как в выгрузке; None — зоны нет.
    networks: int | None = None
    remote: tuple[Address, ...] = ()
    local: tuple[Address, ...] = ()
    #: Вид ICMP-сообщения; только у протоколов ICMP и ICMPv6.
    icmp_type: int | None = None


@dataclass(frozen=True)
class NetRule:
    layer: str
    position: int
    name: str
    action: str
    direction: str = ""
    protocol: str = ""
    local_ports: str = ""
    remote_ports: str = ""
    addresses: str = ""
    enabled: bool = True
    #: Имя профиля; "" — сама политика.
    profile: str = ""
    #: Адреса в виде структуры; в `net_rule_key` не входит.
    scope: Scope = Scope()


@dataclass(frozen=True)
class NetworkZone:
    """Зона сети (`firewall.availableNetworks`)."""
    name: str
    #: Код вида зоны (`type`) как в выгрузке; None — не int.
    kind: int | None
    #: Адрес с маской из `address`.
    address: Address


@dataclass(frozen=True)
class AccessRule:
    """Правило доступа группы доверия к сети (`networkAccessRules[]`); None — значение неверного типа."""
    #: Код сети как в выгрузке (-1, 0, 1, 2); только int, не bool.
    networks: int | None
    allow: bool | None
    inherited: bool | None


@dataclass(frozen=True)
class AppGroupDefault:
    """Группа доверия (`hips.appGroups`) без программ: место в дереве и правила доступа к сети."""
    name: str
    #: `parent` как в выгрузке; None — не int.
    parent: int | None
    #: 0 — верхний уровень; вложенность по `parent`, если её удаётся восстановить, иначе 0.
    depth: int
    #: Все правила `networkAccessRules` группы в порядке выгрузки.
    access: tuple[AccessRule, ...]


@dataclass(frozen=True)
class Locks:
    """Замки листов секции HIPS (`KLPRSS_Mnd`); None — листа или признака замка нет."""
    #: `firewall.networkPacketRules`.
    packet: bool | None
    #: `firewall.availableNetworks`.
    networks: bool | None
    #: `hips.appGroups`.
    app: bool | None


@dataclass(frozen=True)
class FirewallSettings:
    """Состояние сетевого экрана и HIPS, зоны сетей, группы доверия и замки листов политики или профиля."""
    enabled: bool | None
    notify_only: bool | None
    hips_enabled: bool | None
    hips_notify_only: bool | None
    zones: tuple[NetworkZone, ...]
    app_groups: tuple[AppGroupDefault, ...]
    locks: Locks


def firewall_to_json(fw: FirewallSettings) -> dict[str, Any]:
    """Словарь для колонок `*_json`."""
    return asdict(fw)


@dataclass
class PolicyObjects:
    exclusions: list[Exclusion] = field(default_factory=list)
    net_rules: list[NetRule] = field(default_factory=list)
    #: (секция, путь) настроек, из которых получены записи: журнал изменений их как `setting` не считает.
    consumed: set[tuple[str, str]] = field(default_factory=set)
    #: Сетевой экран и HIPS; None — секции HIPS в политике или профиле нет. У результата `policy_index.policy_objects`
    #: всегда None — там данные в `firewall_by_profile`.
    firewall: FirewallSettings | None = None
    #: Заполняет `policy_index.policy_objects`: профиль ("" — сама политика) → `firewall` его секций, без тех, где он None.
    firewall_by_profile: dict[str, FirewallSettings] = field(default_factory=dict)


#: Секции политики или профиля → записи.
Extractor = Callable[[dict[str, Any]], PolicyObjects]
#: Код продукта (KLPOL_PRODUCT) → извлекатель; заполняет пакет `core/extractors`.
EXTRACTORS: dict[str, Extractor] = {}


def extract(product: str, sections: dict[str, Any]) -> PolicyObjects | None:
    """Записи из секций; None — для продукта нет извлекателя (продукт не описан). Сбой извлекателя импорт снапшота не
    роняет: в журнал приложения, записей нет, продукт по-прежнему описан."""
    extractor = EXTRACTORS.get(product)
    if extractor is None:
        return None
    try:
        return extractor(sections)
    except Exception:
        log.exception("извлекатель записей продукта %s упал — записей нет", product)
        return PolicyObjects()


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def exclusion_key(e: Exclusion) -> str:
    return _digest(f"{e.kind}|{e.value.strip().lower()}")


def scope_to_json(scope: Scope) -> str:
    return json.dumps(asdict(scope), ensure_ascii=False)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _address_from_dict(item: Any) -> Address:
    if not isinstance(item, dict):
        raise TypeError("адрес не объект")
    host, ip, hidden, mask, ips = item.get("host", ""), item.get("ip", ""), item.get("hidden", ""), item.get("mask"), item.get("ips", [])
    if not all(isinstance(v, str) for v in (host, ip, hidden)) or not (mask is None or _is_int(mask)):
        raise TypeError("поле адреса неверного типа")
    return Address(host=host, ip=ip, mask=mask, ips=_addresses_from_list(ips), hidden=hidden)


def _addresses_from_list(value: Any) -> tuple[Address, ...]:
    if not isinstance(value, list):
        raise TypeError("адреса не список")
    return tuple(_address_from_dict(item) for item in value)


def scope_from_json(text: str | None) -> Scope | None:
    """Структура адресов из JSON `scope_to_json`; None — текста нет, он не JSON или форма не та (не бросает)."""
    if not text:
        return None
    try:
        data = json.loads(text)
        if not isinstance(data, dict):
            return None
        networks, icmp_type = data.get("networks"), data.get("icmp_type")
        if not all(v is None or _is_int(v) for v in (networks, icmp_type)):
            return None
        return Scope(networks=networks, remote=_addresses_from_list(data.get("remote", [])),
                     local=_addresses_from_list(data.get("local", [])), icmp_type=icmp_type)
    except (TypeError, ValueError, RecursionError):  # ValueError — битый JSON, RecursionError — слишком глубокая вложенность
        return None


def net_rule_key(r: NetRule) -> str:
    return _digest(f"{r.layer}|{r.name}|{r.direction}|{r.protocol}|{r.local_ports}|{r.remote_ports}|{r.addresses}".lower())


def _wider(other: str, value: str) -> bool:
    """`other` — каталог-префикс `value` (граница по разделителю) или маска, под которую `value` подходит.
    Замыкающие разделители не в счёт: `C:\\Tools\\` и `C:\\Tools` — один каталог, шире он не бывает."""
    prefix, bare = other.rstrip("\\/"), value.rstrip("\\/")
    if prefix and len(bare) > len(prefix) and bare.startswith(prefix) and bare[len(prefix)] in "\\/":
        return True
    return ("*" in other or "?" in other) and fnmatch.fnmatchcase(value, other)


def restricted(e: Exclusion) -> bool:
    """Исключение сужено именем объекта (`объект: <маска>`, кроме `*`): касается одной угрозы в этом пути."""
    return any(c.startswith(OBJECT) and c[len(OBJECT):].strip() != "*" for c in e.components)


def covered_by(e: Exclusion, others: Iterable[Exclusion]) -> Exclusion | None:
    """Первое другое включённое исключение-путь или маска, которое шире `e`; равные значения перекрытием не считаются,
    исключение, суженное именем объекта (`restricted`), не перекрывает другие."""
    if e.kind not in PATH_KINDS:
        return None
    value = e.value.strip().lower()
    for o in others:
        if o is e or not o.enabled or o.kind not in PATH_KINDS or restricted(o):
            continue
        other = o.value.strip().lower()
        if other != value and _wider(other, value):
            return o
    return None
