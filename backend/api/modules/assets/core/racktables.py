"""JSON API RackTables (`json_api.php`): вызов методов и разбор ответов, без базы.

API заказчика: POST с JSON-телом, метод в поле `func`, HTTP Basic; успех — 200 и JSON, ошибка —
400 и текст. Сети — `listCells` realm `ipv4net`, адреса диапазона — `getIPAddressList`;
привязок адресов к объектам API не отдаёт, поэтому источник — имена адресов (спека 2026-10-13).
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Self

import httpx

from api.modules.assets.core.matching import normalize_ip

#: Шире — не сеть, а контейнер; модуль сетей принимает IPv4 не шире /16.
MAX_PREFIX = 16
#: Версия API — короткая строка вида 1.3.3; всё прочее в ответ пользователю не уходит.
VERSION_RE = re.compile(r"^[\w.\-]{1,32}$")


class RtError(Exception):
    """Ошибка API или ответ не того вида."""


@dataclass(slots=True)
class RtNetwork:
    rt_id: str
    cidr: str
    name: str = ""
    comment: str = ""
    vlan: int | None = None
    #: Явные теги сети (`etags`) и унаследованные (`itags`: предки тегов и теги объемлющих сетей).
    explicit_tags: list[str] = field(default_factory=list)
    implicit_tags: list[str] = field(default_factory=list)
    #: Есть дочерние сети (иерархия RT; в Assets пока не переносится).
    children: bool = False

    @property
    def too_wide(self) -> bool:
        net = ipaddress.ip_network(self.cidr)
        return net.version == 4 and net.prefixlen < MAX_PREFIX

    @property
    def external(self) -> bool:
        """Публичные адреса: не RFC1918, не 100.64/10, не link-local и не служебные."""
        return ipaddress.ip_network(self.cidr).is_global


@dataclass(slots=True)
class RtAddress:
    ip: str
    name: str
    comment: str = ""
    reserved: bool = False


class Client:
    """`before` — пауза темпа перед каждым запросом (дозатор задачи)."""

    def __init__(
        self, url: str, username: str, password: str, *, verify: bool = True, timeout: float = 30.0,
        before: Callable[[], None] | None = None,
    ) -> None:
        self.url = url
        self.before = before
        # Без переходов по redirect: учётные данные уходят только на заданный адрес.
        self._http = httpx.Client(
            auth=(username, password), verify=verify, timeout=timeout, follow_redirects=False, headers={"Content-Type": "application/json"},
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def call(self, func: str, **args: Any) -> Any:
        if self.before is not None:
            self.before()
        try:
            r = self._http.post(self.url, content=json.dumps({"func": func, **args}))
        except httpx.HTTPError as exc:
            raise RtError(f"{func}: {type(exc).__name__}: {exc}") from None
        if r.status_code == 401:
            raise RtError("RackTables не принял учётные данные (401)")
        if r.status_code == 400:
            # Штатный канал ошибок API — текст причины; тела прочих ответов пользователю не показываются.
            raise RtError(f"{func}: {' '.join(r.text.split())[:200] or 'ошибка API'}")
        if r.status_code != 200:
            raise RtError(f"{func}: HTTP {r.status_code}")
        try:
            return r.json()
        except ValueError:
            # Версия API приходит и голой строкой; списки без JSON отвергнет разбор.
            return r.text.strip()

    def version(self) -> str:
        data = self.call("getAPIVersion")
        if isinstance(data, dict):
            data = data.get("version") or data.get("api_version") or next(iter(data.values()), "")
        version = str(data).strip()
        if not VERSION_RE.match(version):
            raise RtError("getAPIVersion: ответ не похож на версию API")
        return version

    def networks(self) -> list[RtNetwork]:
        return parse_networks(self.call("listCells", realm="ipv4net"))

    def addresses(self, network: RtNetwork) -> list[RtAddress]:
        first, last = address_range(network.cidr)
        return parse_addresses(self.call("getIPAddressList", ipStart=first, ipEnd=last))


def _items(data: Any) -> list[dict[str, Any]]:
    """listCells отдаёт словарь id → ячейка, списки адресов — список."""
    if isinstance(data, dict):
        return [v for v in data.values() if isinstance(v, dict)]
    if isinstance(data, list):
        return [v for v in data if isinstance(v, dict)]
    raise RtError("ответ не список и не словарь")


def _tag_names(value: Any) -> list[str]:
    """Имена тегов из `etags`/`itags`: словарь id тега → {id, tag, …} (как отдаёт `listCells`; пустой —
    `[]`) или список строк/словарей. Без дублей и пустых. `atags` — служебные ($typeid_…), не переносятся."""
    if isinstance(value, dict):
        # В словаре значение — описание тега; строка там не имя, а мусор.
        items = [v for v in value.values() if isinstance(v, dict)]
    elif isinstance(value, list):
        items = value
    else:
        return []
    out: list[str] = []
    for t in items:
        name = t.get("tag") if isinstance(t, dict) else t
        if isinstance(name, str) and name.strip():
            out.append(name.strip())
    return list(dict.fromkeys(out))


def _vlan(cell: dict[str, Any]) -> int | None:
    for binding in cell.get("8021q") or []:
        raw = binding.get("vlan_id") if isinstance(binding, dict) else binding
        try:
            return int(str(raw))
        except (TypeError, ValueError):
            continue
    return None


def parse_networks(data: Any) -> list[RtNetwork]:
    """Сети из `listCells(ipv4net)`; ячейки без разборного адреса пропускаются."""
    out = []
    for cell in _items(data):
        try:
            net = ipaddress.ip_network(f"{cell.get('ip')}/{cell.get('mask')}", strict=False)
        except (TypeError, ValueError):
            continue
        out.append(RtNetwork(
            rt_id=str(cell.get("id") or ""), cidr=str(net), name=str(cell.get("name") or "").strip(),
            comment=str(cell.get("comment") or "").strip(), vlan=_vlan(cell),
            explicit_tags=_tag_names(cell.get("etags")), implicit_tags=_tag_names(cell.get("itags")), children=bool(cell.get("kidc")),
        ))
    return out


def parse_addresses(data: Any) -> list[RtAddress]:
    """Адреса из `getIPAddressList`; адрес без имени — пустое значение, не переносится (решение владельца)."""
    out = []
    for cell in _items(data):
        ip = normalize_ip(str(cell.get("ip_address") or cell.get("ip") or ""))
        name = str(cell.get("name") or "").strip()
        if not ip or not name:
            continue
        out.append(RtAddress(
            ip=ip, name=name, comment=str(cell.get("comment") or "").strip(),
            reserved=str(cell.get("is_reserved") or cell.get("reserved") or "").lower() == "yes",
        ))
    return out


def address_range(cidr: str) -> tuple[str, str]:
    net = ipaddress.ip_network(cidr)
    return str(net.network_address), str(net.broadcast_address)


def narrowest(networks: Iterable[RtNetwork]) -> list[RtNetwork]:
    """Сети от узких к широким: адрес, встреченный раньше, относится к самой узкой сети."""
    return sorted(networks, key=lambda n: (-ipaddress.ip_network(n.cidr).prefixlen, n.cidr))
