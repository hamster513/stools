"""Поддельный DNS-сервер на 127.0.0.1 и поддельный LDAP с AD-integrated зоной.

Сервер — поток с UDP-сокетом на свободном порту: разбирает запрос `dns.message`, отвечает
записями из `records`, NXDOMAIN на прочие имена и молчит на имена из `silent` (таймаут).
Настоящие DNS-серверы и контроллеры домена тесты не трогают.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import socket
import struct
import threading
from typing import Any, Self

import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from api.modules.ad.core.ldap_collector import NO_SUCH_OBJECT, LdapResultError

TTL = 300


class FakeDnsServer:
    """`records[(имя, тип)] = [значения]`; имя без точки на конце, тип — 'A', 'AAAA', 'PTR'."""

    def __init__(self) -> None:
        self.records: dict[tuple[str, str], list[str]] = {}
        self.silent: set[str] = set()
        self.queries: list[tuple[str, str]] = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.port: int = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        self._thread.join(2)
        self.sock.close()

    def add(self, name: str, rtype: str, *values: str) -> None:
        self.records[(name.lower().rstrip("."), rtype)] = list(values)

    def ptr(self, ip: str, name: str) -> None:
        self.add(ipaddress.ip_address(ip).reverse_pointer, "PTR", name)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except (TimeoutError, OSError):
                continue
            query = dns.message.from_wire(data)
            question = query.question[0]
            name = question.name.to_text(omit_final_dot=True).lower()
            rtype = dns.rdatatype.to_text(question.rdtype)
            self.queries.append((name, rtype))
            if name in self.silent:
                continue
            response = dns.message.make_response(query)
            values = self.records.get((name, rtype))
            if values:
                if rtype == "PTR":
                    values = [v.rstrip(".") + "." for v in values]
                response.answer.append(dns.rrset.from_text_list(question.name, TTL, dns.rdataclass.IN, question.rdtype, values))
            elif not any(n == name for n, _ in self.records):
                response.set_rcode(dns.rcode.NXDOMAIN)
            self.sock.sendto(response.to_wire(), addr)


# ---- dnsRecord (DNS_RPC_RECORD) -------------------------------------------

_EPOCH_1601 = dt.datetime(1601, 1, 1, tzinfo=dt.UTC)


def hours_since_1601(when: dt.datetime) -> int:
    return int((when - _EPOCH_1601).total_seconds() // 3600)


def dns_record(rtype: int, data: bytes, *, ttl: int = TTL, stamp: dt.datetime | None = None) -> bytes:
    """Заголовок DNS_RPC_RECORD: длина, тип, версия 5, ранг, флаги, серийный номер (LE);
    TTL — big-endian; резерв и штамп (часы с 1601-01-01, 0 — статическая запись) — LE."""
    hours = hours_since_1601(stamp) if stamp else 0
    return (
        struct.pack("<HHBBHI", len(data), rtype, 5, 240, 0, 1)
        + struct.pack(">I", ttl)
        + struct.pack("<II", 0, hours)
        + data
    )


def a_record(ip: str, **kw: Any) -> bytes:
    addr = ipaddress.ip_address(ip)
    return dns_record(1 if addr.version == 4 else 28, addr.packed, **kw)


def cname_record(target: str, **kw: Any) -> bytes:
    labels = [label.encode() for label in target.split(".")]
    body = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
    return dns_record(5, bytes([len(body), len(labels)]) + body, **kw)


# ---- AD-integrated зона ---------------------------------------------------


class FakeZoneLdap:
    """Searcher сборщика AD (`search(base, filter, attrs, scope)`) с объектами `dnsNode`.

    `zones[зона] = {имя узла: [байты dnsRecord]}`; узел из `tombstoned` помечен `dNSTombstoned`.
    Зоны нет — noSuchObject (32), как у контроллера; зона из `failing` — ошибка «занят» (51)."""

    def __init__(self, domain_dn: str = "DC=corp,DC=local") -> None:
        self.domain_dn = domain_dn
        self.zones: dict[str, dict[str, list[bytes]]] = {}
        self.tombstoned: set[str] = set()
        self.failing: set[str] = set()
        self.calls: list[tuple[str, str, list[str], str]] = []

    def base(self, zone: str) -> str:
        return f"DC={zone},CN=MicrosoftDNS,DC=DomainDnsZones,{self.domain_dn}"

    def search(self, base: str, flt: str, attrs: list[str], scope: str) -> list[dict[str, Any]]:
        self.calls.append((base, flt, attrs, scope))
        for zone in self.failing:
            if base.lower() == self.base(zone).lower():
                raise LdapResultError(51, "busy", flt)
        for zone, nodes in self.zones.items():
            if base.lower() == self.base(zone).lower():
                if flt != "(objectClass=dnsNode)":
                    return []
                return [
                    {
                        "dn": f"DC={name},{base}",
                        "attributes": {"name": name, "dNSTombstoned": name in self.tombstoned},
                        "raw_attributes": {"dnsRecord": list(records)},
                    }
                    for name, records in nodes.items()
                ]
        raise LdapResultError(NO_SUCH_OBJECT, "noSuchObject", flt)


class FakeAdConnection:
    """То, что `ldap3_connection` отдаёт сборщику: rootDSE с defaultNamingContext и unbind."""

    def __init__(self, domain_dn: str = "DC=corp,DC=local") -> None:
        info = type("Info", (), {"other": {"defaultNamingContext": [domain_dn]}})()
        self.server = type("Server", (), {"info": info})()
        self.unbound = False

    def unbind(self) -> None:
        self.unbound = True
