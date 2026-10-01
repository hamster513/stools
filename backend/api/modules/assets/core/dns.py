"""DNS для Assets (спека §4): A/AAAA и PTR через dnspython, разбор `dnsRecord` AD-integrated зон.

Без базы. Запрос к указанному серверу или к системному резолверу (`Resolver()` читает
resolv.conf); без рекурсивного перебора и переноса зоны. «Имени нет» (NXDOMAIN, пустой ответ)
отличается от «сервер не ответил» (`DnsError`): первое снимает наблюдение, второе — нет.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import socket
import struct
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Any

import dns.exception
import dns.name
import dns.resolver
import dns.reversename

from api.modules.ad.core.ldap_collector import NO_SUCH_OBJECT, LdapResultError, Searcher

#: Порт DNS-сервера; тесты ставят порт поддельного сервера на 127.0.0.1.
PORT = 53

TYPE_A, TYPE_CNAME, TYPE_AAAA = 1, 5, 28
TYPE_NAMES = {TYPE_A: "A", TYPE_CNAME: "CNAME", TYPE_AAAA: "AAAA"}

#: Заголовок DNS_RPC_RECORD до данных: wDataLength, wType, bVersion, bRank, wFlags, dwSerial (LE),
#: dwTtlSeconds (BE), dwReserved, dwTimeStamp (LE; часы с 1601-01-01, 0 — статическая запись).
_HEADER = struct.Struct("<HHBBHI")
_HEADER_SIZE = 24
_EPOCH_1601 = dt.datetime(1601, 1, 1, tzinfo=dt.UTC)


class DnsError(Exception):
    """Сервер не дал ответа по существу (SERVFAIL, REFUSED, нет серверов) — про имя ничего не известно."""


class DnsTimeout(DnsError):
    """Сервер не ответил за таймаут."""


@dataclass(slots=True)
class Answer:
    values: list[str]
    ttl: int | None
    #: A, AAAA или PTR — что дал ответ; пусто, если ответа нет.
    record_type: str


@dataclass(slots=True)
class DnsRecord:
    type: int
    value: str
    ttl: int
    #: Штамп обновления динамической записи; у статической — None.
    timestamp: dt.datetime | None

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.type, str(self.type))


# ---- Запросы ----------------------------------------------------------------


def server_address(server: str) -> str:
    """Адрес сервера: dnspython принимает только IP, имя сервера разрешается системой."""
    try:
        return ipaddress.ip_address(server).compressed
    except ValueError:
        try:
            return socket.gethostbyname(server)
        except OSError as exc:
            raise DnsError(f"DNS-сервер {server}: имя не разрешается") from exc


def _resolver(server: str | None, timeout: float) -> dns.resolver.Resolver:
    if server:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [server_address(server)]
        r.port = PORT
    else:
        r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    return r


def _query(r: dns.resolver.Resolver, qname: dns.name.Name, rdtype: str) -> tuple[list[Any], int | None] | None:
    """(записи, TTL); пустой ответ — ([], None); имени нет — None."""
    try:
        answer = r.resolve(qname, rdtype, search=False, raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        return None
    except dns.exception.Timeout as exc:
        raise DnsTimeout(f"{qname.to_text(omit_final_dot=True)} {rdtype}: нет ответа") from exc
    except (dns.resolver.NoNameservers, dns.resolver.NoRootSOA, dns.resolver.YXDOMAIN) as exc:
        raise DnsError(f"{qname.to_text(omit_final_dot=True)} {rdtype}: {exc.__class__.__name__}") from exc
    except dns.exception.DNSException as exc:
        raise DnsError(f"{qname.to_text(omit_final_dot=True)} {rdtype}: {exc.__class__.__name__}") from exc
    if answer.rrset is None:
        return [], None
    return list(answer.rrset), answer.rrset.ttl


def lookup_a(name: str, server: str | None, timeout: float) -> Answer:
    """A, затем AAAA; IPv4 первым. Имени нет или адресов нет — пустой ответ."""
    r = _resolver(server, timeout)
    qname = dns.name.from_text(name.strip().rstrip(".").lower() + ".")
    values: list[str] = []
    ttls: list[int] = []
    types: list[str] = []
    for rdtype in ("A", "AAAA"):
        got = _query(r, qname, rdtype)
        if got is None:
            break
        rdatas, ttl = got
        if rdatas:
            values += sorted({ipaddress.ip_address(rd.address).compressed for rd in rdatas}, key=ipaddress.ip_address)
            types.append(rdtype)
            if ttl is not None:
                ttls.append(ttl)
    return Answer(values, min(ttls) if ttls else None, types[0] if types else "")


def lookup_ptr(ip: str, server: str | None, timeout: float) -> Answer:
    r = _resolver(server, timeout)
    got = _query(r, dns.reversename.from_address(ip), "PTR")
    if not got or not got[0]:
        return Answer([], None, "")
    rdatas, ttl = got
    names = [rd.target.to_text(omit_final_dot=True).lower() for rd in rdatas]
    return Answer(sorted(names), ttl, "PTR")


def resolve_a(name: str, server: str | None, timeout: float) -> list[str]:
    return lookup_a(name, server, timeout).values


def resolve_ptr(ip: str, server: str | None, timeout: float) -> str:
    """Первое имя PTR; записи нет — пусто."""
    values = lookup_ptr(ip, server, timeout).values
    return values[0] if values else ""


class RateLimiter:
    """Не чаще `rate_per_s` вызовов `wait()` в секунду: пауза до следующего разрешённого момента."""

    def __init__(
        self, rate_per_s: float, *, clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.interval = 1 / rate_per_s if rate_per_s > 0 else 0.0
        self.clock = clock
        self.sleep = sleep
        self._next: float | None = None

    def wait(self) -> None:
        now = self.clock()
        if self._next is not None and now < self._next:
            self.sleep(self._next - now)
            now = self._next
        self._next = now + self.interval


# ---- dnsRecord и зона AD ------------------------------------------------------


def _counted_name(data: bytes) -> str | None:
    """DNS_COUNT_NAME: длина, число меток, метки «длина + байты»."""
    if len(data) < 2:
        return None
    count = data[1]
    pos = 2
    labels: list[str] = []
    for _ in range(count):
        if pos >= len(data):
            return None
        size = data[pos]
        label = data[pos + 1 : pos + 1 + size]
        if len(label) != size:
            return None
        labels.append(label.decode("utf-8", errors="replace"))
        pos += 1 + size
    return ".".join(labels).lower() or None


def parse_dns_record(raw: bytes) -> DnsRecord | None:
    """Один `dnsRecord` (DNS_RPC_RECORD): A, AAAA, CNAME; прочие типы и битые записи — None."""
    if len(raw) < _HEADER_SIZE:
        return None
    length, rtype, _version, _rank, _flags, _serial = _HEADER.unpack_from(raw, 0)
    (ttl,) = struct.unpack_from(">I", raw, 12)
    (hours,) = struct.unpack_from("<I", raw, 20)
    data = raw[_HEADER_SIZE : _HEADER_SIZE + length]
    if len(data) != length:
        return None
    if rtype == TYPE_A and length == 4:
        value: str | None = str(ipaddress.IPv4Address(data))
    elif rtype == TYPE_AAAA and length == 16:
        value = ipaddress.IPv6Address(data).compressed
    elif rtype == TYPE_CNAME:
        value = _counted_name(data)
    else:
        return None
    if value is None:
        return None
    stamp = _EPOCH_1601 + dt.timedelta(hours=hours) if hours else None
    return DnsRecord(type=rtype, value=value, ttl=ttl, timestamp=stamp)


def _first(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _tombstoned(value: Any) -> bool:
    v = _first(value)
    if isinstance(v, bytes):
        v = v.decode(errors="replace")
    return v is True or str(v).upper() == "TRUE"


def _raw_list(value: Any) -> Iterable[bytes]:
    if value is None:
        return []
    return [bytes(v) for v in value] if isinstance(value, list) else [bytes(value)]


def zone_base(domain_dn: str, zone: str) -> str:
    return f"DC={zone},CN=MicrosoftDNS,DC=DomainDnsZones,{domain_dn}"


def read_ad_zone(searcher: Searcher, domain_dn: str, zone: str) -> Iterator[tuple[str, DnsRecord]]:
    """Записи A/AAAA/CNAME узлов `dnsNode` зоны: (FQDN, запись). Вершина зоны (`@`), имена служб
    (`_ldap._tcp`, `_msdcs`) и удалённые узлы (`dNSTombstoned`) пропускаются. Зоны нет в разделе
    DomainDnsZones (noSuchObject) — пусто; другой ответ контроллера — LdapResultError.
    Паузы и отмена между запросами — забота дозатора, который получил `searcher` (`ldap3_searcher`)."""
    zone = zone.strip().rstrip(".").lower()
    try:
        entries = iter(searcher(zone_base(domain_dn, zone), "(objectClass=dnsNode)", ["name", "dnsRecord", "dNSTombstoned"], "LEVEL"))
        for entry in entries:
            attrs = entry.get("attributes") or {}
            name = str(_first(attrs.get("name")) or "").strip().lower()
            if not name or name == "@" or name.startswith("_") or _tombstoned(attrs.get("dNSTombstoned")):
                continue
            fqdn = f"{name}.{zone}"
            for raw in _raw_list((entry.get("raw_attributes") or {}).get("dnsRecord")):
                record = parse_dns_record(raw)
                if record is not None:
                    yield fqdn, record
    except LdapResultError as exc:
        if exc.code != NO_SUCH_OBJECT:
            raise
