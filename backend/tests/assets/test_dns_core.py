"""Ядро DNS без базы: A/AAAA и PTR к указанному серверу и системному резолверу, таймаут,
разбор dnsRecord, чтение AD-integrated зоны, темп запросов.

Запросы уходят только на поддельный сервер на 127.0.0.1; системный резолвер подменён."""
from __future__ import annotations

import datetime as dt
import ipaddress
import struct
import time
from collections.abc import Iterator
from typing import Any

import dns.resolver
import pytest

from api.modules.ad.core.ldap_collector import LdapResultError
from api.modules.assets.core import dns as dns_core
from api.modules.assets.core.dns import (
    DnsError,
    DnsRecord,
    DnsTimeout,
    RateLimiter,
    lookup_a,
    parse_dns_record,
    read_ad_zone,
    resolve_a,
    resolve_ptr,
)
from tests.assets.fake_dns import (
    FakeDnsServer,
    FakeZoneLdap,
    a_record,
    cname_record,
    dns_record,
    hours_since_1601,
)

STAMP = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.UTC)


@pytest.fixture
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeDnsServer]:
    with FakeDnsServer() as server:
        server.add("srv01.corp.local", "A", "10.10.0.5")
        server.add("srv02.corp.local", "A", "10.10.0.6")
        server.add("srv02.corp.local", "AAAA", "fd00::6")
        server.ptr("10.10.0.5", "srv01.corp.local")
        server.silent.add("slow.corp.local")
        server.silent.add(ipaddress.ip_address("10.10.0.99").reverse_pointer)
        monkeypatch.setattr(dns_core, "PORT", server.port)
        yield server


# ---- Запросы ----------------------------------------------------------------


def test_resolve_a_against_server(fake_dns: FakeDnsServer) -> None:
    assert resolve_a("srv01.corp.local", "127.0.0.1", 1.0) == ["10.10.0.5"]
    # Имя с точкой на конце и в верхнем регистре — то же имя.
    assert resolve_a("SRV01.corp.local.", "127.0.0.1", 1.0) == ["10.10.0.5"]
    # A и AAAA вместе, IPv4 первым.
    assert resolve_a("srv02.corp.local", "127.0.0.1", 1.0) == ["10.10.0.6", "fd00::6"]
    assert ("srv01.corp.local", "A") in fake_dns.queries


def test_lookup_a_gives_ttl(fake_dns: FakeDnsServer) -> None:
    answer = lookup_a("srv01.corp.local", "127.0.0.1", 1.0)
    assert answer.values == ["10.10.0.5"] and answer.ttl == 300 and answer.record_type == "A"


def test_nxdomain_is_empty(fake_dns: FakeDnsServer) -> None:
    assert resolve_a("nope.corp.local", "127.0.0.1", 1.0) == []
    # Имени нет — AAAA уже не спрашиваем.
    assert ("nope.corp.local", "AAAA") not in fake_dns.queries
    assert resolve_ptr("10.10.0.77", "127.0.0.1", 1.0) == ""


def test_resolve_ptr(fake_dns: FakeDnsServer) -> None:
    assert resolve_ptr("10.10.0.5", "127.0.0.1", 1.0) == "srv01.corp.local"


def test_timeout_raises_quickly(fake_dns: FakeDnsServer) -> None:
    started = time.monotonic()
    with pytest.raises(DnsTimeout):
        resolve_a("slow.corp.local", "127.0.0.1", 0.3)
    with pytest.raises(DnsTimeout):
        resolve_ptr("10.10.0.99", "127.0.0.1", 0.3)
    assert time.monotonic() - started < 3
    assert issubclass(DnsTimeout, DnsError)


def test_system_resolver_without_server(fake_dns: FakeDnsServer, monkeypatch: pytest.MonkeyPatch) -> None:
    """Без сервера — системный резолвер dnspython (`Resolver()` читает resolv.conf); здесь он подменён."""
    real = dns.resolver.Resolver
    made: list[bool] = []

    def system(configure: bool = True) -> Any:
        made.append(configure)
        r = real(configure=False)
        r.nameservers = ["127.0.0.1"]
        r.port = fake_dns.port
        return r

    monkeypatch.setattr(dns.resolver, "Resolver", system)
    assert resolve_a("srv01.corp.local", None, 1.0) == ["10.10.0.5"]
    assert resolve_ptr("10.10.0.5", "", 1.0) == "srv01.corp.local"
    assert made and all(made)


def test_server_by_name_is_resolved(fake_dns: FakeDnsServer) -> None:
    assert resolve_a("srv01.corp.local", "localhost", 1.0) == ["10.10.0.5"]


# ---- dnsRecord --------------------------------------------------------------


def test_parse_a_with_timestamp() -> None:
    rec = parse_dns_record(a_record("10.10.0.5", ttl=1200, stamp=STAMP))
    assert rec == DnsRecord(type=1, value="10.10.0.5", ttl=1200, timestamp=STAMP)
    assert rec is not None and rec.type_name == "A"


def test_parse_static_record_has_no_timestamp() -> None:
    rec = parse_dns_record(a_record("10.10.0.6"))
    assert rec is not None and rec.timestamp is None and rec.ttl == 300


def test_parse_aaaa() -> None:
    rec = parse_dns_record(a_record("fd00::6", stamp=STAMP))
    assert rec == DnsRecord(type=28, value="fd00::6", ttl=300, timestamp=STAMP)


def test_parse_cname() -> None:
    rec = parse_dns_record(cname_record("SRV01.corp.local"))
    assert rec == DnsRecord(type=5, value="srv01.corp.local", ttl=300, timestamp=None)


def test_parse_ttl_is_big_endian() -> None:
    raw = a_record("10.10.0.5", ttl=0x01020304)
    assert raw[12:16] == b"\x01\x02\x03\x04"
    rec = parse_dns_record(raw)
    assert rec is not None and rec.ttl == 0x01020304


def test_parse_timestamp_is_little_endian_hours() -> None:
    raw = a_record("10.10.0.5", stamp=STAMP)
    assert struct.unpack("<I", raw[20:24])[0] == hours_since_1601(STAMP)


def test_parse_unknown_and_broken() -> None:
    assert parse_dns_record(dns_record(15, b"\x00\x0a\x04mail\x00")) is None  # MX
    assert parse_dns_record(dns_record(0, b"")) is None  # «нулевая» запись — надгробие
    assert parse_dns_record(b"\x04\x00\x01\x00") is None  # обрезан заголовок
    assert parse_dns_record(a_record("10.10.0.5")[:-1]) is None  # обрезаны данные
    assert parse_dns_record(dns_record(1, b"\x0a\x0a")) is None  # A не 4 байта


# ---- Зона AD ----------------------------------------------------------------


def _zone() -> FakeZoneLdap:
    ldap = FakeZoneLdap()
    ldap.zones["corp.local"] = {
        "@": [a_record("10.10.0.2")],
        "_ldap._tcp": [dns_record(33, b"\x00" * 8)],
        "_msdcs": [a_record("10.10.0.2")],
        "srv01": [a_record("10.10.0.5", stamp=STAMP)],
        "web": [cname_record("srv01.corp.local")],
        "msk1": [a_record("10.10.0.20"), a_record("fd00::20"), dns_record(16, b"\x03txt")],
        "old": [a_record("10.10.0.30")],
    }
    ldap.tombstoned.add("old")
    return ldap


def test_read_ad_zone() -> None:
    ldap = _zone()
    got = list(read_ad_zone(ldap.search, "DC=corp,DC=local", "corp.local"))
    assert got == [
        ("srv01.corp.local", DnsRecord(1, "10.10.0.5", 300, STAMP)),
        ("web.corp.local", DnsRecord(5, "srv01.corp.local", 300, None)),
        ("msk1.corp.local", DnsRecord(1, "10.10.0.20", 300, None)),
        ("msk1.corp.local", DnsRecord(28, "fd00::20", 300, None)),
    ]
    base, flt, attrs, _scope = ldap.calls[0]
    assert base == "DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=local"
    assert flt == "(objectClass=dnsNode)"
    assert {"name", "dnsRecord"} <= set(attrs)


def test_read_missing_zone_is_empty() -> None:
    assert list(read_ad_zone(_zone().search, "DC=corp,DC=local", "lab.local")) == []


def test_read_zone_other_ldap_error_fails() -> None:
    ldap = _zone()
    ldap.failing.add("corp.local")
    with pytest.raises(LdapResultError):
        list(read_ad_zone(ldap.search, "DC=corp,DC=local", "corp.local"))


def test_read_zone_list_valued_attributes() -> None:
    """ldap3 со схемой отдаёт name строкой, без схемы — списком; dNSTombstoned — bool или 'TRUE'."""

    def search(base: str, flt: str, attrs: list[str], scope: str) -> list[dict[str, Any]]:
        return [
            {"dn": f"DC=srv01,{base}", "attributes": {"name": ["srv01"]}, "raw_attributes": {"dnsRecord": [a_record("10.10.0.5")]}},
            {"dn": f"DC=gone,{base}", "attributes": {"name": ["gone"], "dNSTombstoned": ["TRUE"]},
             "raw_attributes": {"dnsRecord": [a_record("10.10.0.6")]}},
        ]

    assert [fqdn for fqdn, _ in read_ad_zone(search, "DC=corp,DC=local", "corp.local")] == ["srv01.corp.local"]


def test_ldap_result_error_is_the_collectors() -> None:
    assert LdapResultError(32, "noSuchObject", "x").code == 32


# ---- Темп -------------------------------------------------------------------


def test_rate_limiter_spaces_requests() -> None:
    now = [100.0]
    slept: list[float] = []

    def sleep(s: float) -> None:
        slept.append(round(s, 3))
        now[0] += s

    rate = RateLimiter(10, clock=lambda: now[0], sleep=sleep)
    rate.wait()
    rate.wait()
    now[0] += 0.05
    rate.wait()
    now[0] += 1
    rate.wait()
    assert slept == [0.1, 0.05]
