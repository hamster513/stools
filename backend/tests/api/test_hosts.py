"""Адрес внешнего сервера: только имя или IP."""
from __future__ import annotations

import pytest

from api.hosts import BAD_HOST, url_host, validate_host


@pytest.mark.parametrize("value", ["dc01.corp.local", "ksc01", "10.0.0.5", "fe80::1", "::1", "a-b.c-d.local", "x" * 63 + ".local"])
def test_names_and_ips_pass(value: str) -> None:
    assert validate_host(value) == value


def test_surrounding_spaces_are_trimmed() -> None:
    assert validate_host("  dc01.corp.local ") == "dc01.corp.local"


@pytest.mark.parametrize("value", [
    "", " ", "10.0.0.5/internal/admin?x=", "https://dc01", "dc01:636", "u@dc01", "dc01#x", "dc 01", "dc01?x",
    "-dc01.local", "dc01-.local", "dc01..local", "x" * 64 + ".local", ("a." * 127) + "ab", "[fe80::1]", "dc_01.local",
])
def test_everything_else_is_rejected(value: str) -> None:
    with pytest.raises(ValueError, match=BAD_HOST):
        validate_host(value)


def test_url_host_brackets_ipv6() -> None:
    assert url_host("fe80::1") == "[fe80::1]" and url_host("10.0.0.5") == "10.0.0.5" and url_host("dc01") == "dc01"


@pytest.mark.parametrize("value", ["fe80::1%@127.0.0.1:8080#", "fe80::1%eth0", "fe80::1%25eth0", "fe80::1%"])
def test_ipv6_zone_id_is_rejected(value: str) -> None:
    """Зона IPv6 (`%…`) не принимается вовсе: `ipaddress` пропускает в ней любые
    символы, в том числе разделители URL, и адрес уходил бы на другой хост.
    Link-local с зоной для сервера AD/KSC/VM не нужен — указывается имя или
    глобальный адрес."""
    with pytest.raises(ValueError, match=BAD_HOST):
        validate_host(value)


def test_plain_ipv6_still_passes() -> None:
    assert validate_host("2001:db8::10") == "2001:db8::10"
