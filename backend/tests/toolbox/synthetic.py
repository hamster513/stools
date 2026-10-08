"""Синтетика для движка очистки: словари, многострочный лог и выгрузка в стиле JSON.

В логе есть всё, что движок должен найти (адреса, хост в FQDN, учётки, SID,
секреты, слова), и то, что трогать нельзя: служебные адреса, номер версии,
`host011`, в котором не должен найтись `host01`.
"""
from __future__ import annotations

from ipaddress import IPv4Network
from typing import Any

from api.modules.toolbox.core.scrub.types import Ctx

CTX = Ctx(
    domains=frozenset({"corp.test", "corp"}),
    hosts=frozenset({"host01", "srv-db01", "msk1", "srv-db01.corp.test"}),
    users=frozenset(),
    words={"ivanov": "", "Acme": "Contoso"},
    subnets=[(IPv4Network("10.1.2.0/24"), IPv4Network("10.201.2.0/24"))],
)

TEXT = (
    "2026-10-08 10:00:01 logon host01.corp.test (10.1.2.15) user CORP\\jdoe\n"
    "2026-10-08 10:00:02 mail from jdoe@corp.test sid S-1-5-21-111-222-333-500\n"
    "2026-10-08 10:00:03 ipv6 fe80::1 and 2001:4860::8888 mac 00:1A:2B:3C:4D:5E\n"
    "2026-10-08 10:00:04 agent version 12.3.0.0 loopback 127.0.0.1\n"
    "2026-10-08 10:00:05 config password=Qwerty123!\n"
    "2026-10-08 10:00:06 Authorization: Basic am9lOnNlY3JldA==\n"
    "2026-10-08 10:00:07 aws key AKIAIOSFODNN7EXAMPLE\n"
    "2026-10-08 10:00:08 owner Ivanov, vendor ACME, neighbour host011\n"
    "2026-10-08 10:00:09 relay mail.example.test\n"
)

#: Выгрузка в стиле KSC: номер версии похож на адрес, адрес хоста есть и текстом, и двоичным `octets`.
EXPORT_JSON: dict[str, Any] = {
    "version": "12.3.0.0",
    "hosts": [
        {
            "hostname": "host01.corp.test",
            "ip": "10.1.2.15",
            "octets": {"type": "binary", "value": "CgECDw=="},  # 10.1.2.15
        },
    ],
}
