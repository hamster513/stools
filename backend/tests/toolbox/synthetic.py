"""Синтетика для движка очистки: словари, многострочный лог и выгрузка в стиле JSON.

В логе есть всё, что движок должен найти (адреса, хост в FQDN, учётки, SID,
секреты, слова), и то, что трогать нельзя: служебные адреса, номер версии,
`host011`, в котором не должен найтись `host01`.
"""
from __future__ import annotations

import datetime as dt
import random
from collections.abc import Iterable
from ipaddress import IPv4Network
from typing import Any

from api.modules.toolbox.core.scrub.rules import candidate, numbered
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


#: Ключ установки для тестов; настоящий генерируется при первом запуске (спека §2).
KEY = b"synthetic-key"


class MemoryAliases:
    """Таблица соответствий в словаре: (kind, key) → псевдоним; кандидаты — как у реализации на БД."""

    def __init__(self, ctx: Ctx = CTX) -> None:
        self.ctx = ctx
        self.table: dict[tuple[str, str], str] = {}
        self.reals: dict[tuple[str, str], str] = {}
        self.proposed: dict[tuple[str, str], str] = {}

    def get(self, kind: str, key: str) -> str | None:
        return self.table.get((kind, key))

    def propose(self, kind: str, value: str, key: str) -> str:
        if (kind, key) in self.proposed:
            return self.proposed[(kind, key)]
        if kind in ("host", "domain", "user", "word"):
            n = 1 + sum(1 for k in {*self.table, *self.proposed} if k[0] == kind)
            alias = numbered(kind, n, key)
        else:
            used = {*self.table.values(), *self.proposed.values()}
            alias = candidate(kind, key, KEY, used.__contains__, self.ctx)
        self.proposed[(kind, key)] = alias
        return alias

    def commit(self, pairs: Iterable[tuple[str, str, str, str]]) -> None:
        for kind, key, real, alias in pairs:
            self.table[(kind, key)] = alias
            self.reals[(kind, key)] = real

    def pairs(self) -> list[tuple[str, str]]:
        """(псевдоним, настоящее) — вход обратного перевода."""
        return [(alias, self.reals[k]) for k, alias in self.table.items()]


# --- большая выгрузка в стиле KSC -------------------------------------------------------------

#: Хост в стиле KSC: строки — как в выгрузке (имя в четырёх написаниях, домен, версии, даты);
#: id хоста — GUID, как у настоящего KSC, он же ключ в products/components/tags.
def _ksc_host(n: int, rng: random.Random, now: dt.datetime) -> tuple[str, dict[str, Any]]:
    name = f"WS{n:05d}"
    hid = f"{rng.getrandbits(32):08x}-{rng.getrandbits(16):04x}-{rng.getrandbits(16):04x}-{rng.getrandbits(64):016x}"
    seen = now - dt.timedelta(seconds=rng.randrange(86_400 * 30))
    host: dict[str, Any] = {
        "KLHST_WKS_HOSTNAME": hid,
        "KLHST_WKS_DN": name, "KLHST_WKS_WINHOSTNAME": name, "KLHST_WKS_DNSNAME": name.lower(),
        "KLHST_WKS_WINDOMAIN": "CORP", "KLHST_WKS_DNSDOMAIN": "corp.local",
        "KLHST_WKS_FQDN": f"{name.lower()}.corp.local",
        "KLHST_WKS_IP": f"10.{n >> 16 & 255}.{n >> 8 & 255}.{n & 255}",
        "KLHST_WKS_GROUPID": n % 40, "KLHST_WKS_OS_NAME": rng.choice(OS_NAMES), "KLHST_WKS_CTYPE": 1,
        "KLHST_WKS_IP_LONG": {"type": "long", "value": 167_772_160 + n},
        "KLHST_WKS_STATUS": 29, "KLHST_WKS_STATUS_ID": 0, "KLHST_WKS_STATUS_MASK": 0,
        "KLHST_WKS_RTP_STATE": 7, "KLHST_WKS_VIRUS_COUNT": 0, "KLHST_WKS_UNCURED_COUNT": 0,
        "KLHST_WKS_FROM_UNASSIGNED": False,
        "KLHST_WKS_LAST_VISIBLE": {"type": "datetime", "value": seen.strftime("%Y-%m-%dT%H:%M:%SZ")},
        "KLHST_WKS_LAST_NAGENT_CONNECTED": {"type": "datetime", "value": (seen - dt.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")},
        "KLHST_WKS_NAG_VERSION": "15.1.0.0", "KLHST_WKS_RTP_AV_VERSION": rng.choice(("12.0.0.0", "12.6.0.0", "11.0.0.0")),
        "KLHST_WKS_RTP_AV_BASES_TIME": {"type": "datetime", "value": (seen - dt.timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")},
        "KLHST_WKS_LAST_FULLSCAN": {"type": "datetime", "value": (seen - dt.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")},
        "KLHST_WKS_OS_BUILD_NUMBER": 22631, "KLHST_WKS_CPU_ARCH": 2, "HST_VM_TYPE": 3,
        "KLHST_WKS_LAST_USER": f"CORP\\user{n % 500:03d}",
        "KLHST_WKS_COMMENT": rng.choice(COMMENTS),
    }
    return hid, host


OS_NAMES = ("Microsoft Windows 11", "Microsoft Windows 10", "Microsoft Windows Server 2022")
COMPONENTS = ("File Threat Protection", "Behavior Detection", "Exploit Prevention", "Firewall",
              "Network Threat Protection", "Web Control", "Device Control")
#: Свободный текст с тем, что движок ищет и не ищет: адрес, хост, учётка, слово, файл, версия.
COMMENTS = (
    "", "owner Ivanov", "replaced 2026-09-01, see ticket 4711", "relay 10.1.2.15 via srv-db01.corp.local",
    "contact jdoe@corp.local", "build 7.2.3.4 pending", "backup C:\\Backup\\host01_notes.txt",
    "vendor ACME", "sid S-1-5-21-111-222-333-500", "mac 00:1A:2B:3C:4D:5E", "ipv6 2001:4860::8888",
)


def ksc_like_export(hosts: int, *, seed: int = 1) -> dict[str, Any]:
    """Синтетическая выгрузка KSC на `hosts` хостов: по структуре — как `tests.ksc.synthetic.build_export`
    (хосты, продукты, компоненты, группы, политики с содержимым, роли, теги), по объёму — как на стенде
    (~100 кусков на хост, большинство строк повторяются, уникальны GUID, даты и адреса). Только синтетика."""
    rng = random.Random(seed)
    now = dt.datetime(2026, 9, 15, 12, 0, tzinfo=dt.UTC)
    host_list: list[dict[str, Any]] = []
    products: dict[str, Any] = {}
    components: dict[str, Any] = {}
    tags: dict[str, list[str]] = {}
    for n in range(1, hosts + 1):
        hid, host = _ksc_host(n, rng, now)
        host_list.append(host)
        ver = host["KLHST_WKS_RTP_AV_VERSION"]
        products[hid] = {
            "1103": {"1.0.0.0": {"DisplayName": "Агент администрирования", "ProdVersion": host["KLHST_WKS_NAG_VERSION"]}},
            "KES": {ver: {"DisplayName": "Kaspersky Endpoint Security для Windows", "ProdVersion": ver}},
        }
        components[hid] = {f"KES/{ver}": [
            {"KLHST_PRCST_COMPONENT_DN": c, "KLHST_PRCST_COMPONENT_STATUS": 4,
             "KLHST_PRCST_COMPONENT_ID": {"type": "binary", "value": "AAAA"}}
            for c in COMPONENTS
        ]}
        tags[hid] = [f"site-{n % 7}", "workstation"]
    groups = [{"id": g, "name": f"Group {g}", "parentId": 0 if g else -1, "grp_full_name": f"Managed devices/Group {g}", "level": 1}
              for g in range(40)]
    policy = {
        "KLPOL_ID": 1, "KLPOL_DN": "KES workstations", "KLPOL_PRODUCT": "KES", "KLPOL_VERSION": "12.0.0.0",
        "KLPOL_GROUP_ID": 0, "KLPOL_ACTIVE": True, "KLPOL_INHERITED": False, "KLPOL_ACCEPT_PARENT": True,
        "KLPOL_MODIFIED": {"type": "datetime", "value": "2026-08-16T12:00:00Z"}, "KLPOL_GROUP_NAME": "Managed devices",
    }
    roles = [
        {"nRoleId": 2, "wstrRoleName": "Administrator", "wstrTrusteeDisplayName": f"CORP\\user{n:03d}",
         "wstrUserPrincipalName": f"user{n:03d}@corp.local", "nGroupId": 0, "wstrGroupName": "Managed devices"}
        for n in range(500)
    ]
    return {
        "format": "stools-ksc/1",
        "server": {"name": "ksc01", "version": "15.1.0.11225", "user": "KL\\audit", "host": "ksc01.corp.local",
                   "password": "hunter2"},
        "groups": groups, "hosts": host_list, "host_products": products, "host_components": components,
        "policies": [policy], "effective_policies": {str(g["id"]): [dict(policy, KLPOL_INHERITED=True)] for g in groups},
        "policy_contents": {"1": {
            # Значение не то, что под ключом password: пароль в контейнере KSC (под KLPRSS_Val) детекторы не
            # узнают, и включённый по другому месту он остался бы в результате остатком самопроверки.
            "KLPRSS_Basic": {"AdminPassword": {"KLPRSS_Val": "kes-admin-7", "KLPRSS_Mnd": True},
                             "Exclusions": {"KLPRSS_Val": ["C:\\Tools\\a.exe"]}},
            "KLPRSS_Firewall": {"rules": [{"name": "lan", "octets": {"type": "binary", "value": "CgECDw=="}, "mask": 24}]},
        }},
        "domains": [{"KLHST_WKS_WINDOMAIN": "CORP", "KLHST_WKS_DNSDOMAIN": "corp.local"}],
        "role_assignments": roles, "host_tags": tags,
    }


def ksc_like_ctx(hosts: int) -> Ctx:
    """Словарь как на стенде: хосты выгрузки (короткие имена и FQDN) и домен AD в словарях."""
    names = {f"ws{n:05d}" for n in range(1, hosts + 1)}
    return Ctx(
        domains=frozenset({"corp.local", "corp"}),
        hosts=frozenset(names | {f"{n}.corp.local" for n in names} | {"srv-db01"}),
        users=frozenset({f"user{n:03d}" for n in range(500)}),
        words={"ivanov": "", "Acme": "Contoso"},
        subnets=[(IPv4Network("10.1.2.0/24"), IPv4Network("10.201.2.0/24"))],
    )
