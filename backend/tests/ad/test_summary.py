"""Сводка домена (спека гигиены AD, §6): счётчики, корзины, таблицы — на мини-выгрузке."""
from __future__ import annotations

import base64
from typing import Any

from api.modules.ad.core import sd
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex
from api.modules.ad.core.summary import AGE_BOUNDS, build_summary
from tests.ad.mini import DN, DOMAIN_SID, computer, dc, ft, gpo, group, mini_export, rid, user

CONF = f"CN=Configuration,{DN}"
POLICY = gpo("Workstations", "{22222222-2222-2222-2222-222222222222}", flags=1)
OU = f"OU=Workstations,{DN}"


def _summary() -> dict[str, Any]:
    alice = user("alice", 1101, uac=512 | 0x10000, pwdLastSet=ft(400))
    bob = user("bob", 1102, lastLogonTimestamp=ft(200))
    export = mini_export(
        [
            {"dn": DN, "class": "domainDNS", "sid": DOMAIN_SID, "gpLink": f"[LDAP://{POLICY['dn']};2]"},
            {"dn": OU, "class": "organizationalUnit", "gpLink": f"[LDAP://{POLICY['dn']};1]"},
            user("Administrator", 500, uac=514),
            alice,
            bob,
            user("carol", 1103, uac=512 | 0x20 | 0x400000, sIDHistory=["S-1-5-21-9-9-9-1105"], pwdLastSet=0, lastLogonTimestamp=None),
            user("dave", 1104, uac=514),
            group("Protected Users", rid(525), [alice["dn"]]),
            computer("WS1", 1201, operatingSystem="Windows 11 Pro", operatingSystemVersion="10.0 (22631)", lapsExpiry=ft(-10)),
            computer("WS2", 1202, uac=4098, operatingSystem="Windows 11 Pro", operatingSystemVersion="10.0 (22631)"),
            computer("WS3", 1203, operatingSystem="Windows 10 Pro", operatingSystemVersion="10.0 (19045)",
                     lastLogonTimestamp=ft(200), allowedToDelegateTo=["cifs/fs.corp.local"]),
            dc("DC1", 1000, operatingSystem="Windows Server 2022 Standard", operatingSystemVersion="10.0 (20348)",
               lastLogonTimestamp=ft(1), pwdLastSet=ft(20), sd=base64.b64encode(sd.build_sd([sd.build_ace(rid(512), sd.GENERIC_ALL)], owner=rid(512))).decode()),
            {"dn": f"CN=other.local,CN=System,{DN}", "class": "trustedDomain", "flatName": "OTHER", "sid": "S-1-5-21-111-222-333",
             "trustAttributes": 0x20, "trustDirection": 3, "trustType": 2, "trustPartner": "other.local", "whenChanged": "2026-09-01T00:00:00+00:00"},
            {"dn": f"CN=Admins PSO,CN=Password Settings Container,CN=System,{DN}", "class": "msDS-PasswordSettings", "name": "Admins PSO",
             "psoMinLength": 15, "psoLockoutThreshold": 5, "psoComplexity": True, "psoReversible": False, "psoPrecedence": 10},
            {"dn": f"CN=10.0.0.0/24,CN=Subnets,CN=Sites,{CONF}", "class": "subnet", "name": "10.0.0.0/24",
             "site": f"CN=Default-First-Site-Name,CN=Sites,{CONF}"},
            POLICY,
        ],
        admins=["alice", "bob"],
        domain={"min_pwd_length": 7, "lockout_threshold": 0, "pwd_properties": 1},
    )
    return build_summary(ExportIndex(export), AdConfig())


def _bucket(buckets: list[dict[str, Any]], le: int | None) -> int:
    return next(int(b["n"]) for b in buckets if b["le"] == le)


def test_accounts_counts() -> None:
    s = _summary()
    assert s["version"] == 1
    assert s["accounts"]["users"] == {
        "total": 6, "enabled": 3, "disabled": 3, "active": 1, "inactive": 2, "pwd_never_expires": 1, "pwd_not_required": 1,
        "no_preauth": 1, "sid_history": 1, "delegation": 0, "laps": 0,
    }
    assert s["accounts"]["computers"] == {
        "total": 4, "enabled": 3, "disabled": 1, "active": 2, "inactive": 1, "pwd_never_expires": 0, "pwd_not_required": 0,
        "no_preauth": 0, "sid_history": 0, "delegation": 1, "laps": 1,  # WS3; штатная неограниченная у DC1 не в счёт
    }


def test_age_buckets_for_admins_and_all() -> None:
    s = _summary()
    admins = s["password_age"]["admins"]
    assert [b["le"] for b in admins] == [*AGE_BOUNDS, None]
    assert sum(b["n"] for b in admins) == 2
    assert _bucket(admins, 30) == 1 and _bucket(admins, 730) == 1
    everyone = s["password_age"]["all"]
    assert sum(b["n"] for b in everyone) == 3 and _bucket(everyone, None) == 1  # у carol пароль не задан
    logons = s["last_logon"]["admins"]
    assert _bucket(logons, 30) == 1 and _bucket(logons, 365) == 1
    assert _bucket(s["last_logon"]["all"], None) == 1  # carol не входила


def test_dc_row_and_os_table() -> None:
    s = _summary()
    assert s["dcs"] == [{
        "name": "DC1", "dn": f"CN=DC1,OU=Domain Controllers,{DN}", "dns": "dc1.corp.local", "os": "Windows Server 2022 Standard",
        "build": "20348", "rodc": False, "last_logon_days": 1, "pwd_age_days": 20, "owner": "CORP\\Domain Admins",
    }]
    assert s["os"][0] == {"name": "Windows 11 Pro", "build": "22631", "total": 2, "enabled": 1, "active": 1}
    assert {(r["name"], r["total"], r["active"]) for r in s["os"][1:]} == {("Windows 10 Pro", 1, 0), ("Windows Server 2022 Standard", 1, 1)}


def test_privileged_group_row() -> None:
    s = _summary()
    da = next(g for g in s["groups"] if g["sid"] == rid(512))  # выключенный Administrator — участник, но не включённый
    assert da == {
        "name": "Domain Admins", "sid": rid(512), "members": 3, "enabled": 2, "inactive": 1, "pwd_never_expires": 1,
        "delegable": 2, "protected_users": 1,
    }


def test_trusts_policies_gpos_subnets() -> None:
    s = _summary()
    assert s["trusts"] == [{"partner": "other.local", "flat_name": "OTHER", "direction": 3, "type": 2, "within_forest": True,
                            "changed": "2026-09-01T00:00:00+00:00"}]
    assert s["password_policies"] == [
        {"name": "Политика домена", "min_length": 7, "lockout_threshold": 0, "complexity": True, "reversible": False, "precedence": None},
        {"name": "Admins PSO", "min_length": 15, "lockout_threshold": 5, "complexity": True, "reversible": False, "precedence": 10},
    ]
    assert s["gpos"] == [{
        "name": "Workstations", "dn": POLICY["dn"], "machine_disabled": False, "user_disabled": True,
        "links": [{"dn": DN, "enforced": True, "disabled": False}, {"dn": OU, "enforced": False, "disabled": True}],
    }]
    assert s["subnets"] == [{"name": "10.0.0.0/24", "site": "Default-First-Site-Name"}]


def test_old_export_without_new_fields() -> None:
    export = mini_export([computer("WS1", 1201), dc("DC1", 1000), gpo("Old")])
    s = build_summary(ExportIndex(export), AdConfig())
    assert s["dcs"][0]["owner"] == "" and s["dcs"][0]["os"] == "" and s["dcs"][0]["build"] == ""
    assert s["gpos"][0]["links"] is None
    assert s["trusts"] == [] and s["subnets"] == [] and s["password_policies"] == []
    assert s["os"] == [{"name": "", "build": "", "total": 2, "enabled": 2, "active": 2}]


def test_clusters_block() -> None:
    """Роль привязана к кластеру по creatorSid учётки кластера; чужой создатель — роль без кластера; узлы отдельно."""
    export = mini_export([
        computer("CLUSTER01", 1301, spn=["MSServerCluster/CLUSTER01"]),
        computer("SQLROLE1", 1302, spn=["MSClusterVirtualServer/SQLROLE1"], creatorSid=rid(1301)),
        computer("FSROLE1", 1303, spn=["MSClusterVirtualServer/FSROLE1"], creatorSid=rid(1301), uac=4098),
        computer("LOSTROLE1", 1304, spn=["MSClusterVirtualServer/LOSTROLE1"], creatorSid="S-1-5-21-9-9-9-1105"),
        computer("NODE02", 1306, spn=["MSServerClusterMgmtAPI/NODE02"], operatingSystem="Windows Server 2022 Standard"),
        computer("NODE01", 1305, spn=["MSServerClusterMgmtAPI/NODE01"], dNSHostName="node01.corp.local",
                 operatingSystem="Windows Server 2019 Datacenter"),
        computer("WS1", 1201, spn=["HOST/ws1"]),
    ])
    s = build_summary(ExportIndex(export), AdConfig())
    assert s["version"] == 1
    assert s["clusters"] == {
        "clusters": [{
            "name": "CLUSTER01", "dn": f"CN=CLUSTER01,CN=Computers,{DN}", "enabled": True,
            "roles": [{"name": "FSROLE1", "enabled": False}, {"name": "SQLROLE1", "enabled": True}], "roles_disabled": 1,
        }],
        "orphan_roles": [{"name": "LOSTROLE1", "enabled": True}],
        "nodes": [
            {"name": "NODE01", "dns": "node01.corp.local", "os": "Windows Server 2019 Datacenter"},
            {"name": "NODE02", "dns": "node02.corp.local", "os": "Windows Server 2022 Standard"},
        ],
    }


def test_clusters_block_empty_without_cluster_spn() -> None:
    s = build_summary(ExportIndex(mini_export([computer("WS1", 1201, spn=["HOST/ws1"]), dc("DC1", 1000)])), AdConfig())
    assert s["clusters"] == {"clusters": [], "orphan_roles": [], "nodes": []}
