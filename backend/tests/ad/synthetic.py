"""Синтетический домен CORP с известными ответами на все 20 проверок.

Строится функцией, а не лежит файлом: тесты подкручивают отдельные
объекты (убрать ACE, добавить участника), чтобы проверить и отсутствие
находки, а не только её наличие.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import uuid
from typing import Any

from api.modules.ad.core import sd
from api.modules.ad.core.export import datetime_to_filetime

DOMAIN_SID = "S-1-5-21-1000-2000-3000"
DN = "DC=corp,DC=local"
CONF_DN = "CN=Configuration,DC=corp,DC=local"
PKI = f"CN=Public Key Services,CN=Services,{CONF_DN}"
OTHER_SID = "S-1-5-21-111-222-333"

GUID_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GUID_GET_CHANGES_FILTERED = "89e95b76-444d-4c62-991a-0facbeda640c"
GUID_ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
GUID_AUTOENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
GUID_KEYCRED = "5b47d60f-6090-40b2-9f37-2a4de88f3063"

NOW = dt.datetime(2026, 9, 9, 12, 0, tzinfo=dt.UTC)


def rid(n: int) -> str:
    return f"{DOMAIN_SID}-{n}"


def ft(days_ago: int) -> int:
    return datetime_to_filetime(NOW - dt.timedelta(days=days_ago))


def b64sd(aces: list[bytes]) -> str:
    return base64.b64encode(sd.build_sd(aces)).decode()


# Учётные записи: sam → (rid, class)
ACCOUNTS: dict[str, tuple[int, str]] = {
    "admin1": (1101, "user"),
    "admin2": (1102, "user"),
    "shadow.admin": (1103, "user"),
    "svc_backup": (1104, "user"),
    "svc_sql": (1105, "user"),
    "svc_old": (1106, "user"),
    "user.noexpire": (1107, "user"),
    "helpdesk": (1108, "user"),
    "user.inactive": (1109, "user"),
    "user.rc4": (1110, "user"),
    "user.rc4aes": (1111, "user"),
    "delegate.user": (1112, "user"),
    "gpo.editor": (1113, "user"),
    "user.disabled": (1114, "user"),
    "krbtgt": (502, "user"),
    "WS01$": (1201, "computer"),
    "SRV01$": (1202, "computer"),
    "Domain Admins": (512, "group"),
    "Domain Users": (513, "group"),
    "Enterprise Admins": (519, "group"),
    "Protected Users": (525, "group"),
    "Tier0": (1301, "group"),
}


def user_dn(sam: str) -> str:
    return f"CN={sam},CN=Users,{DN}"


def build_export(*, now: dt.datetime = NOW) -> dict[str, Any]:
    def acct(sam: str, **extra: Any) -> dict[str, Any]:
        r, cls = ACCOUNTS[sam]
        base: dict[str, Any] = {
            "dn": user_dn(sam) if cls != "computer" else f"CN={sam.rstrip('$')},CN=Computers,{DN}",
            "class": cls,
            "sid": rid(r),
            "sam": sam,
            "name": sam.rstrip("$"),
            "uac": 512 if cls == "user" else 4096,
            "lastLogonTimestamp": ft(3),
            "pwdLastSet": ft(30),
        }
        base.update(extra)
        return base

    objects: list[dict[str, Any]] = [
        # Корень домена: DCSync у Domain Admins (allowlist) и у svc_backup (нет);
        # запись msDS-KeyCredentialLink у helpdesk.
        {
            "dn": DN,
            "class": "domainDNS",
            "sid": DOMAIN_SID,
            "sd": b64sd(
                [
                    sd.build_ace(rid(512), sd.EXTENDED_RIGHT, object_type=uuid.UUID(GUID_GET_CHANGES_ALL)),
                    sd.build_ace(rid(512), sd.EXTENDED_RIGHT, object_type=uuid.UUID(GUID_GET_CHANGES)),
                    sd.build_ace(rid(1104), sd.EXTENDED_RIGHT, object_type=uuid.UUID(GUID_GET_CHANGES_ALL)),
                    sd.build_ace(rid(1104), sd.EXTENDED_RIGHT, object_type=uuid.UUID(GUID_GET_CHANGES)),
                    sd.build_ace(rid(1108), sd.WRITE_PROPERTY, object_type=uuid.UUID(GUID_KEYCRED)),
                    sd.build_ace("S-1-5-11", sd.READ_PROPERTY | sd.LIST_CHILDREN),
                ]
            ),
        },
        {
            "dn": f"CN=AdminSDHolder,CN=System,{DN}",
            "class": "container",
            "sd": b64sd(
                [
                    sd.build_ace(rid(512), sd.GENERIC_ALL),
                    sd.build_ace(rid(1103), sd.GENERIC_ALL),  # shadow admin
                    sd.build_ace("S-1-5-11", sd.READ_PROPERTY),
                ]
            ),
        },
        {"dn": f"OU=Servers,{DN}", "class": "organizationalUnit", "sd": b64sd([sd.build_ace(rid(1108), sd.WRITE_DACL), sd.build_ace(rid(512), sd.GENERIC_ALL)])},
        {"dn": f"OU=Clean,{DN}", "class": "organizationalUnit", "sd": b64sd([sd.build_ace(rid(512), sd.GENERIC_ALL), sd.build_ace("S-1-5-11", sd.READ_PROPERTY)])},
        acct("admin1", adminCount=1),
        acct("admin2", adminCount=1),
        acct("shadow.admin"),
        acct("svc_backup"),
        acct("svc_sql", spn=["MSSQLSvc/srv01.corp.local:1433"], pwdLastSet=ft(900)),
        acct("svc_old", uac=512 | 0x400000, adminCount=1),
        acct("user.noexpire", uac=512 | 0x10000),
        acct("helpdesk"),
        acct("user.inactive", lastLogonTimestamp=ft(200)),
        acct("user.rc4", supportedEncryptionTypes=4),
        acct("user.rc4aes", supportedEncryptionTypes=28),
        acct("delegate.user", trustedForDelegation=True, uac=512 | 0x80000),
        acct("gpo.editor"),
        acct("user.disabled", uac=514 | 0x400000 | 0x10000, lastLogonTimestamp=ft(400)),
        acct("krbtgt", uac=514, pwdLastSet=ft(400)),
        acct(
            "WS01$",
            allowedToActOnBehalf=b64sd([sd.build_ace(rid(1108), sd.GENERIC_ALL)]),
            sd=b64sd([sd.build_ace(rid(512), sd.GENERIC_ALL)]),
        ),
        acct(
            "SRV01$",
            allowedToDelegateTo=["cifs/fs01.corp.local"],
            trustedToAuthForDelegation=True,
            uac=4096 | 0x1000000,
            sd=b64sd([sd.build_ace(rid(513), sd.GENERIC_ALL), sd.build_ace(rid(512), sd.GENERIC_ALL)]),
        ),
        {"dn": user_dn("Domain Admins"), "class": "group", "sid": rid(512), "sam": "Domain Admins", "name": "Domain Admins", "adminCount": 1, "member": [user_dn("admin1"), user_dn("Tier0"), f"CN=WS01,CN=Computers,{DN}"]},
        {"dn": user_dn("Tier0"), "class": "group", "sid": rid(1301), "sam": "Tier0", "name": "Tier0", "member": [user_dn("admin2"), user_dn("Domain Admins")]},
        {"dn": user_dn("Enterprise Admins"), "class": "group", "sid": rid(519), "sam": "Enterprise Admins", "name": "Enterprise Admins", "adminCount": 1, "member": [user_dn("admin1")]},
        {"dn": user_dn("Domain Users"), "class": "group", "sid": rid(513), "sam": "Domain Users", "name": "Domain Users", "member": []},
        {"dn": user_dn("Protected Users"), "class": "group", "sid": rid(525), "sam": "Protected Users", "name": "Protected Users", "member": [user_dn("admin1")]},
        {
            "dn": f"CN={{31B2F340-016D-11D2-945F-00C04FB984F9}},CN=Policies,CN=System,{DN}",
            "class": "groupPolicyContainer",
            "displayName": "Default Domain Policy",
            "gpcFileSysPath": "\\\\corp.local\\SysVol\\corp.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}",
            "sd": b64sd([sd.build_ace(rid(512), sd.GENERIC_ALL), sd.build_ace(rid(1113), sd.GENERIC_WRITE), sd.build_ace("S-1-5-11", sd.READ_PROPERTY)]),
        },
        {
            "dn": f"CN=VulnTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,{CONF_DN}",
            "class": "pKICertificateTemplate",
            "cn": "VulnTemplate",
            "displayName": "VulnTemplate",
            "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
            "msPKI-Certificate-Name-Flag": 1,
            "msPKI-Enrollment-Flag": 0,
            "sd": b64sd([sd.build_ace(rid(513), sd.EXTENDED_RIGHT, object_type=uuid.UUID(GUID_ENROLL)), sd.build_ace(rid(512), sd.GENERIC_ALL)]),
        },
        {
            "dn": f"CN=AgentTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,{CONF_DN}",
            "class": "pKICertificateTemplate",
            "cn": "AgentTemplate",
            "displayName": "AgentTemplate",
            "pKIExtendedKeyUsage": ["1.3.6.1.4.1.311.20.2.1"],
            "msPKI-Certificate-Name-Flag": 0,
            "sd": b64sd([sd.build_ace("S-1-5-11", sd.EXTENDED_RIGHT, object_type=uuid.UUID(GUID_ENROLL)), sd.build_ace("S-1-5-11", sd.WRITE_DACL)]),
        },
        {
            "dn": f"CN=SafeTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,{CONF_DN}",
            "class": "pKICertificateTemplate",
            "cn": "SafeTemplate",
            "displayName": "SafeTemplate",
            "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.1"],
            "msPKI-Certificate-Name-Flag": 0,
            "sd": b64sd([sd.build_ace(rid(512), sd.GENERIC_ALL)]),
        },
        {
            "dn": f"CN=CORP-CA,CN=Enrollment Services,{PKI}",
            "class": "pKIEnrollmentService",
            "cn": "CORP-CA",
            "dNSHostName": "ca01.corp.local",
            "certificateTemplates": ["VulnTemplate", "AgentTemplate"],
            "sd": b64sd([sd.build_ace(rid(512), sd.GENERIC_ALL)]),
        },
        {"dn": PKI, "class": "pkiContainer", "sd": b64sd([sd.build_ace(rid(512), sd.GENERIC_ALL)])},
        {"dn": f"CN=NTAuthCertificates,{PKI}", "class": "pkiContainer", "sd": b64sd([sd.build_ace(rid(512), sd.GENERIC_ALL)])},
        {
            "dn": f"CN=corp-policy,CN=OID,{PKI}",
            "class": "msPKI-Enterprise-Oid",
            "displayName": "Corp Policy",
            "msPKI-Cert-Template-OID": "1.3.6.1.4.1.311.21.8.1.1",
            "msDS-OIDToGroupLink": "",
        },
        {"dn": f"CN=other.local,CN=System,{DN}", "class": "trustedDomain", "flatName": "OTHER", "sid": OTHER_SID},
    ]
    principals = {rid(r): {"name": f"CORP\\{sam}", "class": cls} for sam, (r, cls) in ACCOUNTS.items()}
    return {
        "format": "stools-ad/1",
        "collected_at": now.isoformat(),
        "collector": {"kind": "powershell", "version": "0.1", "host": "DC01", "account": "CORP\\auditor"},
        "domain": {
            "dns_root": "corp.local",
            "dn": DN,
            "netbios": "CORP",
            "sid": DOMAIN_SID,
            "configuration_dn": CONF_DN,
            "schema_dn": f"CN=Schema,{CONF_DN}",
            "machine_account_quota": 10,
            "functional_level": "2016",
        },
        "guids": {
            "extended_rights": {
                "DS-Replication-Get-Changes": GUID_GET_CHANGES,
                "DS-Replication-Get-Changes-All": GUID_GET_CHANGES_ALL,
                "DS-Replication-Get-Changes-In-Filtered-Set": GUID_GET_CHANGES_FILTERED,
                "Enroll": GUID_ENROLL,
                "AutoEnroll": GUID_AUTOENROLL,
            },
            "schema_attributes": {"msDS-KeyCredentialLink": GUID_KEYCRED},
        },
        "objects": objects,
        "sysvol": {
            f"CN={{31B2F340-016D-11D2-945F-00C04FB984F9}},CN=Policies,CN=System,{DN}": {
                "GptTmpl.inf": "[Unicode]\r\nUnicode=yes\r\n[Privilege Rights]\r\nSeDebugPrivilege = *S-1-5-32-544,*"
                + rid(1108)
                + "\r\nSeBackupPrivilege = *S-1-5-32-551\r\nSeShutdownPrivilege = *S-1-5-32-545\r\n"
            }
        },
        "principals": principals,
    }


def export_bytes(**kwargs: Any) -> bytes:
    return json.dumps(build_export(**kwargs), ensure_ascii=False).encode("utf-8")
