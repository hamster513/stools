"""Синтетический домен CORP с известными ответами на все 22 проверки.

Строится функцией, а не лежит файлом: тесты подкручивают отдельные
объекты (убрать ACE, добавить участника), чтобы проверить и отсутствие
находки, а не только её наличие.
"""
from __future__ import annotations

import base64
import datetime as dt
import functools
import json
import uuid
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.x509.oid import NameOID

from api.modules.ad.core import sd
from api.modules.ad.core.export import datetime_to_filetime

DOMAIN_SID = "S-1-5-21-1000-2000-3000"
DN = "DC=corp,DC=local"
CONF_DN = "CN=Configuration,DC=corp,DC=local"
PKI = f"CN=Public Key Services,CN=Services,{CONF_DN}"
OTHER_SID = "S-1-5-21-111-222-333"
#: Внешнее доверие (не домен леса): безопасные RID администраторов на него не распространяются.
EXT_SID = "S-1-5-21-444-555-666"
TRUST_WITHIN_FOREST = 0x20
TRUST_FOREST_TRANSITIVE = 0x8
TRUST_EXTERNAL = 0x4

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


@functools.cache
def rsa_key(bits: int = 2048, exponent: int = 65537) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(exponent, bits)


@functools.cache
def dsa_key() -> dsa.DSAPrivateKey:
    return dsa.generate_private_key(2048)


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _children(data: bytes) -> list[bytes]:
    """Элементы содержимого SEQUENCE в DER (теги однобайтовые) — целиком, с тегом и длиной."""
    out, i = [], 0
    while i < len(data):
        n, j = data[i + 1], i + 2
        if n & 0x80:
            k = n & 0x7F
            n, j = int.from_bytes(data[j:j + k], "big"), j + k
        out.append(data[i:j + n])
        i = j + n
    return out


def _body(tlv: bytes) -> bytes:
    """Содержимое TLV без тега и длины."""
    return tlv[2 + (tlv[1] & 0x7F if tlv[1] & 0x80 else 0):]


def _oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    out = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        while arc := arc >> 7:
            chunk.append(0x80 | (arc & 0x7F))
        out += bytes(reversed(chunk))
    return _tlv(0x06, bytes(out))


def with_signature_oid(der: bytes, dotted: str) -> bytes:
    """Подменяет алгоритм подписи (в tbsCertificate и снаружи) с пересчётом длин: подпись не сверяется,
    проверке важен только OID."""
    tbs, _, signature = _children(_body(der))
    alg = _tlv(0x30, _oid(dotted))
    fields = _children(_body(tbs))
    fields[2] = alg  # [0] version, serialNumber, signature
    return _tlv(0x30, _tlv(0x30, b"".join(fields)) + alg + signature)


def make_cert(
    cn: str = "CORP-CA", *, issuer: str | None = None, bits: int = 2048, exponent: int = 65537, use_dsa: bool = False,
    public_key: Any = None, sig_oid: str | None = None, not_after: dt.datetime = NOW + dt.timedelta(days=3650),
) -> bytes:
    """DER сертификата ЦС. Подпись SHA-1 и MD* библиотека не выпускает: `sig_oid` подставляется в готовый DER."""
    key: Any = dsa_key() if use_dsa else rsa_key(bits, exponent)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer or cn)]))
        .public_key(public_key or key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_after - dt.timedelta(days=7300))
        .not_valid_after(not_after)
    )
    der = builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    return with_signature_oid(der, sig_oid) if sig_oid else der


#: Чистый сертификат ЦС синтетического домена: RSA 2048, SHA-256, самоподписанный.
CA_CERT = base64.b64encode(make_cert()).decode()


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
            "whenCreated": (now - dt.timedelta(days=365)).isoformat(),
            "primaryGroupID": 513 if cls == "user" else 515,
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
            "gpLink": f"[LDAP://CN={{31B2F340-016D-11D2-945F-00C04FB984F9}},CN=Policies,CN=System,{DN};0]",
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
        acct("user.noexpire", uac=512 | 0x10000, hasUnixPassword=True),
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
            dNSHostName="ws01.corp.local",
            operatingSystem="Windows 11 Pro",
            operatingSystemVersion="10.0 (22631)",
        ),
        acct(
            "SRV01$",
            allowedToDelegateTo=["cifs/fs01.corp.local"],
            trustedToAuthForDelegation=True,
            uac=4096 | 0x1000000,
            sd=b64sd([sd.build_ace(rid(513), sd.GENERIC_ALL), sd.build_ace(rid(512), sd.GENERIC_ALL)]),
            dNSHostName="srv01.corp.local",
            operatingSystem="Windows Server 2022 Standard",
            operatingSystemVersion="10.0 (20348)",
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
            "cACertificate": [CA_CERT],
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
        {
            "dn": f"CN=other.local,CN=System,{DN}",
            "class": "trustedDomain",
            "flatName": "OTHER",
            "sid": OTHER_SID,
            "trustAttributes": TRUST_WITHIN_FOREST,
            "trustDirection": 3,
            "trustType": 2,
            "trustPartner": "other.local",
            "whenChanged": (now - dt.timedelta(days=10)).isoformat(),
            "supportedEncryptionTypes": 24,
        },
        {"dn": f"CN=ext.local,CN=System,{DN}", "class": "trustedDomain", "flatName": "EXT", "sid": EXT_SID, "trustAttributes": TRUST_EXTERNAL},
        {
            "dn": f"DC=corp.local,CN=MicrosoftDNS,DC=DomainDnsZones,{DN}",
            "class": "dnsZone",
            "name": "corp.local",
            "partition": "DomainDnsZones",
            "allowUpdate": 2,  # только безопасные динамические обновления
            "sd": b64sd([sd.build_ace(rid(512), sd.GENERIC_ALL), sd.build_ace("S-1-5-11", sd.READ_PROPERTY)]),
        },
        {"dn": f"CN=Default-First-Site-Name,CN=Sites,{CONF_DN}", "class": "site", "name": "Default-First-Site-Name"},
        {"dn": f"CN=10.0.0.0/24,CN=Subnets,CN=Sites,{CONF_DN}", "class": "subnet", "name": "10.0.0.0/24", "site": f"CN=Default-First-Site-Name,CN=Sites,{CONF_DN}"},
    ]
    principals = {rid(r): {"name": f"CORP\\{sam}", "class": cls} for sam, (r, cls) in ACCOUNTS.items()}
    return {
        "format": "stools-ad/1",
        "collected_at": now.isoformat(),
        "collector": {"kind": "powershell", "version": "0.1", "host": "DC01", "account": "CORP\\auditor", "critical_acl": True},
        "domain": {
            "dns_root": "corp.local",
            "dn": DN,
            "netbios": "CORP",
            "sid": DOMAIN_SID,
            "configuration_dn": CONF_DN,
            "schema_dn": f"CN=Schema,{CONF_DN}",
            "machine_account_quota": 10,
            "functional_level": "2016",
            "forest_functional_level": "7",
            "min_pwd_length": 12,
            "lockout_threshold": 5,
            "pwd_properties": 1,
            "recycle_bin": True,
            "ds_heuristics": "",
            "smartcard_rotation": True,
            "laps_legacy_schema": False,
            "laps_schema": True,
            "last_backup": (now - dt.timedelta(days=1)).isoformat(),
            "backup_read": True,
            "sysvol_replication": "dfsr",
            "schema_poss_superiors": {},
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
            "schema_classes": {"msDS-DelegatedManagedServiceAccount": ""},
        },
        "objects": objects,
        "sysvol": {
            f"CN={{31B2F340-016D-11D2-945F-00C04FB984F9}},CN=Policies,CN=System,{DN}": {
                "GptTmpl.inf": "[Unicode]\r\nUnicode=yes\r\n[Privilege Rights]\r\nSeDebugPrivilege = *S-1-5-32-544,*"
                + rid(1108)
                + "\r\nSeBackupPrivilege = *S-1-5-32-551\r\nSeShutdownPrivilege = *S-1-5-32-545\r\n"
            }
        },
        # Блок gpo, как у сборщика 2.2: у Default Domain Policy нет Registry.pol и настроек GPP, права SYSVOL прочитаны.
        "gpo": {f"CN={{31B2F340-016D-11D2-945F-00C04FB984F9}},CN=Policies,CN=System,{DN}": {"acl": []}},
        "principals": principals,
    }


def export_bytes(**kwargs: Any) -> bytes:
    return json.dumps(build_export(**kwargs), ensure_ascii=False).encode("utf-8")


def build_ca_data(*, now: dt.datetime = NOW, **overrides: Any) -> dict[str, Any]:
    """Файл `stools-ad-ca/1` для домена CORP: всё настроено безопасно."""
    data: dict[str, Any] = {
        "format": "stools-ad-ca/1",
        "collected_at": now.isoformat(),
        "collector": {"kind": "powershell", "version": "2.0", "host": "DC01", "account": "CORP\\auditor"},
        "domain": {"sid": DOMAIN_SID, "dns_root": "corp.local"},
        "sections": ["ca", "dc", "web"],
        "cas": [
            {
                "name": "CORP-CA",
                "host": "ca01.corp.local",
                "os_build": "20348",
                "edit_flags": 0x11014E,
                "interface_flags": 0x641,
                "disable_extension_list": [],
                # ManageCA | ManageCertificates
                "security": b64sd([sd.build_ace(rid(512), 0x1 | 0x2)]),
                "error": "",
            }
        ],
        "dcs": [
            {
                "host": "dc01.corp.local",
                "strong_binding": 2,
                "mapping_methods": 0x18,
                "lm_compatibility": 5,
                "no_lm_hash": 1,
                "ldap_integrity": 2,
                "ldap_channel_binding": 2,
                "tls": {"SSL 3.0": 0, "TLS 1.0": 0, "TLS 1.1": 0},
                "smb1": False,
                "smb_require_signing": True,
                "spooler": "disabled",
                "webclient": "absent",
                "last_boot": (now - dt.timedelta(days=10)).isoformat(),
                "os_build": "20348.2340",
                "registry_read": True,
                "cim_read": True,
                "error": "",
            }
        ],
        "web": [{"url": "http://ca01.corp.local/certsrv/", "status": 404, "auth": [], "error": ""}],
    }
    data.update(overrides)
    return data
