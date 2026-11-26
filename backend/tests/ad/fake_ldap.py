"""Фальшивый LDAP: отдаёт записи из синтетической выгрузки по фильтру.

Разбирает только те фильтры, которыми пользуется сборщик; всё остальное —
пустой ответ, как у настоящего каталога на неизвестный запрос.
"""
from __future__ import annotations

import base64
import datetime as dt
import re
import struct
from collections.abc import Callable
from typing import Any

from api.modules.ad.core import sd
from api.modules.ad.core.ldap_collector import GPT_TMPL, LdapResultError
from tests.ad.synthetic import CONF_DN, DN, GUID_KEYCRED, PKI, b64sd, build_export, rid

_SID_FILTER = re.compile(r"\(objectSid=(S-[0-9-]+)\)")
_SCHEMA_FILTER = re.compile(r"\(lDAPDisplayName=([^)]+)\)")
_CHAIN_FILTER = re.compile(r"\(memberOf:1\.2\.840\.113556\.1\.4\.1941:=(.+)\)")
_DS = f"CN=Directory Service,CN=Windows NT,CN=Services,{CONF_DN}"
DDP_DN = f"CN={{31B2F340-016D-11D2-945F-00C04FB984F9}},CN=Policies,CN=System,{DN}"
DDP_PATH = "\\\\corp.local\\SysVol\\corp.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}"
DDCP_GUID = "{6AC1786C-016F-11D2-945F-00C04fB984F9}"
DDCP_DN = f"CN={DDCP_GUID},CN=Policies,CN=System,{DN}"
DC_OU = f"OU=Domain Controllers,{DN}"


def _uuid_bytes_le(text: str) -> bytes:
    import uuid

    return uuid.UUID(text).bytes_le


def _gentime(iso: str | None) -> list[bytes]:
    """Время в формате LDAP GeneralizedTime, как его отдаёт контроллер."""
    if not iso:
        return []
    return [dt.datetime.fromisoformat(iso).astimezone(dt.UTC).strftime("%Y%m%d%H%M%S.0Z").encode()]


def _bool(value: bool | None) -> str | None:
    return None if value is None else "TRUE" if value else "FALSE"


def sysvol_access(files: dict[str, bytes]) -> tuple[Callable[[str], bytes | None], Callable[[str], list[str] | None]]:
    """Фальшивый SYSVOL «полный путь UNC → байты»: чтение и листинг папки без учёта регистра, как у SMB.
    Листинг — имена файлов и папок на уровень ниже; нет такой папки — None."""
    by_path = {p.lower(): (p, d) for p, d in files.items()}

    def read(path: str) -> bytes | None:
        hit = by_path.get(path.lower())
        return hit[1] if hit else None

    def ls(path: str) -> list[str] | None:
        prefix = path.lower().rstrip("\\") + "\\"
        names = {orig[len(prefix):].split("\\", 1)[0] for low, (orig, _) in by_path.items() if low.startswith(prefix)}
        return sorted(names) if names else None

    return read, ls


def dns_property(prop_id: int, data: bytes) -> bytes:
    """Запись dNSProperty (MS-DNSP 2.3.2.1): DataLength, NameLength, Flag, Version, Id, Data."""
    return struct.pack("<IIIII", len(data), 0, 0, 1, prop_id) + data + b"\x00"


class FakeLdap:
    """`deny` — префиксы баз, поиск в которых отвергается кодом insufficientAccessRights."""

    def __init__(self, *, deny: tuple[str, ...] = ()) -> None:
        self.raw = build_export()
        self.objects = self.raw["objects"]
        self.deny = tuple(p.lower() for p in deny)
        # В настоящем AD сам контейнер CN=OID тоже класса msPKI-Enterprise-Oid.
        self.objects.append({"dn": f"CN=OID,{PKI}", "class": "msPKI-Enterprise-Oid", "sd": b64sd([sd.build_ace(rid(512), sd.GENERIC_ALL)])})
        d = self.raw["domain"]
        # Схема леса: LAPS только новый (Windows LAPS), атрибут смарт-карт Server 2016 есть, Exchange и dMSA нет.
        self.schema: dict[str, dict[str, Any]] = {
            "msDS-KeyCredentialLink": {"schemaIDGUID": [_uuid_bytes_le(GUID_KEYCRED)]},
            "msLAPS-Password": {},
            "msLAPS-PasswordExpirationTime": {},
            "msDS-ExpirePasswordsOnSmartCardOnlyAccounts": {},
        }
        #: Учётки с userPassword/unixUserPassword: значения фальшивый каталог не хранит.
        self.unix_password = {"user.noexpire"}
        # Служебные объекты конфигурации, которые сборщик читает по BASE.
        self.base_entries: dict[str, dict[str, Any]] = {
            f"CN=Partitions,{CONF_DN}": {"msDS-Behavior-Version": int(d["forest_functional_level"])},
            _DS: {"dSHeuristics": d["ds_heuristics"] or None},
            f"CN=Recycle Bin Feature,CN=Optional Features,{_DS}": {
                "msDS-EnabledFeatureBL": [f"CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,{CONF_DN}"] if d["recycle_bin"] else [],
            },
        }
        if d["sysvol_replication"] == "dfsr":
            self.base_entries[f"CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,{DN}"] = {"cn": "Domain System Volume"}
        # Привязка GPO, как в домене по умолчанию: Default Domain Policy на корне,
        # Default Domain Controllers Policy на OU контроллеров (файлов в SYSVOL у неё нет; без
        # дескриптора — иначе против эталонной выгрузки появится лишняя находка GpoPermissions).
        clean = b64sd([sd.build_ace(rid(512), sd.GENERIC_ALL), sd.build_ace("S-1-5-11", sd.READ_PROPERTY)])
        by_dn = {o["dn"]: o for o in self.objects}
        by_dn[DN].update(gpLink=f"[LDAP://{DDP_DN};0]", gpOptions=0)
        by_dn[DDP_DN]["flags"] = 0
        self.objects.append({"dn": DC_OU, "class": "organizationalUnit", "gpLink": f"[LDAP://{DDCP_DN};0]", "sd": clean})
        self.objects.append({
            "dn": DDCP_DN, "class": "groupPolicyContainer", "displayName": "Default Domain Controllers Policy",
            "gpcFileSysPath": f"\\\\corp.local\\SysVol\\corp.local\\Policies\\{DDCP_GUID}", "flags": 0,
        })
        #: SYSVOL: полный путь UNC → байты. GptTmpl.inf — в UTF-16 с BOM, как его пишет Windows.
        self.sysvol: dict[str, bytes] = {}
        for dn, files in self.raw["sysvol"].items():
            self.sysvol[by_dn[dn]["gpcFileSysPath"] + GPT_TMPL] = ("\ufeff" + files["GptTmpl.inf"]).encode("utf-16")

    def entry(self, o: dict[str, Any]) -> dict[str, Any]:
        attrs: dict[str, Any] = {
            "sAMAccountName": o.get("sam"),
            "name": o.get("name"),
            "objectSid": o.get("sid") if o["class"] != "trustedDomain" else None,
            "userAccountControl": o.get("uac"),
            "lastLogonTimestamp": o.get("lastLogonTimestamp"),
            "pwdLastSet": o.get("pwdLastSet"),
            "servicePrincipalName": o.get("spn", []),
            "msDS-AllowedToDelegateTo": o.get("allowedToDelegateTo", []),
            "msDS-SupportedEncryptionTypes": o.get("supportedEncryptionTypes"),
            "adminCount": o.get("adminCount"),
            "member": o.get("member", []),
            "displayName": o.get("displayName"),
            "gPCFileSysPath": o.get("gpcFileSysPath"),
            "pKIExtendedKeyUsage": o.get("pKIExtendedKeyUsage", []),
            "msPKI-Enrollment-Flag": o.get("msPKI-Enrollment-Flag"),
            "msPKI-Certificate-Name-Flag": o.get("msPKI-Certificate-Name-Flag"),
            "msPKI-RA-Signature": o.get("msPKI-RA-Signature"),
            "msPKI-Template-Schema-Version": o.get("msPKI-Template-Schema-Version"),
            "msPKI-Certificate-Policy": o.get("msPKI-Certificate-Policy", []),
            "msPKI-Certificate-Application-Policy": o.get("msPKI-Certificate-Application-Policy", []),
            "msPKI-RA-Application-Policies": o.get("msPKI-RA-Application-Policies", []),
            "msPKI-Cert-Template-OID": o.get("msPKI-Cert-Template-OID"),
            "cn": o.get("cn"),
            "dNSHostName": o.get("dNSHostName"),
            "operatingSystem": o.get("operatingSystem"),
            "operatingSystemVersion": o.get("operatingSystemVersion"),
            "certificateTemplates": o.get("certificateTemplates", []),
            "msPKI-Enrollment-Servers": o.get("msPKI-Enrollment-Servers", []),
            "msDS-OIDToGroupLink": o.get("msDS-OIDToGroupLink"),
            "flatName": o.get("flatName"),
            "trustAttributes": o.get("trustAttributes"),
            "altSecurityIdentities": o.get("altSecurityIdentities", []),
            "objectClass": ["top", o["class"]],
            "primaryGroupID": o.get("primaryGroupID"),
            "scriptPath": o.get("scriptPath"),
            "userPrincipalName": o.get("userPrincipalName"),
            "mail": o.get("mail"),
            "manager": o.get("manager"),
            "ms-Mcs-AdmPwdExpirationTime": o.get("lapsExpiry"),
            "msLAPS-PasswordExpirationTime": o.get("lapsNewExpiry"),
            "msDS-RevealOnDemandGroup": o.get("revealOnDemand", []),
            "msDS-NeverRevealGroup": o.get("neverReveal", []),
            "msDS-KrbTgtLink": o.get("krbTgtLink"),
            "trustDirection": o.get("trustDirection"),
            "trustType": o.get("trustType"),
            "trustPartner": o.get("trustPartner"),
            "siteObject": o.get("site"),
            "msDS-MinimumPasswordLength": o.get("psoMinLength"),
            "msDS-LockoutThreshold": o.get("psoLockoutThreshold"),
            "msDS-PasswordReversibleEncryptionEnabled": _bool(o.get("psoReversible")),
            "msDS-PasswordComplexityEnabled": _bool(o.get("psoComplexity")),
            "msDS-PasswordSettingsPrecedence": o.get("psoPrecedence"),
            "msDS-PSOAppliesTo": o.get("psoAppliesTo", []),
            "gPLink": o.get("gpLink"),
            "gPOptions": o.get("gpOptions"),
            "flags": o.get("flags"),
        }
        raw: dict[str, Any] = {}
        if o["class"] == "domainDNS":
            d = self.raw["domain"]
            attrs.update(
                {
                    "ms-DS-MachineAccountQuota": d["machine_account_quota"],
                    "minPwdLength": d.get("min_pwd_length"),
                    "lockoutThreshold": d.get("lockout_threshold"),
                    "pwdProperties": d.get("pwd_properties"),
                    "pwdHistoryLength": d.get("pwd_history_length"),
                    "msDS-ExpirePasswordsOnSmartCardOnlyAccounts": _bool(d.get("smartcard_rotation")),
                }
            )
            if d.get("last_backup"):
                stamp = dt.datetime.fromisoformat(d["last_backup"]).strftime("%Y-%m-%dT%H:%M:%SZ")
                raw["msDS-ReplAttributeMetaData"] = [
                    f"<DS_REPL_ATTR_META_DATA><pszAttributeName>{name}</pszAttributeName><dwVersion>1</dwVersion>"
                    f"<ftimeLastOriginatingChange>{when}</ftimeLastOriginatingChange></DS_REPL_ATTR_META_DATA>\x00".encode()
                    for name, when in (("objectClass", "2020-01-01T00:00:00Z"), ("dSASignature", stamp))
                ]
        for name in ("whenCreated", "whenChanged"):
            if o.get(name):
                raw[name] = _gentime(o[name])
        if o.get("revealedUsers"):
            # DN-Binary: B:<число символов>:<hex>:<DN>, по значению на каждый раскрытый секрет.
            # ldap3 со схемой отдаёт этот синтаксис байтами и в attributes.
            revealed = [f"B:8:{n:08x}:{dn}".encode() for dn in o["revealedUsers"] for n in (1, 2)]
            attrs["msDS-RevealedUsers"] = revealed
            raw["msDS-RevealedUsers"] = revealed
        if o.get("sIDHistory"):
            raw["sIDHistory"] = [sd.str_to_sid(s) for s in o["sIDHistory"]]
        if o.get("creatorSid"):
            raw["ms-DS-CreatorSID"] = [sd.str_to_sid(o["creatorSid"])]
        if o["class"] == "dnsZone" and o.get("allowUpdate") is not None:
            raw["dNSProperty"] = [dns_property(1, struct.pack("<I", 1)), dns_property(2, bytes([o["allowUpdate"]]))]
        if o.get("sd"):
            raw["nTSecurityDescriptor"] = [base64.b64decode(o["sd"])]
        if o.get("cACertificate"):
            raw["cACertificate"] = [base64.b64decode(c) for c in o["cACertificate"]]
        if o.get("allowedToActOnBehalf"):
            raw["msDS-AllowedToActOnBehalfOfOtherIdentity"] = [base64.b64decode(o["allowedToActOnBehalf"])]
        if o["class"] == "trustedDomain" and o.get("sid"):
            raw["securityIdentifier"] = [sd.str_to_sid(o["sid"])]
        return {"dn": o["dn"], "attributes": attrs, "raw_attributes": raw}

    def search(self, base: str, flt: str, attrs: list[str], scope: str) -> list[dict[str, Any]]:
        base_l = base.lower()
        if self.deny and base_l.startswith(self.deny):
            raise LdapResultError(50, "insufficientAccessRights", flt)
        if scope == "BASE":
            for o in self.objects:
                if o["dn"].lower() == base_l:
                    return [self.entry(o)]
            for dn, extra in self.base_entries.items():
                if dn.lower() == base_l:
                    return [{"dn": dn, "attributes": extra, "raw_attributes": {}}]
            return []
        if base_l.startswith("cn=partitions,"):
            return [{"dn": f"CN=CORP,{base}", "attributes": {"nETBIOSName": "CORP"}, "raw_attributes": {}}]
        if base_l.startswith("cn=extended-rights,"):
            m = re.match(r"\(displayName=(.+)\)", flt)
            name = m.group(1) if m else ""
            guid = self.raw["guids"]["extended_rights"].get(name)
            return [{"dn": f"CN={name},{base}", "attributes": {"rightsGuid": guid}, "raw_attributes": {}}] if guid else []
        if base_l.startswith("cn=schema,"):
            found = []
            for name in _SCHEMA_FILTER.findall(flt):
                if name in self.schema:
                    # Двоичные значения (schemaIDGUID) — в raw_attributes, как у ldap3.
                    rec = self.schema[name]
                    attrs_ = {"lDAPDisplayName": name, **{k: v for k, v in rec.items() if k != "schemaIDGUID"}}
                    raw_ = {k: v for k, v in rec.items() if k == "schemaIDGUID"}
                    found.append({"dn": f"CN={name},{base}", "attributes": attrs_, "raw_attributes": raw_})
            return found
        if "(userPassword=*)" in flt:
            return [{"dn": o["dn"], "attributes": {"sAMAccountName": o["sam"]}, "raw_attributes": {}} for o in self.objects if o.get("sam") in self.unix_password]
        chain = _CHAIN_FILTER.fullmatch(flt)
        if chain:
            group_dn = re.sub(r"\\([0-9a-f]{2})", lambda m: chr(int(m.group(1), 16)), chain.group(1))
            return [self.entry(o) for o in self.members_recursive(group_dn)]
        sids = _SID_FILTER.findall(flt)
        if sids:
            return [self.entry(o) for o in self.objects if o.get("sid") in sids]
        wanted = {
            "(&(objectCategory=person)(objectClass=user))": "user",
            "(objectClass=computer)": "computer",
            "(objectClass=group)": "group",
            "(objectClass=organizationalUnit)": "organizationalUnit",
            "(objectClass=groupPolicyContainer)": "groupPolicyContainer",
            "(objectClass=pKICertificateTemplate)": "pKICertificateTemplate",
            "(objectClass=pKIEnrollmentService)": "pKIEnrollmentService",
            "(objectClass=msPKI-Enterprise-Oid)": "msPKI-Enterprise-Oid",
            "(objectClass=certificationAuthority)": "certificationAuthority",
            "(objectClass=trustedDomain)": "trustedDomain",
            "(objectClass=msDS-PasswordSettings)": "msDS-PasswordSettings",
            "(objectClass=dnsZone)": "dnsZone",
            "(objectClass=site)": "site",
            "(objectClass=subnet)": "subnet",
            "(objectClass=*)": "*",
        }.get(flt)
        if wanted is None:
            return []

        def in_scope(dn: str) -> bool:
            if scope == "LEVEL":
                return dn.split(",", 1)[-1].lower() == base_l
            return dn.lower().endswith(base_l)

        return [self.entry(o) for o in self.objects if wanted in ("*", o["class"]) and in_scope(o["dn"])]

    def members_recursive(self, group_dn: str) -> list[dict[str, Any]]:
        """Как правило LDAP_MATCHING_RULE_IN_CHAIN: прямые и вложенные члены, группы тоже."""
        by_dn = {o["dn"].lower(): o for o in self.objects}
        out: dict[str, dict[str, Any]] = {}
        stack = list(by_dn.get(group_dn.lower(), {}).get("member", []))
        while stack:
            o = by_dn.get(stack.pop().lower())
            if o is None or o["dn"].lower() in out:
                continue
            out[o["dn"].lower()] = o
            stack.extend(o.get("member", []))
        return list(out.values())

    def root_dse(self) -> dict[str, str]:
        return {"defaultNamingContext": DN, "configurationNamingContext": CONF_DN, "schemaNamingContext": f"CN=Schema,{CONF_DN}", "rootDomainNamingContext": DN}

    def smb(self, path: str) -> bytes | None:
        return sysvol_access(self.sysvol)[0](path)

    def ls(self, path: str) -> list[str] | None:
        return sysvol_access(self.sysvol)[1](path)


def parse_ok(blob: str) -> bool:
    try:
        sd.parse_sd(base64.b64decode(blob))
        return True
    except ValueError:
        return False
