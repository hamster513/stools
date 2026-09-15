"""Фальшивый LDAP: отдаёт записи из синтетической выгрузки по фильтру.

Разбирает только те фильтры, которыми пользуется сборщик; всё остальное —
пустой ответ, как у настоящего каталога на неизвестный запрос.
"""
from __future__ import annotations

import base64
import re
from typing import Any

from api.modules.ad.core import sd
from tests.ad.synthetic import CONF_DN, DN, GUID_KEYCRED, build_export

_SID_FILTER = re.compile(r"\(objectSid=(S-[0-9-]+)\)")


def _uuid_bytes_le(text: str) -> bytes:
    import uuid

    return uuid.UUID(text).bytes_le


class FakeLdap:
    def __init__(self) -> None:
        self.raw = build_export()
        self.objects = self.raw["objects"]

    def entry(self, o: dict[str, Any]) -> dict[str, Any]:
        attrs: dict[str, Any] = {
            "sAMAccountName": o.get("sam"),
            "name": o.get("name"),
            "objectSid": o.get("sid"),
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
            "objectClass": ["top", o["class"]],
            "ms-DS-MachineAccountQuota": self.raw["domain"]["machine_account_quota"] if o["class"] == "domainDNS" else None,
        }
        raw: dict[str, Any] = {}
        if o.get("sd"):
            raw["nTSecurityDescriptor"] = [base64.b64decode(o["sd"])]
        if o.get("allowedToActOnBehalf"):
            raw["msDS-AllowedToActOnBehalfOfOtherIdentity"] = [base64.b64decode(o["allowedToActOnBehalf"])]
        return {"dn": o["dn"], "attributes": attrs, "raw_attributes": raw}

    def search(self, base: str, flt: str, attrs: list[str], scope: str) -> list[dict[str, Any]]:
        base_l = base.lower()
        if scope == "BASE":
            for o in self.objects:
                if o["dn"].lower() == base_l:
                    return [self.entry(o)]
            return []
        if base_l.startswith("cn=partitions,"):
            return [{"dn": f"CN=CORP,{base}", "attributes": {"nETBIOSName": "CORP"}, "raw_attributes": {}}]
        if base_l.startswith("cn=extended-rights,"):
            m = re.match(r"\(displayName=(.+)\)", flt)
            name = m.group(1) if m else ""
            guid = self.raw["guids"]["extended_rights"].get(name)
            return [{"dn": f"CN={name},{base}", "attributes": {"rightsGuid": guid}, "raw_attributes": {}}] if guid else []
        if base_l.startswith("cn=schema,"):
            return [{"dn": f"CN=ms-DS-Key-Credential-Link,{base}", "attributes": {}, "raw_attributes": {"schemaIDGUID": [_uuid_bytes_le(GUID_KEYCRED)]}}]
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
        }.get(flt)
        if wanted is None:
            return []
        return [self.entry(o) for o in self.objects if o["class"] == wanted and o["dn"].lower().endswith(base_l)]

    def root_dse(self) -> dict[str, str]:
        return {"defaultNamingContext": DN, "configurationNamingContext": CONF_DN, "schemaNamingContext": f"CN=Schema,{CONF_DN}"}

    def smb(self, path: str) -> bytes | None:
        for dn, files in self.raw["sysvol"].items():
            gpo = next(o for o in self.objects if o["dn"] == dn)
            if path.startswith(gpo["gpcFileSysPath"]):
                return ("﻿" + files["GptTmpl.inf"]).encode("utf-16")
        return None


def parse_ok(blob: str) -> bool:
    try:
        sd.parse_sd(base64.b64decode(blob))
        return True
    except ValueError:
        return False
