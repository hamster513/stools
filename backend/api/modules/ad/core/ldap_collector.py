"""Онлайн-сборщик: та же выгрузка stools-ad/1, но по LDAP из контейнера.

Поиск абстрагирован функцией `search(base, filter, attributes, scope)`,
возвращающей записи `{dn, attributes, raw_attributes}` — так сборщик
проверяется без домена. Реальная реализация поверх ldap3 — `ldap3_searcher`.
"""
from __future__ import annotations

import base64
import datetime as dt
import time
import uuid
from collections.abc import Callable, Iterable
from typing import Any

from api.modules.ad.core import sd
from api.modules.ad.core.export import FORMAT, WELL_KNOWN_SIDS

Entry = dict[str, Any]
Searcher = Callable[[str, str, list[str], str], Iterable[Entry]]
SmbReader = Callable[[str], bytes | None]

USER_ATTRS = [
    "sAMAccountName", "name", "objectSid", "userAccountControl", "lastLogonTimestamp", "pwdLastSet",
    "servicePrincipalName", "msDS-AllowedToDelegateTo", "msDS-SupportedEncryptionTypes", "adminCount",
]
COMPUTER_ATTRS = [*USER_ATTRS, "msDS-AllowedToActOnBehalfOfOtherIdentity", "nTSecurityDescriptor"]
GROUP_ATTRS = ["sAMAccountName", "name", "objectSid", "member", "adminCount"]
TEMPLATE_ATTRS = [
    "displayName", "pKIExtendedKeyUsage", "msPKI-Enrollment-Flag", "msPKI-Certificate-Name-Flag",
    "msPKI-RA-Signature", "msPKI-Template-Schema-Version", "nTSecurityDescriptor",
]
EXTENDED_RIGHTS = ["DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All", "DS-Replication-Get-Changes-In-Filtered-Set", "Enroll", "AutoEnroll"]
GPT_TMPL = "\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"


def _first(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _int(value: Any) -> int | None:
    v = _first(value)
    if v is None or v == "":
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _raw(entry: Entry, attr: str) -> bytes | None:
    raw = entry.get("raw_attributes") or {}
    value = raw.get(attr)
    if isinstance(value, list):
        value = value[0] if value else None
    return bytes(value) if value else None


def _b64(data: bytes | None) -> str | None:
    return base64.b64encode(data).decode() if data else None


def _sid_str(value: Any) -> str | None:
    v = _first(value)
    if v is None:
        return None
    if isinstance(v, bytes | bytearray):
        return sd.sid_to_str(bytes(v))
    return str(v)


class LdapCollector:
    def __init__(
        self,
        search: Searcher,
        root_dse: dict[str, Any],
        *,
        smb_reader: SmbReader | None = None,
        host: str = "",
        account: str = "",
        include_computer_sd: bool = True,
    ) -> None:
        self.search = search
        self.root = root_dse
        self.smb = smb_reader
        self.host = host
        self.account = account
        self.include_computer_sd = include_computer_sd
        self.principals: dict[str, dict[str, str]] = {}
        self._pending_sids: set[str] = set()

    # -- вспомогательное ---------------------------------------------------

    def _one(self, base: str, flt: str, attrs: list[str], scope: str = "SUBTREE") -> Entry | None:
        for e in self.search(base, flt, attrs, scope):
            return e
        return None

    def _register(self, sid: str | None, name: str, cls: str) -> None:
        if sid and sid not in self.principals:
            self.principals[sid] = {"name": name, "class": cls}

    def _note_sd(self, data: bytes | None) -> None:
        if not data:
            return
        try:
            for ace in sd.parse_sd(data).dacl:
                if ace.sid not in self.principals and ace.sid not in WELL_KNOWN_SIDS:
                    self._pending_sids.add(ace.sid)
        except (ValueError, IndexError):
            pass

    # -- сбор -------------------------------------------------------------

    def collect(self) -> dict[str, Any]:
        default_nc = str(self.root["defaultNamingContext"])
        config_nc = str(self.root.get("configurationNamingContext") or f"CN=Configuration,{default_nc}")
        schema_nc = str(self.root.get("schemaNamingContext") or f"CN=Schema,{config_nc}")

        root_obj = self._one(default_nc, "(objectClass=*)", ["objectSid", "ms-DS-MachineAccountQuota", "nTSecurityDescriptor", "msDS-Behavior-Version"], "BASE")
        if root_obj is None:
            raise ValueError("корень домена не прочитан — проверьте base DN и права")
        attrs = root_obj["attributes"]
        domain_sid = _sid_str(attrs.get("objectSid")) or ""
        netbios = ""
        part = self._one(f"CN=Partitions,{config_nc}", f"(nCName={default_nc})", ["nETBIOSName"], "SUBTREE")
        if part is not None:
            netbios = str(_first(part["attributes"].get("nETBIOSName")) or "")
        dns_root = ".".join(p[3:] for p in default_nc.split(",") if p.upper().startswith("DC="))
        domain = {
            "dns_root": dns_root,
            "dn": default_nc,
            "netbios": netbios,
            "sid": domain_sid,
            "configuration_dn": config_nc,
            "schema_dn": schema_nc,
            "machine_account_quota": _int(attrs.get("ms-DS-MachineAccountQuota")),
            "functional_level": str(_first(attrs.get("msDS-Behavior-Version")) or ""),
        }

        ext: dict[str, str] = {}
        for name in EXTENDED_RIGHTS:
            e = self._one(f"CN=Extended-Rights,{config_nc}", f"(displayName={name})", ["rightsGuid"])
            if e is not None and _first(e["attributes"].get("rightsGuid")):
                ext[name] = str(_first(e["attributes"]["rightsGuid"]))
        schema_attrs: dict[str, str] = {}
        kc = self._one(schema_nc, "(lDAPDisplayName=msDS-KeyCredentialLink)", ["schemaIDGUID"])
        if kc is not None:
            raw_guid = _raw(kc, "schemaIDGUID")
            if raw_guid:
                schema_attrs["msDS-KeyCredentialLink"] = str(uuid.UUID(bytes_le=raw_guid))

        objects: list[dict[str, Any]] = []
        root_sd = _raw(root_obj, "nTSecurityDescriptor")
        objects.append({"dn": default_nc, "class": "domainDNS", "sid": domain_sid, "sd": _b64(root_sd)})
        self._note_sd(root_sd)
        holder = self._one(f"CN=AdminSDHolder,CN=System,{default_nc}", "(objectClass=*)", ["nTSecurityDescriptor"], "BASE")
        if holder is not None:
            hsd = _raw(holder, "nTSecurityDescriptor")
            objects.append({"dn": holder["dn"], "class": "container", "sd": _b64(hsd)})
            self._note_sd(hsd)

        for e in self.search(default_nc, "(&(objectCategory=person)(objectClass=user))", USER_ATTRS, "SUBTREE"):
            objects.append(self._account(e, "user", netbios, with_sd=False))
        comp_attrs = COMPUTER_ATTRS if self.include_computer_sd else COMPUTER_ATTRS[:-1]
        for e in self.search(default_nc, "(objectClass=computer)", comp_attrs, "SUBTREE"):
            objects.append(self._account(e, "computer", netbios, with_sd=self.include_computer_sd))
        for e in self.search(default_nc, "(objectClass=group)", GROUP_ATTRS, "SUBTREE"):
            a = e["attributes"]
            sid_ = _sid_str(a.get("objectSid"))
            sam = str(_first(a.get("sAMAccountName")) or "")
            objects.append({"dn": e["dn"], "class": "group", "sid": sid_, "sam": sam, "name": str(_first(a.get("name")) or sam), "member": _list(a.get("member")), "adminCount": _int(a.get("adminCount"))})
            self._register(sid_, f"{netbios}\\{sam}", "group")
        for e in self.search(default_nc, "(objectClass=organizationalUnit)", ["nTSecurityDescriptor"], "SUBTREE"):
            ousd = _raw(e, "nTSecurityDescriptor")
            objects.append({"dn": e["dn"], "class": "organizationalUnit", "sd": _b64(ousd)})
            self._note_sd(ousd)

        sysvol: dict[str, dict[str, str]] = {}
        for e in self.search(f"CN=Policies,CN=System,{default_nc}", "(objectClass=groupPolicyContainer)", ["displayName", "gPCFileSysPath", "nTSecurityDescriptor"], "SUBTREE"):
            a = e["attributes"]
            gsd = _raw(e, "nTSecurityDescriptor")
            path = str(_first(a.get("gPCFileSysPath")) or "")
            objects.append({"dn": e["dn"], "class": "groupPolicyContainer", "displayName": str(_first(a.get("displayName")) or ""), "gpcFileSysPath": path, "sd": _b64(gsd)})
            self._note_sd(gsd)
            if self.smb is not None and path:
                content = self.smb(path + GPT_TMPL)
                if content:
                    sysvol[e["dn"]] = {"GptTmpl.inf": _decode_inf(content)}

        tpl_base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_nc}"
        for e in self.search(tpl_base, "(objectClass=pKICertificateTemplate)", TEMPLATE_ATTRS, "SUBTREE"):
            a = e["attributes"]
            tsd = _raw(e, "nTSecurityDescriptor")
            objects.append(
                {
                    "dn": e["dn"],
                    "class": "pKICertificateTemplate",
                    "displayName": str(_first(a.get("displayName")) or ""),
                    "pKIExtendedKeyUsage": _list(a.get("pKIExtendedKeyUsage")),
                    "msPKI-Enrollment-Flag": _int(a.get("msPKI-Enrollment-Flag")),
                    "msPKI-Certificate-Name-Flag": _int(a.get("msPKI-Certificate-Name-Flag")),
                    "msPKI-RA-Signature": _int(a.get("msPKI-RA-Signature")),
                    "msPKI-Template-Schema-Version": _int(a.get("msPKI-Template-Schema-Version")),
                    "sd": _b64(tsd),
                }
            )
            self._note_sd(tsd)

        self._resolve_pending(default_nc, netbios)
        return {
            "format": FORMAT,
            "collected_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "collector": {"kind": "ldap", "version": "1.0", "host": self.host, "account": self.account},
            "domain": domain,
            "guids": {"extended_rights": ext, "schema_attributes": schema_attrs},
            "objects": objects,
            "sysvol": sysvol,
            "principals": self.principals,
        }

    def _account(self, e: Entry, cls: str, netbios: str, *, with_sd: bool) -> dict[str, Any]:
        a = e["attributes"]
        sid_ = _sid_str(a.get("objectSid"))
        sam = str(_first(a.get("sAMAccountName")) or "")
        uac = _int(a.get("userAccountControl")) or 0
        rec: dict[str, Any] = {
            "dn": e["dn"],
            "class": cls,
            "sid": sid_,
            "sam": sam,
            "name": str(_first(a.get("name")) or sam),
            "uac": uac,
            "lastLogonTimestamp": _int(a.get("lastLogonTimestamp")),
            "pwdLastSet": _int(a.get("pwdLastSet")),
            "spn": _list(a.get("servicePrincipalName")),
            "trustedForDelegation": bool(uac & 0x80000),
            "trustedToAuthForDelegation": bool(uac & 0x1000000),
            "allowedToDelegateTo": _list(a.get("msDS-AllowedToDelegateTo")),
            "supportedEncryptionTypes": _int(a.get("msDS-SupportedEncryptionTypes")),
            "adminCount": _int(a.get("adminCount")),
        }
        if cls == "computer":
            rbcd = _raw(e, "msDS-AllowedToActOnBehalfOfOtherIdentity")
            rec["allowedToActOnBehalf"] = _b64(rbcd)
            self._note_sd(rbcd)
            if with_sd:
                csd = _raw(e, "nTSecurityDescriptor")
                rec["sd"] = _b64(csd)
                self._note_sd(csd)
        self._register(sid_, f"{netbios}\\{sam}", cls)
        return rec

    def _resolve_pending(self, default_nc: str, netbios: str) -> None:
        """Имена для SID из ACE, которых нет среди выгруженных объектов
        (например, из другого домена леса или удалённые)."""
        pending = [s for s in self._pending_sids if s not in self.principals]
        for i in range(0, len(pending), 100):
            chunk = pending[i : i + 100]
            flt = "(|" + "".join(f"(objectSid={s})" for s in chunk) + ")"
            for e in self.search(default_nc, flt, ["sAMAccountName", "objectSid", "objectClass"], "SUBTREE"):
                a = e["attributes"]
                sid_ = _sid_str(a.get("objectSid"))
                classes = [c.lower() for c in _list(a.get("objectClass"))]
                cls = "computer" if "computer" in classes else "group" if "group" in classes else "user"
                self._register(sid_, f"{netbios}\\{_first(a.get('sAMAccountName')) or sid_}", cls)


def _decode_inf(content: bytes) -> str:
    if content[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return content.decode("utf-16")
    return content.decode("utf-8", errors="replace").lstrip("\ufeff")


# ---- Реальный транспорт ----------------------------------------------------


#: Умолчания подключения: щадят контроллер — страница меньше и пауза между запросами.
PAGE_SIZE_DEFAULT = 500
PAUSE_MS_DEFAULT = 500
PAGED_CONTROL = "1.2.840.113556.1.4.319"


def ldap3_searcher(
    connection: Any,
    *,
    page_size: int = PAGE_SIZE_DEFAULT,
    pause_ms: int = PAUSE_MS_DEFAULT,
    on_page: Callable[[int], None] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> Searcher:
    """Постраничный поиск ldap3 с контролем SD_FLAGS (только DACL).

    Страницы запрашиваются своей петлёй, а не `paged_search`: между любыми
    двумя запросами к контроллеру — страницами одного поиска и отдельными
    поисками (дозапросы имён по SID тоже) — пауза `pause_ms`; после последнего
    запроса паузы нет. После каждой страницы — `on_page(прочитано всего)`:
    прогресс и проверка отмены (исключение из него прерывает сбор до
    следующего запроса)."""
    from ldap3 import BASE, SUBTREE
    from ldap3.protocol.microsoft import security_descriptor_control

    scopes = {"BASE": BASE, "SUBTREE": SUBTREE}
    pause = pause_ms / 1000
    wait = sleep or time.sleep
    # Автопереход по ссылкам с постраничным поиском несовместим — ldap3 в paged_search выключает его так же.
    connection.auto_referrals = False
    state = {"requests": 0, "read": 0}

    def search(base: str, flt: str, attrs: list[str], scope: str) -> Iterable[Entry]:
        controls = security_descriptor_control(sdflags=0x04) if "nTSecurityDescriptor" in attrs else None
        cookie: bytes | None = None
        while True:
            if state["requests"] and pause > 0:
                wait(pause)
            state["requests"] += 1
            connection.search(
                base, flt, search_scope=scopes[scope], attributes=attrs, controls=controls, paged_size=page_size, paged_cookie=cookie,
            )
            entries = [e for e in connection.response or [] if e.get("type") == "searchResEntry"]
            cookie = (((connection.result or {}).get("controls") or {}).get(PAGED_CONTROL) or {}).get("value", {}).get("cookie")
            state["read"] += len(entries)
            if on_page is not None:
                on_page(state["read"])
            for entry in entries:
                yield {"dn": entry["dn"], "attributes": entry.get("attributes") or {}, "raw_attributes": entry.get("raw_attributes") or {}}
            if not cookie:
                return

    return search


def smb_reader(host: str, username: str, password: str) -> SmbReader:
    """Чтение файлов SYSVOL через smbprotocol; путь DFS переводится на
    контроллер домена, к которому уже подключились."""
    import smbclient

    smbclient.register_session(host, username=username, password=password)

    def read(unc: str) -> bytes | None:
        parts = unc.lstrip("\\").split("\\", 1)
        path = f"\\\\{host}\\{parts[1]}" if len(parts) == 2 else unc
        try:
            with smbclient.open_file(path, mode="rb") as fh:
                return bytes(fh.read())
        except OSError:
            return None

    return read
