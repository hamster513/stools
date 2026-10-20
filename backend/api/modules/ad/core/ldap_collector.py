"""Онлайн-сборщик: та же выгрузка stools-ad/1, но по LDAP из контейнера.

Поиск абстрагирован функцией `search(base, filter, attributes, scope)`,
возвращающей записи `{dn, attributes, raw_attributes}` — так сборщик
проверяется без домена. Реальная реализация поверх ldap3 — `ldap3_searcher`.
"""
from __future__ import annotations

import base64
import datetime as dt
import errno
import re
import struct
import time
import uuid
from collections.abc import Callable, Iterable, Iterator
from typing import Any

from api.modules.ad.core import sd
from api.modules.ad.core.export import (
    CRITICAL_ACL_UNREAD,
    CRITICAL_BUILTIN_RIDS,
    CRITICAL_GROUP_NAMES,
    CRITICAL_GROUP_RIDS,
    FORMAT,
    WELL_KNOWN_SIDS,
    datetime_to_filetime,
)
from api.modules.ad.core.gpo_files import (
    GPO_FILES,
    MAX_GPO_FILE,
    keep_registry,
    parse_audit_csv,
    parse_gpp,
    parse_registry_pol,
    parse_scripts_ini,
    redact,
)

Entry = dict[str, Any]
Searcher = Callable[[str, str, list[str], str], Iterable[Entry]]
SmbReader = Callable[[str], bytes | None]
#: Папка UNC → имена файлов и папок в ней; None — только «папки нет» (ENOENT, ENOTDIR).
#: Любой другой отказ (нет доступа, таймаут) — исключение OSError: он не должен выглядеть как пустая папка.
SmbLister = Callable[[str], list[str] | None]

USER_ATTRS = [
    "sAMAccountName", "name", "objectSid", "userAccountControl", "lastLogonTimestamp", "pwdLastSet",
    "servicePrincipalName", "msDS-AllowedToDelegateTo", "msDS-SupportedEncryptionTypes", "adminCount",
    "altSecurityIdentities", "primaryGroupID", "sIDHistory", "whenCreated", "scriptPath", "userPrincipalName", "displayName",
]
#: DNS-имя и ОС компьютера — по ним Assets сопоставляет его с хостами других источников.
#: nTSecurityDescriptor последним: без ACL компьютеров список берётся без него.
COMPUTER_ATTRS = [
    *USER_ATTRS, "msDS-AllowedToActOnBehalfOfOtherIdentity", "dNSHostName", "operatingSystem", "operatingSystemVersion",
    "ms-DS-CreatorSID", "msDS-RevealOnDemandGroup", "msDS-NeverRevealGroup", "msDS-RevealedUsers", "msDS-KrbTgtLink",
    "nTSecurityDescriptor",
]
GROUP_ATTRS = ["sAMAccountName", "name", "objectSid", "member", "adminCount"]
TEMPLATE_ATTRS = [
    "cn", "displayName", "pKIExtendedKeyUsage", "msPKI-Enrollment-Flag", "msPKI-Certificate-Name-Flag",
    "msPKI-RA-Signature", "msPKI-Template-Schema-Version", "msPKI-Certificate-Policy",
    "msPKI-Certificate-Application-Policy", "msPKI-RA-Application-Policies", "msPKI-Cert-Template-OID",
    "nTSecurityDescriptor",
]
CA_ATTRS = ["cn", "dNSHostName", "certificateTemplates", "msPKI-Enrollment-Servers", "nTSecurityDescriptor", "cACertificate"]
#: Хранилища сертификатов ЦС под контейнером PKI: корневые и промежуточные (спека §5).
CA_STORES = {"Certification Authorities": "root", "AIA": "intermediate"}
OID_ATTRS = ["displayName", "msPKI-Cert-Template-OID", "msDS-OIDToGroupLink"]
EXTENDED_RIGHTS = ["DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All", "DS-Replication-Get-Changes-In-Filtered-Set", "Enroll", "AutoEnroll"]
PSO_ATTRS = [
    "name", "msDS-MinimumPasswordLength", "msDS-LockoutThreshold", "msDS-PasswordReversibleEncryptionEnabled",
    "msDS-PasswordComplexityEnabled", "msDS-PasswordSettingsPrecedence", "msDS-PSOAppliesTo",
]
LAPS_LEGACY = "ms-Mcs-AdmPwd"
LAPS = "msLAPS-Password"
LAPS_EXPIRY = {"ms-Mcs-AdmPwdExpirationTime": "lapsExpiry", "msLAPS-PasswordExpirationTime": "lapsNewExpiry"}
SMARTCARD_ROTATION = "msDS-ExpirePasswordsOnSmartCardOnlyAccounts"
EXCHANGE_STORAGE_GROUP = "msExchStorageGroup"
DMSA = "msDS-DelegatedManagedServiceAccount"
#: Имена схемы, которых может не быть (LAPS, Server 2016, Exchange, dMSA). ldap3 со схемой
#: отвергает запрос с неизвестным атрибутом целиком — такие атрибуты запрашиваются после проверки.
SCHEMA_OPTIONAL = [LAPS_LEGACY, *LAPS_EXPIRY, LAPS, SMARTCARD_ROTATION, EXCHANGE_STORAGE_GROUP, DMSA]
UNIX_PASSWORD_FILTER = "(&(objectCategory=person)(objectClass=user)(|(userPassword=*)(unixUserPassword=*)))"
#: dNSProperty: Id свойства DSPROPERTY_ZONE_ALLOW_UPDATE (MS-DNSP 2.3.2.1.1).
DNS_ZONE_ALLOW_UPDATE = 2
GPT_TMPL = "\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
#: Атрибуты привязки GPO у корня домена, OU и сайтов.
GPLINK_ATTRS = ["gPLink", "gPOptions"]
#: Рекурсивные члены группы (LDAP_MATCHING_RULE_IN_CHAIN), вложенные группы тоже.
IN_CHAIN = "1.2.840.113556.1.4.1941"
#: Дескрипторов участников одной критичной группы читается не больше — остальные в notes.
CRITICAL_MEMBERS_LIMIT = 5000
#: Код LDAP noSuchObject: базы поиска нет.
NO_SUCH_OBJECT = 32


class LdapResultError(RuntimeError):
    """Контроллер ответил на поиск кодом ошибки (busy, unavailable, timeLimitExceeded…).
    Такой ответ приходит без постраничного контрола — продолжать нельзя: выгрузка
    вышла бы без части объектов, а находки — без части нарушений."""

    def __init__(self, code: int, description: str, flt: str) -> None:
        self.code = code
        #: Для записи в notes, когда отказ раздела не прерывает сбор.
        self.reason = f"{description or 'ошибка'} ({code})"
        what = flt if len(flt) <= 60 else flt[:59] + "…"
        super().__init__(f"контроллер ответил {description or 'ошибкой'} ({code}) на поиске {what} — сбор прерван")


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


def _filetime(entry: Entry, attr: str) -> int | None:
    """Отметка времени AD (FILETIME). Со схемой (get_info=ALL) ldap3 отдаёт её уже
    датой, без схемы — строкой; исходные байты есть всегда, с них и читаем."""
    raw = _raw(entry, attr)
    if raw is not None:
        return _int(raw.decode("ascii", errors="replace"))
    value = _first(entry["attributes"].get(attr))
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.UTC)
        return max(datetime_to_filetime(value), 0)
    return _int(value)


def _raw_list(entry: Entry, attr: str) -> list[bytes]:
    value = (entry.get("raw_attributes") or {}).get(attr)
    if value is None:
        return []
    return [bytes(v) for v in (value if isinstance(value, list) else [value])]


def _b64_list(entry: Entry, attr: str) -> list[str]:
    return [base64.b64encode(v).decode() for v in _raw_list(entry, attr) if v]


def _bool(value: Any) -> bool | None:
    """Boolean AD: со схемой ldap3 отдаёт bool, без неё — строку TRUE/FALSE."""
    v = _first(value)
    if isinstance(v, bool):
        return v
    if isinstance(v, bytes | str):
        text = (v.decode("ascii", errors="replace") if isinstance(v, bytes) else v).upper()
        return True if text == "TRUE" else False if text == "FALSE" else None
    return None


def _gentime(entry: Entry, attr: str) -> str | None:
    """GeneralizedTime (whenCreated, whenChanged) → ISO UTC. Как и FILETIME, со схемой
    ldap3 отдаёт дату, без неё — строку; исходные байты есть всегда."""
    raw = _raw(entry, attr)
    value: Any = raw.decode("ascii", errors="replace") if raw is not None else _first(entry["attributes"].get(attr))
    if isinstance(value, dt.datetime):
        moment = value if value.tzinfo is not None else value.replace(tzinfo=dt.UTC)
    elif isinstance(value, str):
        try:
            moment = dt.datetime.strptime(value[:14], "%Y%m%d%H%M%S").replace(tzinfo=dt.UTC)
        except ValueError:
            return None
    else:
        return None
    return moment.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sids(entry: Entry, attr: str) -> list[str]:
    raw = _raw_list(entry, attr)
    if raw:
        return [sd.sid_to_str(v) for v in raw]
    return _list(entry["attributes"].get(attr))


def _texts(entry: Entry, attr: str) -> list[str]:
    """Строковые значения, которые ldap3 со схемой отдаёт байтами (DN-Binary)."""
    raw = _raw_list(entry, attr)
    if raw:
        return [v.decode("utf-8", errors="replace") for v in raw]
    value = entry["attributes"].get(attr)
    values = value if isinstance(value, list) else [] if value is None else [value]
    return [v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v) for v in values]


def _dn_binary(value: str) -> str:
    """DN-Binary `B:<длина>:<hex>:<DN>` → DN; в самом DN двоеточие допустимо."""
    parts = value.split(":", 3)
    return parts[3] if len(parts) == 4 and parts[0].upper() == "B" else value


_META_ITEM = re.compile(
    r"<pszAttributeName>\s*([^<]*?)\s*</pszAttributeName>.*?<ftimeLastOriginatingChange>\s*([^<]*?)\s*</ftimeLastOriginatingChange>",
    re.DOTALL,
)


def last_backup_from_metadata(values: list[str]) -> dt.datetime | None:
    """Время последней резервной копии домена: резервное копирование меняет dSASignature
    корня, время изменения берётся из msDS-ReplAttributeMetaData (XML на каждый атрибут)."""
    for value in values or []:
        m = _META_ITEM.search(value) if isinstance(value, str) else None
        if m is None or m.group(1) != "dSASignature":
            continue
        try:
            moment = dt.datetime.fromisoformat(m.group(2))
        except ValueError:
            return None
        return moment if moment.tzinfo is not None else moment.replace(tzinfo=dt.UTC)
    return None


def dns_allow_update(properties: list[bytes]) -> int | None:
    """Режим динамических обновлений зоны из dNSProperty: заголовок 20 байт
    (DataLength, NameLength, Flag, Version, Id), затем данные; 0 — нет, 1 — любые, 2 — безопасные."""
    for prop in properties or []:
        if not isinstance(prop, bytes | bytearray) or len(prop) < 20:
            continue
        length, prop_id = struct.unpack_from("<I", prop, 0)[0], struct.unpack_from("<I", prop, 16)[0]
        data = prop[20 : 20 + length]
        if prop_id == DNS_ZONE_ALLOW_UPDATE and data:
            return data[0]
    return None


def filter_value(value: str) -> str:
    """Значение для фильтра LDAP (RFC 4515): \\, *, (, ) и NUL — шестнадцатеричными кодами."""
    return "".join(f"\\{ord(c):02x}" if c in "\\*()\x00" else c for c in value)


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
        smb_lister: SmbLister | None = None,
        host: str = "",
        account: str = "",
        include_computer_sd: bool = True,
        notes: list[str] | None = None,
    ) -> None:
        self.search = search
        self.root = root_dse
        self.smb = smb_reader
        self.smb_list = smb_lister
        self.host = host
        self.account = account
        self.include_computer_sd = include_computer_sd
        self.notes = list(notes or [])
        self.principals: dict[str, dict[str, str]] = {}
        self._pending_sids: set[str] = set()

    # -- вспомогательное ---------------------------------------------------

    def _one(self, base: str, flt: str, attrs: list[str], scope: str = "SUBTREE", *, missing_ok: bool = False) -> Entry | None:
        for e in self._search_optional(base, flt, attrs, scope) if missing_ok else self.search(base, flt, attrs, scope):
            return e
        return None

    def _search_optional(self, base: str, flt: str, attrs: list[str], scope: str) -> Iterator[Entry]:
        """Поиск в базе, которой может не быть (шаблоны сертификатов без AD CS):
        noSuchObject — пустой ответ; любой другой код ошибки — отказ сбора."""
        try:
            yield from self.search(base, flt, attrs, scope)
        except LdapResultError as exc:
            if exc.code != NO_SUCH_OBJECT:
                raise

    def _read(self, failure: str, base: str, flt: str, attrs: list[str], scope: str) -> list[Entry] | None:
        """Необязательный раздел: нет базы — пустой список; любой отказ контроллера —
        запись «<failure>: <причина>» в notes и None («не прочитано»), сбор продолжается."""
        try:
            return list(self._search_optional(base, flt, attrs, scope))
        except LdapResultError as exc:
            self.notes.append(f"{failure}: {exc.reason}")
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

        root_attrs = [
            "objectSid", "ms-DS-MachineAccountQuota", "nTSecurityDescriptor", "msDS-Behavior-Version",
            "minPwdLength", "lockoutThreshold", "pwdProperties", "pwdHistoryLength", *GPLINK_ATTRS,
        ]
        root_obj = self._one(default_nc, "(objectClass=*)", root_attrs, "BASE", missing_ok=True)
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
            "min_pwd_length": _int(attrs.get("minPwdLength")),
            "lockout_threshold": _int(attrs.get("lockoutThreshold")),
            "pwd_properties": _int(attrs.get("pwdProperties")),
            "pwd_history_length": _int(attrs.get("pwdHistoryLength")),
        }
        schema_flt = "(|" + "".join(f"(lDAPDisplayName={n})" for n in SCHEMA_OPTIONAL) + ")"
        schema = self._read("схема не прочитана", schema_nc, schema_flt, ["lDAPDisplayName", "schemaIDGUID", "possSuperiors", "systemPossSuperiors"], "SUBTREE")
        in_schema = {str(_first(e["attributes"].get("lDAPDisplayName"))): e for e in schema or []}
        domain.update(self._domain_settings(default_nc, config_nc, in_schema if schema is not None else None))

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
        # Ключ есть — схема проверена; пустое значение — класса нет. Схема не прочитана — ключа нет.
        schema_classes: dict[str, str] = {}
        if schema is not None:
            dmsa_guid = _raw(in_schema[DMSA], "schemaIDGUID") if DMSA in in_schema else None
            schema_classes[DMSA] = str(uuid.UUID(bytes_le=dmsa_guid)) if dmsa_guid else ""

        objects: list[dict[str, Any]] = []
        root_sd = _raw(root_obj, "nTSecurityDescriptor")
        objects.append({"dn": default_nc, "class": "domainDNS", "sid": domain_sid, "sd": _b64(root_sd), **_gplink(attrs)})
        self._note_sd(root_sd)
        holder = self._one(f"CN=AdminSDHolder,CN=System,{default_nc}", "(objectClass=*)", ["nTSecurityDescriptor"], "BASE", missing_ok=True)
        if holder is not None:
            hsd = _raw(holder, "nTSecurityDescriptor")
            objects.append({"dn": holder["dn"], "class": "container", "sd": _b64(hsd)})
            self._note_sd(hsd)

        users = [self._account(e, "user", netbios, with_sd=False) for e in self.search(default_nc, "(&(objectCategory=person)(objectClass=user))", USER_ATTRS, "SUBTREE")]
        objects.extend(users)
        # Только наличие пароля: значения userPassword/unixUserPassword не запрашиваются.
        unix = self._read("Unix-пароли не проверены", default_nc, UNIX_PASSWORD_FILTER, ["sAMAccountName"], "SUBTREE")
        unix_dns = {e["dn"].lower() for e in unix or []}
        for u in users:
            if u["dn"].lower() in unix_dns:
                u["hasUnixPassword"] = True
        laps_attrs = [a for a in LAPS_EXPIRY if a in in_schema]
        comp_attrs = [*COMPUTER_ATTRS[:-1], *laps_attrs, *(COMPUTER_ATTRS[-1:] if self.include_computer_sd else [])]
        for e in self.search(default_nc, "(objectClass=computer)", comp_attrs, "SUBTREE"):
            objects.append(self._account(e, "computer", netbios, with_sd=self.include_computer_sd))
        for e in self.search(default_nc, "(objectClass=group)", GROUP_ATTRS, "SUBTREE"):
            a = e["attributes"]
            sid_ = _sid_str(a.get("objectSid"))
            sam = str(_first(a.get("sAMAccountName")) or "")
            objects.append({"dn": e["dn"], "class": "group", "sid": sid_, "sam": sam, "name": str(_first(a.get("name")) or sam), "member": _list(a.get("member")), "adminCount": _int(a.get("adminCount"))})
            self._register(sid_, f"{netbios}\\{sam}", "group")
        self._critical_acl(default_nc, domain_sid, objects)
        for e in self.search(default_nc, "(objectClass=organizationalUnit)", [*GPLINK_ATTRS, "nTSecurityDescriptor"], "SUBTREE"):
            ousd = _raw(e, "nTSecurityDescriptor")
            objects.append({"dn": e["dn"], "class": "organizationalUnit", "sd": _b64(ousd), **_gplink(e["attributes"])})
            self._note_sd(ousd)

        sysvol: dict[str, dict[str, str]] = {}
        # SYSVOL не читается (выключен или недоступен) — блока gpo нет, причина уже в notes.
        gpo: dict[str, dict[str, Any]] | None = {} if self.smb is not None else None
        for e in self.search(f"CN=Policies,CN=System,{default_nc}", "(objectClass=groupPolicyContainer)", ["displayName", "gPCFileSysPath", "flags", "nTSecurityDescriptor"], "SUBTREE"):
            a = e["attributes"]
            gsd = _raw(e, "nTSecurityDescriptor")
            path = str(_first(a.get("gPCFileSysPath")) or "")
            objects.append({
                "dn": e["dn"], "class": "groupPolicyContainer", "displayName": str(_first(a.get("displayName")) or ""),
                "gpcFileSysPath": path, "flags": _int(a.get("flags")), "sd": _b64(gsd),
            })
            self._note_sd(gsd)
            if gpo is not None and path:
                gpo[e["dn"]] = self._gpo_files(e["dn"], path, sysvol)

        pki = f"CN=Public Key Services,CN=Services,{config_nc}"
        for e in self._search_optional(f"CN=Certificate Templates,{pki}", "(objectClass=pKICertificateTemplate)", TEMPLATE_ATTRS, "SUBTREE"):
            a = e["attributes"]
            tsd = _raw(e, "nTSecurityDescriptor")
            objects.append(
                {
                    "dn": e["dn"],
                    "class": "pKICertificateTemplate",
                    "cn": str(_first(a.get("cn")) or ""),
                    "displayName": str(_first(a.get("displayName")) or ""),
                    "pKIExtendedKeyUsage": _list(a.get("pKIExtendedKeyUsage")),
                    "msPKI-Enrollment-Flag": _int(a.get("msPKI-Enrollment-Flag")),
                    "msPKI-Certificate-Name-Flag": _int(a.get("msPKI-Certificate-Name-Flag")),
                    "msPKI-RA-Signature": _int(a.get("msPKI-RA-Signature")),
                    "msPKI-Template-Schema-Version": _int(a.get("msPKI-Template-Schema-Version")),
                    "msPKI-Certificate-Policy": _list(a.get("msPKI-Certificate-Policy")),
                    "msPKI-Certificate-Application-Policy": _list(a.get("msPKI-Certificate-Application-Policy")),
                    "msPKI-RA-Application-Policies": _list(a.get("msPKI-RA-Application-Policies")),
                    "msPKI-Cert-Template-OID": _first(a.get("msPKI-Cert-Template-OID")),
                    "sd": _b64(tsd),
                }
            )
            self._note_sd(tsd)
        objects.extend(self._pki_objects(pki))
        objects.extend(self._trusts(default_nc))
        objects.extend(self._password_settings(default_nc))
        forest_nc = str(self.root.get("rootDomainNamingContext") or default_nc)
        objects.extend(self._dns_zones(default_nc, forest_nc))
        objects.extend(self._sites(config_nc))

        self._resolve_pending(default_nc, netbios)
        return {
            "format": FORMAT,
            "collected_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "collector": {"kind": "ldap", "version": "1.4", "host": self.host, "account": self.account, "notes": self.notes, "critical_acl": True},
            "domain": domain,
            "guids": {"extended_rights": ext, "schema_attributes": schema_attrs, "schema_classes": schema_classes},
            "objects": objects,
            "sysvol": sysvol,
            "principals": self.principals,
            **({"gpo": gpo} if gpo is not None else {}),
        }

    def _gpo_files(self, dn: str, base: str, sysvol: dict[str, dict[str, str]]) -> dict[str, Any]:
        """Файлы GPO из SYSVOL (спека §3.1): Registry.pol — по белому списку и без паролей,
        у GPP — только факт cpassword. Отказ на файле — строка в notes записи, сбор продолжается."""
        data: dict[str, Any] = {"registry": [], "gpp": [], "audit": [], "scripts": [], "acl": None, "notes": []}
        notes: list[str] = data["notes"]
        present = self._gpo_listing(base, notes)
        tmpl_rel = GPT_TMPL.lstrip("\\")
        content = self._gpo_file(base, tmpl_rel, present, notes)
        if content:
            try:
                sysvol[dn] = {"GptTmpl.inf": _decode_inf(content)}
            except ValueError as exc:
                notes.append(f"{tmpl_rel}: {exc}")
        for name, rel in GPO_FILES.items():
            content = self._gpo_file(base, rel, present, notes)
            if content is None:
                continue
            scope, file = name.split("/", 1)
            kind = file.lower()
            try:
                if kind.endswith(".pol"):
                    for v in parse_registry_pol(content):
                        if keep_registry(v.key, v.value):
                            v = redact(v)
                            data["registry"].append({"scope": scope, "key": v.key, "value": v.value, "type": v.type, "data": v.data})
                elif kind == "audit.csv":
                    data["audit"].extend(parse_audit_csv(_decode_inf(content)))
                elif kind.endswith(".ini"):
                    data["scripts"].extend(parse_scripts_ini(_decode_inf(content), scope))
                elif kind.endswith(".xml"):
                    data["gpp"].extend(parse_gpp(file, scope, _decode_inf(content)))
                else:
                    notes.append(f"{rel}: неизвестный тип файла")
            except ValueError as exc:
                notes.append(f"{rel}: {exc}")
        return data

    def _gpo_listing(self, base: str, notes: list[str]) -> set[str] | None:
        """Относительные пути (нижний регистр) файлов, которые показал листинг папки GPO;
        None — листинга нет, читаются все пути. Папка, которой нет у родителя, не листается."""
        if self.smb_list is None:
            return None
        lister = self.smb_list
        found: set[str] = set()

        def ls(rel: str) -> set[str] | None:
            try:
                names = lister(f"{base}\\{rel}")
            except OSError as exc:
                # Пропускается только эта папка; отмена сбора (не OSError) проходит насквозь.
                notes.append(f"{rel}: папка не прочитана по SMB ({exc.strerror or exc.__class__.__name__})")
                return set()
            if names is None:
                return None
            low = {n.lower() for n in names}
            found.update(f"{rel}\\{n}".lower() for n in low)
            return low

        tops = {part: ls(part) for part in ("Machine", "User")}
        if tops["Machine"] is None and tops["User"] is None:
            notes.append("папка GPO не прочитана по SMB: нет Machine и User")
        for part, top in tops.items():
            if not top:
                continue
            if "preferences" in top:
                kinds = ls(f"{part}\\Preferences") or set()
                for kind in sorted(_gpp_kinds(part)):
                    if kind.lower() in kinds:
                        ls(f"{part}\\Preferences\\{kind}")
            if "scripts" in top:
                ls(f"{part}\\Scripts")
        if "microsoft" in (tops["Machine"] or set()):
            ls("MACHINE\\Microsoft\\Windows NT\\SecEdit")
            ls("MACHINE\\Microsoft\\Windows NT\\Audit")
        return found

    def _gpo_file(self, base: str, rel: str, present: set[str] | None, notes: list[str]) -> bytes | None:
        """Байты файла GPO; None — файла нет, он не прочитан или больше потолка (последние два — в notes)."""
        if self.smb is None or (present is not None and rel.lower() not in present):
            return None
        content = self.smb(f"{base}\\{rel}")
        if content is None:
            # Без листинга «нет файла» и «не прочитан» не различить — пишется только для показанного листингом.
            if present is not None:
                notes.append(f"{rel}: не прочитан по SMB")
            return None
        if len(content) > MAX_GPO_FILE:
            notes.append(f"{rel}: файл больше {MAX_GPO_FILE // (1024 * 1024)} МБ, не разобран")
            return None
        return content

    def _critical_acl(self, default_nc: str, domain_sid: str, objects: list[dict[str, Any]]) -> None:
        """Дескрипторы критичных групп, их рекурсивных участников и учёток RID 500 и 502 —
        в поле sd уже собранных записей пользователей и групп."""
        by_dn = {o["dn"].lower(): o for o in objects if o["class"] in ("user", "group")}
        by_sid = {o["sid"]: o for o in by_dn.values() if o.get("sid")}
        names = {n.lower() for n in CRITICAL_GROUP_NAMES}
        groups = [by_sid.get(f"{domain_sid}-{r}") for r in CRITICAL_GROUP_RIDS] + [by_sid.get(f"S-1-5-32-{r}") for r in CRITICAL_BUILTIN_RIDS]
        groups += [o for o in by_dn.values() if o["class"] == "group" and (o.get("sam") or "").lower() in names]
        found = list({g["dn"].lower(): g for g in groups if g is not None}.values())
        accounts = [a for a in (by_sid.get(f"{domain_sid}-{r}") for r in (500, 502)) if a is not None]

        def attach(e: Entry) -> None:
            rec = by_dn.get(e["dn"].lower())
            raw = _raw(e, "nTSecurityDescriptor")
            if rec is not None and raw:
                rec["sd"] = _b64(raw)
                self._note_sd(raw)

        own = [o["sid"] for o in [*found, *accounts]]
        if own:
            flt = "(|" + "".join(f"(objectSid={s})" for s in own) + ")"
            for e in self._read(CRITICAL_ACL_UNREAD, default_nc, flt, ["nTSecurityDescriptor"], "SUBTREE") or []:
                attach(e)
        for g in found:
            label = g.get("sam") or g["dn"]
            try:
                for n, e in enumerate(self._search_optional(default_nc, f"(memberOf:{IN_CHAIN}:={filter_value(g['dn'])})", ["nTSecurityDescriptor"], "SUBTREE")):
                    if n == CRITICAL_MEMBERS_LIMIT:
                        self.notes.append(f"{CRITICAL_ACL_UNREAD} у части участников {label}: их больше {CRITICAL_MEMBERS_LIMIT}")
                        break
                    attach(e)
            except LdapResultError as exc:
                self.notes.append(f"{CRITICAL_ACL_UNREAD} (участники {label}): {exc.reason}")

    def _pki_objects(self, pki: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for e in self._search_optional(f"CN=Enrollment Services,{pki}", "(objectClass=pKIEnrollmentService)", CA_ATTRS, "SUBTREE"):
            a = e["attributes"]
            csd = _raw(e, "nTSecurityDescriptor")
            out.append(
                {
                    "dn": e["dn"],
                    "class": "pKIEnrollmentService",
                    "cn": str(_first(a.get("cn")) or ""),
                    "dNSHostName": str(_first(a.get("dNSHostName")) or ""),
                    "certificateTemplates": _list(a.get("certificateTemplates")),
                    "msPKI-Enrollment-Servers": _list(a.get("msPKI-Enrollment-Servers")),
                    "cACertificate": _b64_list(e, "cACertificate"),
                    "sd": _b64(csd),
                }
            )
            self._note_sd(csd)
        for scope in ("BASE", "LEVEL"):
            # cACertificate есть только у CN=NTAuthCertificates.
            for e in self._search_optional(pki, "(objectClass=*)", ["nTSecurityDescriptor", "cACertificate"], scope):
                psd = _raw(e, "nTSecurityDescriptor")
                rec: dict[str, Any] = {"dn": e["dn"], "class": "pkiContainer", "sd": _b64(psd)}
                if certs := _b64_list(e, "cACertificate"):
                    rec["cACertificate"] = certs
                out.append(rec)
                self._note_sd(psd)
        for container, store in CA_STORES.items():
            base = f"CN={container},{pki}"
            for e in self._read(f"сертификаты ЦС (CN={container}) не прочитаны", base, "(objectClass=certificationAuthority)", ["cn", "cACertificate"], "LEVEL") or []:
                cn = str(_first(e["attributes"].get("cn")) or "")
                out.append({"dn": e["dn"], "class": "certificationAuthority", "cn": cn, "store": store, "cACertificate": _b64_list(e, "cACertificate")})
        # На один уровень: сам контейнер CN=OID тоже класса msPKI-Enterprise-Oid и уже записан как pkiContainer.
        for e in self._search_optional(f"CN=OID,{pki}", "(objectClass=msPKI-Enterprise-Oid)", OID_ATTRS, "LEVEL"):
            a = e["attributes"]
            out.append(
                {
                    "dn": e["dn"],
                    "class": "msPKI-Enterprise-Oid",
                    "displayName": str(_first(a.get("displayName")) or ""),
                    "msPKI-Cert-Template-OID": _first(a.get("msPKI-Cert-Template-OID")),
                    "msDS-OIDToGroupLink": _first(a.get("msDS-OIDToGroupLink")),
                }
            )
        return out

    def _trusts(self, default_nc: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        trust_attrs = [
            "flatName", "securityIdentifier", "trustAttributes", "trustDirection", "trustType", "trustPartner", "whenChanged",
            "msDS-SupportedEncryptionTypes",
        ]
        for e in self._search_optional(f"CN=System,{default_nc}", "(objectClass=trustedDomain)", trust_attrs, "LEVEL"):
            a = e["attributes"]
            raw_sid = _raw(e, "securityIdentifier")
            out.append(
                {
                    "dn": e["dn"],
                    "class": "trustedDomain",
                    "flatName": str(_first(a.get("flatName")) or ""),
                    "sid": sd.sid_to_str(raw_sid) if raw_sid else None,
                    "trustAttributes": _int(a.get("trustAttributes")),
                    "trustDirection": _int(a.get("trustDirection")),
                    "trustType": _int(a.get("trustType")),
                    "trustPartner": _first(a.get("trustPartner")),
                    "whenChanged": _gentime(e, "whenChanged"),
                    "supportedEncryptionTypes": _int(a.get("msDS-SupportedEncryptionTypes")),
                }
            )
        return out

    def _domain_settings(self, default_nc: str, config_nc: str, in_schema: dict[str, Entry] | None) -> dict[str, Any]:
        """Настройки домена и леса вне корня домена. `in_schema` — найденные имена из
        SCHEMA_OPTIONAL; None — схема не прочитана, зависящие от неё поля тоже None."""
        ds = f"CN=Directory Service,CN=Windows NT,CN=Services,{config_nc}"
        out: dict[str, Any] = {}

        forest = self._read("функциональный уровень леса не прочитан", f"CN=Partitions,{config_nc}", "(objectClass=*)", ["msDS-Behavior-Version"], "BASE")
        level = _first(forest[0]["attributes"].get("msDS-Behavior-Version")) if forest else None
        out["forest_functional_level"] = str(level) if level is not None else None

        rb = self._read("корзина AD не прочитана", f"CN=Recycle Bin Feature,CN=Optional Features,{ds}", "(objectClass=*)", ["msDS-EnabledFeatureBL"], "BASE")
        if rb == []:
            self.notes.append("корзина AD не прочитана: объекта Recycle Bin Feature нет (лес старше Server 2008 R2)")
        out["recycle_bin"] = bool(_list(rb[0]["attributes"].get("msDS-EnabledFeatureBL"))) if rb else None

        dsh = self._read("dSHeuristics не прочитан", ds, "(objectClass=*)", ["dSHeuristics"], "BASE")
        out["ds_heuristics"] = str(_first(dsh[0]["attributes"].get("dSHeuristics")) or "") if dsh else None

        dfsr = self._read("способ репликации SYSVOL не определён", f"CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,{default_nc}", "(objectClass=*)", ["cn"], "BASE")
        out["sysvol_replication"] = None if dfsr is None else "dfsr" if dfsr else "ntfrs"

        # Метаданные репликации — конструируемый атрибут: отдаётся только по явному запросу.
        meta_attrs = ["msDS-ReplAttributeMetaData"]
        if in_schema is not None and SMARTCARD_ROTATION in in_schema:
            meta_attrs.append(SMARTCARD_ROTATION)
        meta = self._read("метаданные репликации корня домена не прочитаны", default_nc, "(objectClass=*)", meta_attrs, "BASE")
        values = [v.decode("utf-8", errors="replace") for v in _raw_list(meta[0], "msDS-ReplAttributeMetaData")] if meta else []
        if not values and meta:
            values = _list(meta[0]["attributes"].get("msDS-ReplAttributeMetaData"))
        backup = last_backup_from_metadata(values)
        out["last_backup"] = backup.strftime("%Y-%m-%dT%H:%M:%SZ") if backup else None
        out["backup_read"] = bool(values) if meta else None
        # Атрибута нет в схеме (лес старше Server 2016) или он не задан — ротация выключена.
        if in_schema is None:
            out["smartcard_rotation"] = None
        elif SMARTCARD_ROTATION not in in_schema:
            out["smartcard_rotation"] = False
        else:
            out["smartcard_rotation"] = bool(_bool(meta[0]["attributes"].get(SMARTCARD_ROTATION))) if meta else None

        if in_schema is None:
            out.update(laps_legacy_schema=None, laps_schema=None, schema_poss_superiors=None)
        else:
            out["laps_legacy_schema"] = LAPS_LEGACY in in_schema
            out["laps_schema"] = LAPS in in_schema
            storage = in_schema.get(EXCHANGE_STORAGE_GROUP)
            out["schema_poss_superiors"] = (
                {EXCHANGE_STORAGE_GROUP: _list(storage["attributes"].get("possSuperiors")) + _list(storage["attributes"].get("systemPossSuperiors"))}
                if storage is not None
                else {}
            )
        return out

    def _password_settings(self, default_nc: str) -> list[dict[str, Any]]:
        found = self._read("PSO не прочитаны", f"CN=Password Settings Container,CN=System,{default_nc}", "(objectClass=msDS-PasswordSettings)", PSO_ATTRS, "LEVEL")
        if found == []:
            self.notes.append("PSO не найдены: при сборе не администратором домена они не видны")
        out: list[dict[str, Any]] = []
        for e in found or []:
            a = e["attributes"]
            out.append(
                {
                    "dn": e["dn"],
                    "class": "msDS-PasswordSettings",
                    "name": str(_first(a.get("name")) or ""),
                    "psoMinLength": _int(a.get("msDS-MinimumPasswordLength")),
                    "psoLockoutThreshold": _int(a.get("msDS-LockoutThreshold")),
                    "psoReversible": _bool(a.get("msDS-PasswordReversibleEncryptionEnabled")),
                    "psoComplexity": _bool(a.get("msDS-PasswordComplexityEnabled")),
                    "psoPrecedence": _int(a.get("msDS-PasswordSettingsPrecedence")),
                    "psoAppliesTo": _list(a.get("msDS-PSOAppliesTo")),
                }
            )
        return out

    def _dns_zones(self, default_nc: str, forest_nc: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        bases = {
            "DomainDnsZones": f"DC=DomainDnsZones,{default_nc}",
            "ForestDnsZones": f"DC=ForestDnsZones,{forest_nc}",
            "System": f"CN=MicrosoftDNS,CN=System,{default_nc}",
        }
        for partition, base in bases.items():
            found = self._read(f"зоны DNS не прочитаны ({partition})", base, "(objectClass=dnsZone)", ["name", "dNSProperty", "nTSecurityDescriptor"], "SUBTREE")
            for e in found or []:
                zsd = _raw(e, "nTSecurityDescriptor")
                out.append(
                    {
                        "dn": e["dn"],
                        "class": "dnsZone",
                        "name": str(_first(e["attributes"].get("name")) or ""),
                        "partition": partition,
                        "allowUpdate": dns_allow_update(_raw_list(e, "dNSProperty")),
                        "sd": _b64(zsd),
                    }
                )
                self._note_sd(zsd)
        return out

    def _sites(self, config_nc: str) -> list[dict[str, Any]]:
        sites = self._read("сайты не прочитаны", f"CN=Sites,{config_nc}", "(objectClass=site)", ["name", *GPLINK_ATTRS], "LEVEL")
        subnets = self._read("подсети не прочитаны", f"CN=Subnets,CN=Sites,{config_nc}", "(objectClass=subnet)", ["name", "siteObject"], "LEVEL")
        out: list[dict[str, Any]] = [
            {"dn": e["dn"], "class": "site", "name": str(_first(e["attributes"].get("name")) or ""), **_gplink(e["attributes"])} for e in sites or []
        ]
        for e in subnets or []:
            a = e["attributes"]
            site = _first(a.get("siteObject"))
            out.append({"dn": e["dn"], "class": "subnet", "name": str(_first(a.get("name")) or ""), "site": str(site) if site else None})
        return out

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
            "lastLogonTimestamp": _filetime(e, "lastLogonTimestamp"),
            "pwdLastSet": _filetime(e, "pwdLastSet"),
            "spn": _list(a.get("servicePrincipalName")),
            "trustedForDelegation": bool(uac & 0x80000),
            "trustedToAuthForDelegation": bool(uac & 0x1000000),
            "allowedToDelegateTo": _list(a.get("msDS-AllowedToDelegateTo")),
            "supportedEncryptionTypes": _int(a.get("msDS-SupportedEncryptionTypes")),
            "adminCount": _int(a.get("adminCount")),
            "altSecurityIdentities": _list(a.get("altSecurityIdentities")),
            "primaryGroupID": _int(a.get("primaryGroupID")),
            "sIDHistory": _sids(e, "sIDHistory"),
            "whenCreated": _gentime(e, "whenCreated"),
            "scriptPath": _first(a.get("scriptPath")) or None,
            "userPrincipalName": _first(a.get("userPrincipalName")) or None,
            "displayName": _first(a.get("displayName")) or None,
        }
        if cls == "computer":
            for attr, field in LAPS_EXPIRY.items():
                rec[field] = _filetime(e, attr)
            rec["creatorSid"] = _sid_str(_raw(e, "ms-DS-CreatorSID") or a.get("ms-DS-CreatorSID"))
            rec["revealOnDemand"] = _list(a.get("msDS-RevealOnDemandGroup"))
            rec["neverReveal"] = _list(a.get("msDS-NeverRevealGroup"))
            # Значение на каждый раскрытый секрет учётки — DN повторяются.
            rec["revealedUsers"] = list(dict.fromkeys(_dn_binary(v) for v in _texts(e, "msDS-RevealedUsers")))
            rec["krbTgtLink"] = _first(a.get("msDS-KrbTgtLink"))
            rbcd = _raw(e, "msDS-AllowedToActOnBehalfOfOtherIdentity")
            rec["allowedToActOnBehalf"] = _b64(rbcd)
            self._note_sd(rbcd)
            for name in ("dNSHostName", "operatingSystem", "operatingSystemVersion"):
                rec[name] = str(_first(a.get(name)) or "")
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
                sam = _first(a.get("sAMAccountName"))
                classes = [c.lower() for c in _list(a.get("objectClass"))]
                # Запись foreignSecurityPrincipal — SID чужого домена в локальной группе, без имени:
                # не регистрируется, чтобы имя дал доверенный домен (ExportIndex.principal_name).
                if not sam or "foreignsecurityprincipal" in classes:
                    continue
                cls = "computer" if "computer" in classes else "group" if "group" in classes else "user"
                self._register(sid_, f"{netbios}\\{sam}", cls)


def _gplink(attrs: dict[str, Any]) -> dict[str, Any]:
    """gPLink без атрибута — пустая строка: сборщик ссылки читал, их нет (None — старый сборщик)."""
    return {"gpLink": str(_first(attrs.get("gPLink")) or ""), "gpOptions": _int(attrs.get("gPOptions"))}


def _gpp_kinds(part: str) -> set[str]:
    """Папки Preferences\\<вид>, файлы из которых читаются для части GPO (Machine или User)."""
    prefix = f"{part}\\Preferences\\".lower()
    return {rel.split("\\")[2] for rel in GPO_FILES.values() if rel.lower().startswith(prefix)}


def _decode_inf(content: bytes) -> str:
    if content[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return content.decode("utf-16")
    return content.decode("utf-8", errors="replace").lstrip("\ufeff")


# ---- Реальный транспорт ----------------------------------------------------


#: Умолчания подключения: щадят контроллер — страница меньше и пауза между запросами.
PAGE_SIZE_DEFAULT = 500
PAUSE_MS_DEFAULT = 500
PAGED_CONTROL = "1.2.840.113556.1.4.319"


class Pacer:
    """Дозатор запросов к контроллеру — один на сбор, общий для LDAP и SMB.

    Вызывается перед каждым запросом: перед первым в сборе — ничего, перед
    остальными — пауза `pause_ms` (если она не 0) и `check_cancel()`. Так пауза
    выдерживается и на стыке LDAP и SMB, а отмена замечается до следующего
    запроса и при нулевой паузе. Исключение из `check_cancel` прерывает сбор."""

    def __init__(
        self, pause_ms: int = PAUSE_MS_DEFAULT, *,
        check_cancel: Callable[[], None] | None = None, sleep: Callable[[float], None] | None = None,
    ) -> None:
        self.pause = pause_ms / 1000
        self.check_cancel = check_cancel
        self.sleep = sleep or time.sleep
        self.requests = 0

    def __call__(self) -> None:
        if self.requests:
            if self.pause > 0:
                self.sleep(self.pause)
            if self.check_cancel is not None:
                self.check_cancel()
        self.requests += 1


def ldap3_searcher(
    connection: Any,
    *,
    page_size: int = PAGE_SIZE_DEFAULT,
    pacer: Pacer | None = None,
    on_page: Callable[[int], None] | None = None,
) -> Searcher:
    """Постраничный поиск ldap3 с контролем SD_FLAGS (владелец и DACL; SACL не запрашивается — на него нужна привилегия).

    Страницы запрашиваются своей петлёй, а не `paged_search`: перед каждым
    запросом — страницей одного поиска или отдельным поиском (дозапросы имён
    по SID тоже) — `pacer()`: пауза и проверка отмены (`Pacer`). После каждой
    страницы — `on_page(прочитано всего)`: прогресс и проверка отмены.
    Исключение из них прерывает сбор до следующего запроса.
    Ответ контроллера с кодом ошибки — `LdapResultError`."""
    from ldap3 import BASE, LEVEL, SUBTREE
    from ldap3.core.exceptions import LDAPAttributeError, LDAPObjectClassError
    from ldap3.protocol.microsoft import security_descriptor_control

    scopes = {"BASE": BASE, "LEVEL": LEVEL, "SUBTREE": SUBTREE}
    before_request = pacer or Pacer()
    # По ссылкам (referrals) на другие серверы сбор не ходит: все базы поиска — разделы
    # этого контроллера (домен, конфигурация, схема). Прежний paged_search при включённом
    # auto_referrals открывал новое соединение к серверу из ссылки; здесь ссылки
    # пропускаются, а ответ-ссылка на саму базу (код 10) — ошибка сбора.
    connection.auto_referrals = False
    state = {"read": 0}

    def search(base: str, flt: str, attrs: list[str], scope: str) -> Iterable[Entry]:
        controls = security_descriptor_control(sdflags=0x05) if "nTSecurityDescriptor" in attrs else None
        cookie: bytes | None = None
        while True:
            before_request()
            try:
                connection.search(
                    base, flt, search_scope=scopes[scope], attributes=attrs, controls=controls, paged_size=page_size, paged_cookie=cookie,
                )
            except (LDAPAttributeError, LDAPObjectClassError) as exc:
                # ldap3 со схемой отвергает до отправки имя, которого нет в схеме контроллера (старый лес):
                # как ответ контроллера — необязательный раздел запишет note, а не прервёт сбор.
                raise LdapResultError(17, "undefinedAttributeType", flt) from exc
            result = connection.result or {}
            if result.get("result", 0) != 0:
                raise LdapResultError(int(result["result"]), str(result.get("description") or ""), flt)
            entries = [e for e in connection.response or [] if e.get("type") == "searchResEntry"]
            cookie = ((result.get("controls") or {}).get(PAGED_CONTROL) or {}).get("value", {}).get("cookie")
            state["read"] += len(entries)
            if on_page is not None:
                on_page(state["read"])
            for entry in entries:
                yield {"dn": entry["dn"], "attributes": entry.get("attributes") or {}, "raw_attributes": entry.get("raw_attributes") or {}}
            if not cookie:
                return

    return search


def paced_reader(read: SmbReader, pacer: Pacer) -> SmbReader:
    """Чтения SYSVOL идут через тот же дозатор, что и запросы LDAP: перед каждым — `pacer()`."""

    def paced(unc: str) -> bytes | None:
        pacer()
        return read(unc)

    return paced


def paced_lister(ls: SmbLister, pacer: Pacer) -> SmbLister:
    """Листинги папок SYSVOL — тоже запросы к контроллеру: перед каждым — `pacer()`."""

    def paced(unc: str) -> list[str] | None:
        pacer()
        return ls(unc)

    return paced


def smb_access(host: str, username: str, password: str, *, pacer: Pacer | None = None) -> tuple[SmbReader, SmbLister]:
    """Чтение файлов и листинг папок SYSVOL через smbprotocol; путь DFS переводится на
    контроллер домена, к которому уже подключились. Запросы — через дозатор сбора.
    Файл читается не больше MAX_GPO_FILE + 1 байт: превышение видно, а память не расходуется."""
    import smbclient

    smbclient.register_session(host, username=username, password=password)

    def local(unc: str) -> str:
        parts = unc.lstrip("\\").split("\\", 1)
        return f"\\\\{host}\\{parts[1]}" if len(parts) == 2 else unc

    def read(unc: str) -> bytes | None:
        try:
            with smbclient.open_file(local(unc), mode="rb") as fh:
                return bytes(fh.read(MAX_GPO_FILE + 1))
        except OSError:
            return None

    def ls(unc: str) -> list[str] | None:
        try:
            return [str(n) for n in smbclient.listdir(local(unc))]
        except OSError as exc:
            # SMBOSError — OSError с errno из NTSTATUS, но не подкласс FileNotFoundError: смотрим errno.
            if isinstance(exc, FileNotFoundError | NotADirectoryError) or exc.errno in (errno.ENOENT, errno.ENOTDIR):
                return None
            raise

    p = pacer or Pacer()
    return paced_reader(read, p), paced_lister(ls, p)


def smb_reader(host: str, username: str, password: str, *, pacer: Pacer | None = None) -> SmbReader:
    """Только чтение файлов SYSVOL (`smb_access` без листинга) — для прежних вызовов."""
    return smb_access(host, username, password, pacer=pacer)[0]
