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
from collections.abc import Callable, Iterable, Iterator
from typing import Any

from api.modules.ad.core import sd
from api.modules.ad.core.export import FORMAT, WELL_KNOWN_SIDS, datetime_to_filetime

Entry = dict[str, Any]
Searcher = Callable[[str, str, list[str], str], Iterable[Entry]]
SmbReader = Callable[[str], bytes | None]

USER_ATTRS = [
    "sAMAccountName", "name", "objectSid", "userAccountControl", "lastLogonTimestamp", "pwdLastSet",
    "servicePrincipalName", "msDS-AllowedToDelegateTo", "msDS-SupportedEncryptionTypes", "adminCount",
    "altSecurityIdentities",
]
COMPUTER_ATTRS = [*USER_ATTRS, "msDS-AllowedToActOnBehalfOfOtherIdentity", "nTSecurityDescriptor"]
GROUP_ATTRS = ["sAMAccountName", "name", "objectSid", "member", "adminCount"]
TEMPLATE_ATTRS = [
    "cn", "displayName", "pKIExtendedKeyUsage", "msPKI-Enrollment-Flag", "msPKI-Certificate-Name-Flag",
    "msPKI-RA-Signature", "msPKI-Template-Schema-Version", "msPKI-Certificate-Policy",
    "msPKI-Certificate-Application-Policy", "msPKI-RA-Application-Policies", "msPKI-Cert-Template-OID",
    "nTSecurityDescriptor",
]
CA_ATTRS = ["cn", "dNSHostName", "certificateTemplates", "msPKI-Enrollment-Servers", "nTSecurityDescriptor"]
OID_ATTRS = ["displayName", "msPKI-Cert-Template-OID", "msDS-OIDToGroupLink"]
EXTENDED_RIGHTS = ["DS-Replication-Get-Changes", "DS-Replication-Get-Changes-All", "DS-Replication-Get-Changes-In-Filtered-Set", "Enroll", "AutoEnroll"]
GPT_TMPL = "\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"
#: Код LDAP noSuchObject: базы поиска нет.
NO_SUCH_OBJECT = 32


class LdapResultError(RuntimeError):
    """Контроллер ответил на поиск кодом ошибки (busy, unavailable, timeLimitExceeded…).
    Такой ответ приходит без постраничного контрола — продолжать нельзя: выгрузка
    вышла бы без части объектов, а находки — без части нарушений."""

    def __init__(self, code: int, description: str, flt: str) -> None:
        self.code = code
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
        notes: list[str] | None = None,
    ) -> None:
        self.search = search
        self.root = root_dse
        self.smb = smb_reader
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

        root_obj = self._one(default_nc, "(objectClass=*)", ["objectSid", "ms-DS-MachineAccountQuota", "nTSecurityDescriptor", "msDS-Behavior-Version"], "BASE", missing_ok=True)
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
        holder = self._one(f"CN=AdminSDHolder,CN=System,{default_nc}", "(objectClass=*)", ["nTSecurityDescriptor"], "BASE", missing_ok=True)
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

        self._resolve_pending(default_nc, netbios)
        return {
            "format": FORMAT,
            "collected_at": dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "collector": {"kind": "ldap", "version": "1.0", "host": self.host, "account": self.account, "notes": self.notes},
            "domain": domain,
            "guids": {"extended_rights": ext, "schema_attributes": schema_attrs},
            "objects": objects,
            "sysvol": sysvol,
            "principals": self.principals,
        }

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
                    "sd": _b64(csd),
                }
            )
            self._note_sd(csd)
        for scope in ("BASE", "LEVEL"):
            for e in self._search_optional(pki, "(objectClass=*)", ["nTSecurityDescriptor"], scope):
                psd = _raw(e, "nTSecurityDescriptor")
                out.append({"dn": e["dn"], "class": "pkiContainer", "sd": _b64(psd)})
                self._note_sd(psd)
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
        for e in self._search_optional(f"CN=System,{default_nc}", "(objectClass=trustedDomain)", ["flatName", "securityIdentifier"], "SUBTREE"):
            raw_sid = _raw(e, "securityIdentifier")
            out.append(
                {
                    "dn": e["dn"],
                    "class": "trustedDomain",
                    "flatName": str(_first(e["attributes"].get("flatName")) or ""),
                    "sid": sd.sid_to_str(raw_sid) if raw_sid else None,
                }
            )
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
    """Постраничный поиск ldap3 с контролем SD_FLAGS (только DACL).

    Страницы запрашиваются своей петлёй, а не `paged_search`: перед каждым
    запросом — страницей одного поиска или отдельным поиском (дозапросы имён
    по SID тоже) — `pacer()`: пауза и проверка отмены (`Pacer`). После каждой
    страницы — `on_page(прочитано всего)`: прогресс и проверка отмены.
    Исключение из них прерывает сбор до следующего запроса.
    Ответ контроллера с кодом ошибки — `LdapResultError`."""
    from ldap3 import BASE, LEVEL, SUBTREE
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
        controls = security_descriptor_control(sdflags=0x04) if "nTSecurityDescriptor" in attrs else None
        cookie: bytes | None = None
        while True:
            before_request()
            connection.search(
                base, flt, search_scope=scopes[scope], attributes=attrs, controls=controls, paged_size=page_size, paged_cookie=cookie,
            )
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


def smb_reader(host: str, username: str, password: str, *, pacer: Pacer | None = None) -> SmbReader:
    """Чтение файлов SYSVOL через smbprotocol; путь DFS переводится на
    контроллер домена, к которому уже подключились. Чтения — через дозатор сбора (`paced_reader`)."""
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

    return paced_reader(read, pacer or Pacer())
