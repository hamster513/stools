"""Формат выгрузки `stools-ad/1` (спека §3) и индексы по ней.

Выгрузку дают два сборщика, анализатор видит только её. Всё, что нужно
проверкам сверх сырых атрибутов — рекурсивные члены групп, разбор
дескрипторов, имена SID, — считается здесь и кэшируется.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
from functools import cached_property
from pathlib import Path
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from api.export_files import GZIP_MAGIC
from api.modules.ad.core.sd import SecurityDescriptor, parse_sd
from kbaudit.safe_io import MB, decompress_gzip, decompress_gzip_file

FORMAT = "stools-ad/1"
#: Потолок распакованной выгрузки: сжатая загрузка ограничена 200 МБ,
#: но gzip разворачивается до ~1000:1 (аудит H2). Распакованные байты плюс
#: разобранный JSON должны помещаться в `mem_limit` контейнера API (STOOLS_API_MEM).
MAX_UNPACKED = 512 * MB

UAC_DISABLED = 0x2
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_DONT_REQ_PREAUTH = 0x400000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000

RID_DOMAIN_ADMINS = 512
RID_DOMAIN_USERS = 513
RID_DOMAIN_COMPUTERS = 515
RID_SCHEMA_ADMINS = 518
RID_ENTERPRISE_ADMINS = 519
RID_PROTECTED_USERS = 525
RID_KRBTGT = 502

WELL_KNOWN_SIDS: dict[str, str] = {
    "S-1-1-0": "Everyone",
    "S-1-3-0": "CREATOR OWNER",
    "S-1-5-7": "NT AUTHORITY\\ANONYMOUS LOGON",
    "S-1-5-9": "NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS",
    "S-1-5-10": "NT AUTHORITY\\SELF",
    "S-1-5-11": "NT AUTHORITY\\Authenticated Users",
    "S-1-5-18": "NT AUTHORITY\\SYSTEM",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
}

#: Имена RID-групп домена, если сборщик не положил их в principals.
DOMAIN_RID_NAMES: dict[int, str] = {
    512: "Domain Admins",
    513: "Domain Users",
    515: "Domain Computers",
    516: "Domain Controllers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    525: "Protected Users",
}


def _as_list(value: Any) -> Any:
    """ConvertTo-Json в PowerShell отдаёт пустой список как null, одиночный — скаляром."""
    if value is None:
        return []
    if isinstance(value, (str, int)):
        return [str(value)]
    if isinstance(value, dict) and not value:  # Windows PowerShell 5.1: пустой массив → {}
        return []
    return value


StrList = Annotated[list[str], BeforeValidator(_as_list)]


def _as_text(value: Any) -> Any:
    """Windows PowerShell 5.1 пишет строку из Get-Content -Raw как {"value": ..., "PSPath": ...}."""
    if isinstance(value, dict) and isinstance(value.get("value"), str):
        return value["value"]
    return value


Text = Annotated[str, BeforeValidator(_as_text)]


class AdObject(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    dn: str
    cls: str = Field(alias="class")
    sid: str | None = None
    sam: str | None = None
    name: str | None = None
    uac: int | None = None
    lastLogonTimestamp: int | None = None
    pwdLastSet: int | None = None
    spn: StrList = Field(default_factory=list)
    member: StrList = Field(default_factory=list)
    trustedForDelegation: bool = False
    trustedToAuthForDelegation: bool = False
    allowedToDelegateTo: StrList = Field(default_factory=list)
    allowedToActOnBehalf: str | None = None
    supportedEncryptionTypes: int | None = None
    adminCount: int | None = None
    displayName: str | None = None
    gpcFileSysPath: str | None = None
    pKIExtendedKeyUsage: StrList = Field(default_factory=list)
    enrollment_flag: int | None = Field(default=None, alias="msPKI-Enrollment-Flag")
    name_flag: int | None = Field(default=None, alias="msPKI-Certificate-Name-Flag")
    ra_signature: int | None = Field(default=None, alias="msPKI-RA-Signature")
    schema_version: int | None = Field(default=None, alias="msPKI-Template-Schema-Version")
    sd: str | None = None

    @property
    def enabled(self) -> bool:
        return not bool((self.uac or 0) & UAC_DISABLED)

    @property
    def label(self) -> str:
        return self.sam or self.name or self.dn

    @property
    def unconstrained_delegation(self) -> bool:
        return self.trustedForDelegation or bool((self.uac or 0) & UAC_TRUSTED_FOR_DELEGATION)

    @property
    def protocol_transition(self) -> bool:
        return self.trustedToAuthForDelegation or bool((self.uac or 0) & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)

    @property
    def rid(self) -> int | None:
        if not self.sid:
            return None
        try:
            return int(self.sid.rsplit("-", 1)[1])
        except ValueError:
            return None


class DomainInfo(BaseModel):
    dns_root: str = ""
    dn: str
    netbios: str = ""
    sid: str
    configuration_dn: str = ""
    schema_dn: str = ""
    machine_account_quota: int | None = None
    functional_level: str = ""


class CollectorInfo(BaseModel):
    kind: str = ""
    version: str = ""
    host: str = ""
    account: str = ""
    #: Что сборщик не смог или не стал читать — попадает в «не проверено».
    notes: list[str] = Field(default_factory=list)


class Guids(BaseModel):
    extended_rights: dict[str, str] = Field(default_factory=dict)
    schema_attributes: dict[str, str] = Field(default_factory=dict)


class Principal(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    cls: str = Field(default="", alias="class")


class AdExport(BaseModel):
    format: str
    collected_at: dt.datetime
    collector: CollectorInfo = Field(default_factory=CollectorInfo)
    domain: DomainInfo
    guids: Guids = Field(default_factory=Guids)
    objects: list[AdObject] = Field(default_factory=list)
    sysvol: dict[str, dict[str, Text]] = Field(default_factory=dict)
    principals: dict[str, Principal] = Field(default_factory=dict)


class ExportFormatError(ValueError):
    pass


def load_export(data: bytes | bytearray) -> AdExport:
    if data[:2] == GZIP_MAGIC:
        try:
            data = decompress_gzip(data, MAX_UNPACKED)
        except ValueError as exc:
            raise ExportFormatError(f"выгрузка не распакована: {exc}") from exc
    return _validated(_parsed(data))


def load_export_path(path: Path) -> AdExport:
    """Файл читается один раз, сжатый — распаковкой потоком с тем же потолком;
    текст освобождается до проверки модели, а не живёт рядом с объектами."""
    return _validated(_parsed(_read(path)))


def _read(path: Path) -> bytes | bytearray:
    with path.open("rb") as f:
        packed = f.read(2) == GZIP_MAGIC
        f.seek(0)
        if not packed:
            return f.read()
        try:
            return decompress_gzip_file(f, MAX_UNPACKED)
        except ValueError as exc:
            raise ExportFormatError(f"выгрузка не распакована: {exc}") from exc


def _parsed(data: bytes | bytearray) -> Any:
    try:
        return json.loads(data)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise ExportFormatError("файл не разобран как JSON выгрузки") from exc


def _validated(raw: Any) -> AdExport:
    if not isinstance(raw, dict) or raw.get("format") != FORMAT:
        raise ExportFormatError(f"это не выгрузка формата {FORMAT}: в файле «{(raw or {}).get('format') if isinstance(raw, dict) else '—'}»")
    try:
        return AdExport.model_validate(raw)
    except ValueError as exc:
        raise ExportFormatError("выгрузка неполная: " + _describe_validation(exc)) from exc


def _describe_validation(exc: ValueError) -> str:
    errors = getattr(exc, "errors", None)
    if errors is None:
        return str(exc).splitlines()[0][:200]
    items = errors()
    shown = "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in items[:3])
    first = items[0].get("input") if items else None
    sample = f"; значение первого поля ({type(first).__name__}): {first!r:.80}"
    return f"{len(items)} ошибок, первые: {shown}{sample}"[:500]


def filetime_to_datetime(value: int | None) -> dt.datetime | None:
    if not value or value <= 0:
        return None
    try:
        return dt.datetime(1601, 1, 1, tzinfo=dt.UTC) + dt.timedelta(microseconds=value // 10)
    except OverflowError:
        return None


def datetime_to_filetime(value: dt.datetime) -> int:
    return int((value - dt.datetime(1601, 1, 1, tzinfo=dt.UTC)).total_seconds() * 10_000_000)


class ExportIndex:
    """Ускорители для проверок; строится один раз на выгрузку."""

    def __init__(self, export: AdExport) -> None:
        self.export = export
        self.domain_sid = export.domain.sid
        self.by_dn: dict[str, AdObject] = {o.dn.lower(): o for o in export.objects}
        self.by_sid: dict[str, AdObject] = {o.sid: o for o in export.objects if o.sid}
        self.by_class: dict[str, list[AdObject]] = {}
        for o in export.objects:
            self.by_class.setdefault(o.cls, []).append(o)
        self._sd_cache: dict[str, SecurityDescriptor | None] = {}

    def objects(self, cls: str) -> list[AdObject]:
        return self.by_class.get(cls, [])

    def get(self, dn: str) -> AdObject | None:
        return self.by_dn.get(dn.lower())

    @cached_property
    def root(self) -> AdObject | None:
        return self.get(self.export.domain.dn)

    def domain_rid_sid(self, rid: int) -> str:
        return f"{self.domain_sid}-{rid}"

    def group_by_rid(self, rid: int) -> AdObject | None:
        return self.by_sid.get(self.domain_rid_sid(rid))

    def group_by_name(self, name: str) -> AdObject | None:
        needle = name.lower()
        for g in self.objects("group"):
            if (g.sam or "").lower() == needle or (g.name or "").lower() == needle:
                return g
        return None

    def members_recursive(self, group: AdObject) -> list[AdObject]:
        """Как Get-ADGroupMember -Recursive: пользователи и компьютеры, вложенные группы раскрыты."""
        seen: set[str] = set()
        out: list[AdObject] = []
        stack = [group]
        while stack:
            g = stack.pop()
            if g.dn.lower() in seen:
                continue
            seen.add(g.dn.lower())
            for dn in g.member:
                m = self.get(dn)
                if m is None:
                    continue
                if m.cls == "group":
                    stack.append(m)
                elif m.dn.lower() not in seen:
                    seen.add(m.dn.lower())
                    out.append(m)
        return out

    def principal_name(self, sid: str | None) -> str:
        """DOMAIN\\name для SID: из выгрузки, из well-known, иначе сам SID."""
        if not sid:
            return ""
        p = self.export.principals.get(sid)
        if p is not None and p.name:
            return p.name
        if sid in WELL_KNOWN_SIDS:
            return WELL_KNOWN_SIDS[sid]
        obj = self.by_sid.get(sid)
        if obj is not None:
            return f"{self.export.domain.netbios or self.export.domain.dns_root}\\{obj.label}"
        if sid.startswith(self.domain_sid + "-"):
            rid = int(sid.rsplit("-", 1)[1])
            if rid in DOMAIN_RID_NAMES:
                return f"{self.export.domain.netbios or self.export.domain.dns_root}\\{DOMAIN_RID_NAMES[rid]}"
        return sid

    def sd_of(self, obj: AdObject) -> SecurityDescriptor | None:
        key = obj.dn.lower()
        if key not in self._sd_cache:
            self._sd_cache[key] = parse_sd(base64.b64decode(obj.sd)) if obj.sd else None
        return self._sd_cache[key]

    def extended_right(self, name: str) -> str | None:
        return (self.export.guids.extended_rights.get(name) or "").lower() or None

    def schema_attribute(self, name: str) -> str | None:
        return (self.export.guids.schema_attributes.get(name) or "").lower() or None

    def gpo_inf(self, gpo: AdObject) -> str | None:
        files = self.export.sysvol.get(gpo.dn) or self.export.sysvol.get(gpo.dn.lower())
        return files.get("GptTmpl.inf") if files else None

    def to_dict(self) -> dict[str, Any]:
        return self.export.model_dump(by_alias=True, mode="json")
