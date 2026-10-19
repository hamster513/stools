"""Формат выгрузки `stools-ad/1` (спека §3) и индексы по ней.

Выгрузку дают два сборщика, анализатор видит только её. Всё, что нужно
проверкам сверх сырых атрибутов — рекурсивные члены групп, разбор
дескрипторов, имена SID, — считается здесь и кэшируется.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import zlib
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field

from api.export_files import GZIP_MAGIC
from api.modules.ad.core.gpo_files import parse_gplink, parse_inf
from api.modules.ad.core.sd import SecurityDescriptor, parse_sd
from kbaudit.safe_io import MB, decompress_gzip, decompress_gzip_file

if TYPE_CHECKING:
    from api.modules.ad.core.ca_data import CaData

FORMAT = "stools-ad/1"
#: Потолок распакованной выгрузки: сжатая загрузка ограничена 200 МБ,
#: но gzip разворачивается до ~1000:1 (аудит H2). Распакованные байты плюс
#: разобранный JSON должны помещаться в `mem_limit` контейнера API (STOOLS_API_MEM).
MAX_UNPACKED = 512 * MB

UAC_DISABLED = 0x2
UAC_SERVER_TRUST_ACCOUNT = 0x2000
UAC_PARTIAL_SECRETS_ACCOUNT = 0x4000000
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

#: Критичные объекты (сборщики читают их дескрипторы, проверка CriticalObjectAcl — права на них):
#: группы домена Domain Admins, Cert Publishers, Schema Admins, Enterprise Admins, Group Policy Creator
#: Owners, Key Admins, Enterprise Key Admins, Allowed RODC Password Replication Group; встроенные
#: (S-1-5-32-<RID>) Administrators, Account, Server, Print, Backup Operators, Replicator; DnsAdmins по имени.
CRITICAL_GROUP_RIDS = (512, 517, 518, 519, 520, 526, 527, 571)
CRITICAL_BUILTIN_RIDS = (544, 548, 549, 550, 551, 552)
CRITICAL_GROUP_NAMES = ("DnsAdmins",)
#: Начало записи сборщика в notes об отказе чтения дескрипторов — по нему пробел в «Не проверено».
CRITICAL_ACL_UNREAD = "дескрипторы критичных объектов не прочитаны"

#: trustAttributes: доверенный домен — домен того же леса (MS-ADTS 6.1.6.7.9).
TRUST_ATTRIBUTE_WITHIN_FOREST = 0x20

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


def _as_obj_list(value: Any) -> Any:
    """Как _as_list, но для списка объектов: одиночный объект ConvertTo-Json отдаёт без массива."""
    if value is None or (isinstance(value, dict) and not value):
        return []
    return [value] if isinstance(value, dict) else value


def _utc_if_naive(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=dt.UTC)


#: Время без пояса — UTC.
UtcTime = Annotated[dt.datetime, AfterValidator(_utc_if_naive)]


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
    cn: str | None = None
    issuance_policies: StrList = Field(default_factory=list, alias="msPKI-Certificate-Policy")
    application_policies: StrList = Field(default_factory=list, alias="msPKI-Certificate-Application-Policy")
    ra_application_policies: StrList = Field(default_factory=list, alias="msPKI-RA-Application-Policies")
    template_oid: str | None = Field(default=None, alias="msPKI-Cert-Template-OID")
    dNSHostName: str | None = None
    operatingSystem: str | None = None
    operatingSystemVersion: str | None = None
    certificateTemplates: StrList = Field(default_factory=list)
    enrollment_servers: StrList = Field(default_factory=list, alias="msPKI-Enrollment-Servers")
    oid_group_link: str | None = Field(default=None, alias="msDS-OIDToGroupLink")
    flatName: str | None = None
    trustAttributes: int | None = None
    altSecurityIdentities: StrList = Field(default_factory=list)
    # Сертификаты ЦС (DER в base64): у pKIEnrollmentService, NTAuthCertificates и certificationAuthority;
    # у certificationAuthority — хранилище: root (CN=Certification Authorities) или intermediate (CN=AIA).
    cACertificate: StrList = Field(default_factory=list)
    store: str | None = None
    sd: str | None = None
    # Учётные записи.
    primaryGroupID: int | None = None
    sIDHistory: StrList = Field(default_factory=list)
    whenCreated: UtcTime | None = None
    scriptPath: str | None = None
    hasUnixPassword: bool = False
    # Компьютеры: срок пароля LAPS (FILETIME), создатель учётки; у RODC — списки кэширования паролей.
    lapsExpiry: int | None = None
    lapsNewExpiry: int | None = None
    creatorSid: str | None = None
    revealOnDemand: StrList = Field(default_factory=list)
    neverReveal: StrList = Field(default_factory=list)
    revealedUsers: StrList = Field(default_factory=list)
    krbTgtLink: str | None = None
    # Доверия.
    trustDirection: int | None = None
    trustType: int | None = None
    trustPartner: str | None = None
    whenChanged: UtcTime | None = None
    # Зоны DNS.
    partition: str | None = None
    allowUpdate: int | None = None
    # Подсети: DN сайта.
    site: str | None = None
    # PSO (msDS-PasswordSettings).
    psoMinLength: int | None = None
    psoLockoutThreshold: int | None = None
    psoReversible: bool | None = None
    psoComplexity: bool | None = None
    psoPrecedence: int | None = None
    psoAppliesTo: StrList = Field(default_factory=list)
    # Привязка GPO: у domainDNS, organizationalUnit, site — gPLink и gPOptions; у GPO — flags
    # (1 — выключена пользовательская часть, 2 — компьютерная).
    gpLink: str | None = None
    gpOptions: int | None = None
    flags: int | None = None

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
    def rdn_value(self) -> str:
        """cn, а без него — значение первого RDN из dn (экранирование не снимается)."""
        return self.cn or self.dn.split(",", 1)[0].partition("=")[2]

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
    # Новые поля: None — «не прочитано» (выгрузка старого сборщика или отказ чтения раздела).
    forest_functional_level: str | None = None
    min_pwd_length: int | None = None
    lockout_threshold: int | None = None
    pwd_properties: int | None = None
    pwd_history_length: int | None = None
    recycle_bin: bool | None = None
    #: Пустая строка — dSHeuristics не задан.
    ds_heuristics: str | None = None
    smartcard_rotation: bool | None = None
    laps_legacy_schema: bool | None = None
    laps_schema: bool | None = None
    last_backup: UtcTime | None = None
    #: Метаданные репликации корня прочитаны: с last_backup=None значит «бэкапа не было».
    backup_read: bool | None = None
    #: "dfsr" | "ntfrs".
    sysvol_replication: str | None = None
    schema_poss_superiors: dict[str, list[str]] | None = None


class CollectorInfo(BaseModel):
    kind: str = ""
    version: str = ""
    host: str = ""
    account: str = ""
    #: Что сборщик не смог или не стал читать — попадает в «не проверено».
    notes: list[str] = Field(default_factory=list)
    #: Сборщик читает дескрипторы критичных групп, их участников и учёток RID 500 и 502.
    critical_acl: bool = False


class Guids(BaseModel):
    extended_rights: dict[str, str] = Field(default_factory=dict)
    schema_attributes: dict[str, str] = Field(default_factory=dict)
    #: Класс → GUID; пустая строка — класса в схеме нет; ключа нет — не проверялось.
    schema_classes: dict[str, str] = Field(default_factory=dict)


class Principal(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    cls: str = Field(default="", alias="class")


class GpoRegistry(BaseModel):
    scope: str
    key: str
    value: str
    type: int
    data: str | int | list[str] | None = None


class GppMember(BaseModel):
    name: str = ""
    sid: str = ""
    action: str = ""


class GppItem(BaseModel):
    scope: str
    file: str
    kind: str
    name: str = ""
    user: str = ""
    #: Факт наличия cpassword; само значение сборщик не передаёт.
    cpassword: bool = False
    action: str = ""
    members: Annotated[list[GppMember], BeforeValidator(_as_obj_list)] = Field(default_factory=list)
    group_sid: str = ""
    group_name: str = ""
    path: str = ""


class GpoAudit(BaseModel):
    #: GUID подкатегории в нижнем регистре, без скобок.
    subcategory: str
    #: 0 — нет, 1 — успех, 2 — отказ, 3 — оба.
    setting: int


class GpoScript(BaseModel):
    scope: str
    phase: str
    command: str
    parameters: str = ""


class GpoAcl(BaseModel):
    path: str
    #: SID, кроме владельца, с правом записи.
    writers: StrList = Field(default_factory=list)


class GpoData(BaseModel):
    registry: Annotated[list[GpoRegistry], BeforeValidator(_as_obj_list)] = Field(default_factory=list)
    gpp: Annotated[list[GppItem], BeforeValidator(_as_obj_list)] = Field(default_factory=list)
    audit: Annotated[list[GpoAudit], BeforeValidator(_as_obj_list)] = Field(default_factory=list)
    scripts: Annotated[list[GpoScript], BeforeValidator(_as_obj_list)] = Field(default_factory=list)
    #: None — права не собирались (LDAP-сборщик или отказ Get-Acl).
    acl: Annotated[list[GpoAcl], BeforeValidator(_as_obj_list)] | None = None
    notes: StrList = Field(default_factory=list)


class AdExport(BaseModel):
    format: str
    collected_at: dt.datetime
    collector: CollectorInfo = Field(default_factory=CollectorInfo)
    domain: DomainInfo
    guids: Guids = Field(default_factory=Guids)
    objects: list[AdObject] = Field(default_factory=list)
    sysvol: dict[str, dict[str, Text]] = Field(default_factory=dict)
    principals: dict[str, Principal] = Field(default_factory=dict)
    #: DN GPO → файлы из SYSVOL; None — блока нет (старый сборщик или SYSVOL не прочитан).
    gpo: dict[str, GpoData] | None = None


class ExportFormatError(ValueError):
    pass


#: Превышение потолка — ValueError; битый заголовок — OSError, обрыв — EOFError,
#: битый поток deflate — zlib.error (он не OSError).
_GZIP_ERRORS = (ValueError, OSError, EOFError, zlib.error)


def _unpack_error(exc: BaseException) -> ExportFormatError:
    """Текст превышения потолка русский и с лимитом; тексты zlib и gzip — нет."""
    reason = str(exc) if type(exc) is ValueError else "сжатый файл повреждён или обрезан"
    return ExportFormatError(f"выгрузка не распакована: {reason}")


def load_export(data: bytes | bytearray) -> AdExport:
    if data[:2] == GZIP_MAGIC:
        try:
            data = decompress_gzip(data, MAX_UNPACKED)
        except _GZIP_ERRORS as exc:
            raise _unpack_error(exc) from exc
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
        except _GZIP_ERRORS as exc:
            raise _unpack_error(exc) from exc


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
        raise ExportFormatError("выгрузка неполная: " + describe_validation(exc)) from exc


def describe_validation(exc: ValueError) -> str:
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


@dataclass(frozen=True)
class GpoLink:
    container_dn: str
    enforced: bool
    disabled: bool


#: GPO.flags: выключена компьютерная часть.
GPO_FLAG_MACHINE_DISABLED = 2
_LINK_CONTAINERS = ("domainDNS", "organizationalUnit", "site")


class ExportIndex:
    """Ускорители для проверок; строится один раз на выгрузку."""

    def __init__(self, export: AdExport, ca: CaData | None = None) -> None:
        self.export = export
        #: Данные ЦС домена (самые свежие разделы); None — не загружались.
        self.ca = ca
        self.domain_sid = export.domain.sid
        self.by_dn: dict[str, AdObject] = {o.dn.lower(): o for o in export.objects}
        # У объекта доверия в sid — SID чужого домена, это не учётная запись.
        self.by_sid: dict[str, AdObject] = {o.sid: o for o in export.objects if o.sid and o.cls != "trustedDomain"}
        self.by_class: dict[str, list[AdObject]] = {}
        for o in export.objects:
            self.by_class.setdefault(o.cls, []).append(o)
        self._sd_cache: dict[str, SecurityDescriptor | None] = {}
        #: Производные списки проверок (админы, защищённые объекты) — считаются один раз на выгрузку.
        self.cache: dict[Any, Any] = {}

    def objects(self, cls: str) -> list[AdObject]:
        return self.by_class.get(cls, [])

    def get(self, dn: str) -> AdObject | None:
        return self.by_dn.get(dn.lower())

    @cached_property
    def root(self) -> AdObject | None:
        return self.get(self.export.domain.dn)

    @cached_property
    def trusted_domains(self) -> dict[str, str]:
        """SID доверенного домена → его NetBIOS-имя."""
        return {o.sid: o.flatName for o in self.objects("trustedDomain") if o.sid and o.flatName}

    @cached_property
    def forest_domain_sids(self) -> set[str] | None:
        """SID доменов своего леса: свой и доверия с TRUST_ATTRIBUTE_WITHIN_FOREST.
        None — состав леса неизвестен: доверий в выгрузке нет или у них нет
        trustAttributes (выгрузка старого сборщика)."""
        trusts = self.objects("trustedDomain")
        if not trusts or any(t.trustAttributes is None for t in trusts):
            return None
        return {self.domain_sid} | {t.sid for t in trusts if t.sid and (t.trustAttributes or 0) & TRUST_ATTRIBUTE_WITHIN_FOREST}

    @cached_property
    def _publication(self) -> dict[str, list[str]] | None:
        cas = self.objects("pKIEnrollmentService")
        if not cas:
            return None
        out: dict[str, list[str]] = {}
        for ca in cas:
            for name in {t.lower() for t in ca.certificateTemplates}:
                out.setdefault(name, []).append(ca.rdn_value)
        return out

    def published_on(self, template: AdObject) -> list[str] | None:
        """Имена ЦС, где шаблон опубликован; None — объектов ЦС в выгрузке нет, публикация неизвестна."""
        if self._publication is None:
            return None
        return list(self._publication.get(template.rdn_value.lower(), []))

    def domain_rid_sid(self, rid: int) -> str:
        return f"{self.domain_sid}-{rid}"

    def group_by_rid(self, rid: int) -> AdObject | None:
        return self.by_sid.get(self.domain_rid_sid(rid))

    def group_for_rid(self, rid: int) -> AdObject | None:
        """RID 544–582 — встроенная группа S-1-5-32-<RID>, остальные — RID своего домена."""
        if 544 <= rid <= 582:
            return self.by_sid.get(f"S-1-5-32-{rid}")
        return self.group_by_rid(rid)

    @staticmethod
    def is_dc(obj: AdObject) -> bool:
        """Контроллер домена, в том числе RODC."""
        return obj.cls == "computer" and bool((obj.uac or 0) & (UAC_SERVER_TRUST_ACCOUNT | UAC_PARTIAL_SECRETS_ACCOUNT))

    @cached_property
    def dcs(self) -> list[AdObject]:
        return [o for o in self.objects("computer") if self.is_dc(o)]

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
        domain_part, _, rid_text = sid.rpartition("-")
        foreign = self.trusted_domains.get(domain_part)
        if foreign is not None:
            rid = int(rid_text)
            return f"{foreign}\\{DOMAIN_RID_NAMES.get(rid, f'RID-{rid}')}"
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

    def inf_sections(self, gpo: AdObject) -> dict[str, dict[str, str]]:
        cache: dict[str, dict[str, dict[str, str]]] = self.cache.setdefault("inf_sections", {})
        key = gpo.dn.lower()
        if key not in cache:
            cache[key] = parse_inf(self.gpo_inf(gpo) or "")
        return cache[key]

    @cached_property
    def _gpo_by_dn(self) -> dict[str, GpoData] | None:
        if self.export.gpo is None:
            return None
        return {dn.lower(): data for dn, data in self.export.gpo.items()}

    def gpo_data(self, gpo: AdObject) -> GpoData | None:
        """Файлы GPO из SYSVOL; None — блока gpo нет или GPO в нём нет."""
        return self._gpo_by_dn.get(gpo.dn.lower()) if self._gpo_by_dn is not None else None

    @cached_property
    def gpo_link_map(self) -> dict[str, list[GpoLink]] | None:
        """DN GPO (нижний регистр) → все ссылки на неё, в том числе выключенные.
        None — ни у одного контейнера нет gPLink (сборщик старой версии)."""
        containers = [o for cls in _LINK_CONTAINERS for o in self.objects(cls) if o.gpLink is not None]
        if not containers:
            return None
        out: dict[str, list[GpoLink]] = {}
        for c in containers:
            for dn, disabled, enforced in parse_gplink(c.gpLink or ""):
                out.setdefault(dn, []).append(GpoLink(c.dn, enforced=enforced, disabled=disabled))
        return out

    def gpo_links(self, gpo: AdObject) -> list[GpoLink] | None:
        """Включённые ссылки на GPO (спека §3.1); None — привязка неизвестна."""
        if self.gpo_link_map is None:
            return None
        return [link for link in self.gpo_link_map.get(gpo.dn.lower(), []) if not link.disabled]

    def applies_to_dcs(self, gpo: AdObject) -> bool | None:
        """Включённая ссылка на корень домена или на предка DN контроллера, компьютерная часть не выключена.
        None — привязка неизвестна (компьютерная часть выключена — False и без неё). Блокировка наследования (gPOptions) не учитывается."""
        if (gpo.flags or 0) & GPO_FLAG_MACHINE_DISABLED:
            return False
        links = self.gpo_links(gpo)
        if links is None:
            return None
        root = self.export.domain.dn.lower()
        dc_dns = [d.dn.lower() for d in self.dcs]
        for link in links:
            container = link.container_dn.lower()
            if container == root or any(dn.endswith("," + container) for dn in dc_dns):
                return True
        return False

    def to_dict(self) -> dict[str, Any]:
        return self.export.model_dump(by_alias=True, mode="json")
