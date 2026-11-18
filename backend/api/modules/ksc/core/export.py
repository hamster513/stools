"""Формат выгрузки `stools-ksc/1` и индекс по ней.

Секции — ответы Open API как есть (имена атрибутов KLHST_WKS_* и т. п.).
Типизированные значения KSC (`{"type": "datetime", "value": …}`) снимает
`unwrap`; всё, что нужно проверкам, — разобранные `HostRecord` в
`ExportIndex`.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import gzip
import json
import zlib
from collections.abc import Callable
from contextlib import nullcontext
from decimal import Decimal
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Any

import ijson
from pydantic import BaseModel, ConfigDict, Field

from api.export_files import GZIP_MAGIC
from api.modules.ksc.core.secrets import hide_secrets, hide_task_params
from kbaudit.safe_io import MB, decompress_gzip, decompress_gzip_file

if TYPE_CHECKING:
    from api.modules.ksc.core.coverage import AdComputer, Coverage

FORMAT = "stools-ksc/1"
#: Потолок распакованной внешней выгрузки: сжатая загрузка ограничена 200 МБ,
#: но gzip разворачивается до ~1000:1 (аудит H2). Распакованные байты плюс
#: разобранный JSON должны помещаться в `mem_limit` контейнера API (STOOLS_API_MEM).
MAX_UNPACKED = 512 * MB

STATUS_VISIBLE = 1 << 0
STATUS_AGENT_INSTALLED = 1 << 2
STATUS_AGENT_ALIVE = 1 << 3
STATUS_RTP_INSTALLED = 1 << 4

#: KLHST_WKS_RTP_STATE
RTP_RUNNING = {4, 5, 6, 7, 8}
RTP_OFF = {1, 2, 9}
RTP_NO_LICENSE = 11

#: KLHST_WKS_STATUS_ID
HOST_STATUS = {0: "ok", 1: "critical", 2: "warning"}

#: Биты KLHST_WKS_STATUS_MASK → текст причины.
STATUS_MASK_REASONS: dict[int, str] = {
    0: "агент установлен, но неактивен",
    1: "постоянная защита давно не работала",
    2: "продукт защиты установлен, но не запущен",
    3: "слишком много обнаруженных вирусов",
    4: "состояние постоянной защиты не соответствует заданному",
    5: "продукт защиты не установлен",
    6: "полный поиск давно не выполнялся",
    7: "базы давно не обновлялись",
    8: "агент давно не выходил на связь",
    9: "старая лицензия",
    10: "слишком много невылеченных объектов",
    11: "требуется перезагрузка",
    12: "установлено несовместимое ПО",
    13: "есть уязвимости",
    14: "давно не искали обновления ОС",
    15: "состояние шифрования не соответствует заданному",
    16: "настройки мобильного устройства не по политике",
    17: "есть необработанные инциденты",
    18: "статус задан управляемым продуктом",
    19: "мало места на диске или ошибки синхронизации",
}
#: Причина статуса не «ок», когда ни один бит маски не выставлен и текста продукта нет.
REASON_UNKNOWN = "причина не расшифрована"


def status_reasons(status: str, mask: int, text: str) -> list[str]:
    """Причины статуса устройства: расшифрованные биты `KLHST_WKS_STATUS_MASK` по порядку номеров (бит без расшифровки —
    «код N»), затем текст статуса управляемого продукта (`KLHST_WKS_STATUS_HSDP`), если он непустой. Статус не «ок»
    без единой причины — «причина не расшифрована»; у «ок» с пустой маской причин нет."""
    reasons = [STATUS_MASK_REASONS.get(bit, f"код {bit}") for bit in range(mask.bit_length()) if mask & (1 << bit)]
    if text:
        reasons.append(text)
    if not reasons and status != "ok":
        reasons.append(REASON_UNKNOWN)
    return reasons

#: Имена продуктов KSC (KLHST_WKS_PRODUCT_NAME).
PRODUCT_AGENT = "1103"
PRODUCT_SERVER = "1093"


def unwrap(value: Any) -> Any:
    """`{"type": "datetime", "value": "…Z"}` → datetime; long/date/binary → значение; рекурсивно."""
    if isinstance(value, dict):
        if set(value.keys()) == {"type", "value"} and isinstance(value["type"], str):
            kind, inner = value["type"], value["value"]
            if kind == "datetime" and isinstance(inner, str):
                try:
                    return dt.datetime.strptime(inner, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
                except ValueError:
                    return None
            return inner
        return {k: unwrap(v) for k, v in value.items()}
    if isinstance(value, list):
        return [unwrap(v) for v in value]
    return value


def strip_params(value: Any) -> Any:
    """Снимает обёртки `{"type": "params", "value": {…}}` рекурсивно.

    Живой KSC заворачивает в них каждую запись списка и каждый вложенный
    контейнер; остальные типизированные значения (datetime, long, binary)
    остаются как есть — их снимает `unwrap` при чтении поля."""
    if isinstance(value, dict):
        if set(value.keys()) == {"type", "value"} and value["type"] == "params":
            return strip_params(value["value"] if value["value"] is not None else {})
        return {k: strip_params(v) for k, v in value.items()}
    if isinstance(value, list):
        return [strip_params(v) for v in value]
    # ijson preserves arbitrary-sized integers; its non-integers are Decimal.
    return float(value) if isinstance(value, Decimal) else value


class ServerInfo(BaseModel):
    name: str
    version: str = ""
    collected_at: dt.datetime
    collector: str = ""
    collector_version: str = ""
    user: str = ""
    host: str = ""
    warnings: list[str] = Field(default_factory=list)


class KscExport(BaseModel):
    model_config = ConfigDict(extra="allow")

    format: str
    server: ServerInfo
    groups: list[dict[str, Any]] = Field(default_factory=list)
    hosts: list[dict[str, Any]] = Field(default_factory=list)
    host_products: dict[str, dict[str, Any]] = Field(default_factory=dict)
    host_inventory: dict[str, dict[str, Any]] = Field(default_factory=dict)
    host_components: dict[str, dict[str, list[dict[str, Any]]]] = Field(default_factory=dict)
    policies: list[dict[str, Any]] = Field(default_factory=list)
    effective_policies: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    tasks: list[dict[str, Any]] = Field(default_factory=list)
    licenses: list[dict[str, Any]] = Field(default_factory=list)
    static: dict[str, Any] = Field(default_factory=dict)
    domains: list[dict[str, Any]] = Field(default_factory=list)
    role_assignments: list[dict[str, Any]] = Field(default_factory=list)
    internal_users: list[dict[str, Any]] = Field(default_factory=list)
    security: dict[str, Any] = Field(default_factory=dict)
    server_certs: dict[str, Any] = Field(default_factory=dict)
    secondary_servers: list[dict[str, Any]] = Field(default_factory=list)
    update_agents: list[dict[str, Any]] = Field(default_factory=list)
    #: {"<KLPOL_ID>": {"product", "version", "sections": {...}, "errors": [...]}}; необязательная секция.
    policy_contents: dict[str, dict[str, Any]] = Field(default_factory=dict)
    #: {"<KLHST_WKS_HOSTNAME>": ["тег", …]}; None — секции нет (старый сборщик), «не собрано», а не «пусто».
    host_tags: dict[str, list[str]] | None = None
    #: {"<KLPOL_ID>": {"profiles": [{"name", "attrs", "sections", "errors"}], "priorities": [...], "errors": [...]}};
    #: None — секции нет (не собрано).
    policy_profiles: dict[str, dict[str, Any]] | None = None
    #: Сборщик 1.4: {"<KLHST_WKS_HOSTNAME>": [{"sid", "sam", "upn", "display_name", "domain", "local", "group", "active",
    #: "bin_id"}] | None} — по хостам с агентом; None у хоста — запрос по нему отказал; None целиком — секции нет
    #: (сборщик до 1.4), «не собрано», а не «пусто».
    host_users: dict[str, list[dict[str, Any]] | None] | None = None


class ExportFormatError(ValueError):
    pass


def _hide_export_secrets(raw: dict[str, Any]) -> None:
    """Повторное скрытие секретов (аудит M4) в содержимом политик и параметрах задач уже
    разобранного файла: файл старого сборщика или поправленный руками не должен показать то,
    что нынешний сборщик скрыл бы. Меняет `raw` на месте; нестандартные формы пропускает — их
    отвергнет проверка схемы."""
    contents = raw.get("policy_contents")
    if isinstance(contents, dict):
        for policy in contents.values():
            sections = policy.get("sections") if isinstance(policy, dict) else None
            if isinstance(sections, dict):
                policy["sections"] = {name: hide_secrets(value, str(name)) for name, value in sections.items()}
    profiles = raw.get("policy_profiles")
    if isinstance(profiles, dict):
        for policy in profiles.values():
            for profile in (policy.get("profiles") if isinstance(policy, dict) else None) or []:
                if not isinstance(profile, dict):
                    continue
                sections = profile.get("sections")
                if isinstance(sections, dict):
                    profile["sections"] = {name: hide_secrets(value, str(name)) for name, value in sections.items()}
                if isinstance(profile.get("attrs"), dict):
                    profile["attrs"] = hide_secrets(profile["attrs"])
    tasks = raw.get("tasks")
    if isinstance(tasks, list):
        for task in tasks:
            if isinstance(task, dict):
                hide_task_params(task)


def load_export(data: bytes | bytearray) -> KscExport:
    if data[:2] == GZIP_MAGIC:
        data = _unpacked(lambda: decompress_gzip(data, MAX_UNPACKED))
    return parse_export(_parsed(data))


def load_export_path(path: Path) -> KscExport:
    """Файл читается один раз, сжатый — распаковкой потоком с тем же потолком;
    текст освобождается до проверки модели."""
    return parse_export(_parsed(_read(path)))


def load_snapshot_export(path: Path) -> KscExport:
    """Read only an already accepted local snapshot, never an incoming upload.

    Online snapshots may exceed the upload limit. Stream their JSON to avoid
    holding the entire decompressed text alongside its parsed object tree.
    """
    with path.open("rb") as f:
        packed = f.read(2) == GZIP_MAGIC
        f.seek(0)
        try:
            with gzip.GzipFile(fileobj=f, mode="rb") if packed else nullcontext(f) as stream:
                values = ijson.items(stream, "")
                raw = next(values)
                # Exhaust the stream to validate trailing JSON and the gzip CRC.
                sentinel = object()
                if next(values, sentinel) is not sentinel:
                    raise ExportFormatError("файл не разобран как JSON выгрузки")
        except (OSError, EOFError, zlib.error) as exc:
            raise ExportFormatError("файл не разобран как JSON выгрузки (битый gzip)") from exc
        except (ijson.JSONError, StopIteration, UnicodeDecodeError) as exc:
            raise ExportFormatError("файл не разобран как JSON выгрузки") from exc
    return parse_export(raw)


def _read(path: Path) -> bytes | bytearray:
    with path.open("rb") as f:
        packed = f.read(2) == GZIP_MAGIC
        f.seek(0)
        return _unpacked(lambda: decompress_gzip_file(f, MAX_UNPACKED)) if packed else f.read()


def _unpacked(unpack: Callable[[], bytearray]) -> bytearray:
    try:
        return unpack()
    except (OSError, EOFError, zlib.error) as exc:
        # Порча внутри потока deflate — `zlib.error`, не `OSError`.
        raise ExportFormatError("файл не разобран как JSON выгрузки (битый gzip)") from exc
    except ValueError as exc:
        raise ExportFormatError(f"выгрузка не распакована: {exc}") from exc


def _parsed(data: bytes | bytearray) -> Any:
    try:
        return json.loads(data)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise ExportFormatError("файл не разобран как JSON выгрузки") from exc


def parse_export(raw: Any) -> KscExport:
    """Validate collected or decoded data, unwrap containers and hide secrets."""
    if not isinstance(raw, dict) or raw.get("format") != FORMAT:
        found = raw.get("format") if isinstance(raw, dict) else "—"
        raise ExportFormatError(f"это не выгрузка формата {FORMAT}: в файле «{found}»")
    try:
        # Файл хранится как собран; обёртки контейнеров снимаются и секреты скрываются только в памяти.
        plain = strip_params(raw)
        _hide_export_secrets(plain)
        return KscExport.model_validate(plain)
    except ValueError as exc:
        first = str(exc).splitlines()[0][:200]
        raise ExportFormatError(f"выгрузка неполная: {first}") from exc
    except RecursionError as exc:
        # JSON-разбор держит вложенность глубже, чем рекурсивный разбор обёрток.
        raise ExportFormatError("выгрузка не разобрана: вложенность глубже допустимой") from exc


def _dt(value: Any) -> dt.datetime | None:
    value = unwrap(value)
    return value if isinstance(value, dt.datetime) else None


def _int(value: Any) -> int:
    value = unwrap(value)
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0


def _str(value: Any) -> str:
    value = unwrap(value)
    return str(value) if value is not None else ""


def parent_id(group: dict[str, Any]) -> int:
    """`parentId` группы; -1, если поля нет вовсе — это корень, а не группа 0."""
    return _int(group.get("parentId")) if group.get("parentId") is not None else -1


def ip_from_long(value: int) -> str:
    """KLHST_WKS_IP_LONG → адрес; 3232235777 → 192.168.1.1. Отрицательные значения —
    тот же адрес знаковым int32 (от 128.0.0.0). Порядок байтов принят прямым,
    на живых данных не проверен."""
    if value == 0:
        return ""
    b = (value & 0xFFFFFFFF).to_bytes(4, "big")
    return ".".join(str(x) for x in b)


def version_tuple(version: str) -> tuple[int, ...]:
    out: list[int] = []
    for part in version.split("."):
        try:
            out.append(int(part))
        except ValueError:
            out.append(0)
    return tuple(out)


@dataclasses.dataclass(frozen=True)
class HostUser:
    """Пользователь устройства из секции `host_users` (поля контракта спеки «Пользователи как активы» §2.1):
    `active` — в системе на момент сбора, иначе заходил раньше; `group` — группа, а не пользователь (KSC отдаёт их
    в том же списке)."""

    sid: str
    sam: str
    upn: str
    display_name: str
    domain: str
    local: bool
    group: bool
    active: bool

    @classmethod
    def parse(cls, item: dict[str, Any]) -> HostUser:
        return cls(sid=_str(item.get("sid")), sam=_str(item.get("sam")), upn=_str(item.get("upn")), display_name=_str(item.get("display_name")),
                   domain=_str(item.get("domain")), local=bool(item.get("local")), group=bool(item.get("group")), active=bool(item.get("active")))


def _owner(owner_id: str, items: list[dict[str, Any]] | None) -> dict[str, str] | None:
    """Владелец устройства: `KLHST_WKS_OWNER_ID` связывается с пользователем того же хоста по `bin_id` (`ul_binId`) —
    `{"sid", "sam", "display_name"}`; не задан — None; задан, но в списке пользователей хоста его нет (или список не
    собран) — только `{"owner_id": <base64>}`."""
    if not owner_id:
        return None
    for item in items or []:
        if isinstance(item, dict) and _str(item.get("bin_id")) == owner_id:
            return {"sid": _str(item.get("sid")), "sam": _str(item.get("sam")), "display_name": _str(item.get("display_name"))}
    return {"owner_id": owner_id}


class HostRecord:
    """Разобранный хост KSC: флаги статуса, даты, продукт, компоненты."""

    def __init__(self, raw: dict[str, Any], export: KscExport, group_path: str) -> None:
        self.raw = raw
        self.host_id = _str(raw.get("KLHST_WKS_HOSTNAME"))
        self.name = _str(raw.get("KLHST_WKS_DN")) or _str(raw.get("KLHST_WKS_WINHOSTNAME")) or self.host_id
        self.winhostname = _str(raw.get("KLHST_WKS_WINHOSTNAME"))
        self.windomain = _str(raw.get("KLHST_WKS_WINDOMAIN"))
        self.domain = _str(raw.get("KLHST_WKS_DNSDOMAIN")).lower()
        self.fqdn = _str(raw.get("KLHST_WKS_FQDN")).lower()
        self.group_id = _int(raw.get("KLHST_WKS_GROUPID"))
        self.group_path = group_path
        self.os = _str(raw.get("KLHST_WKS_OS_NAME"))
        self.ip = ip_from_long(_int(raw.get("KLHST_WKS_IP_LONG")))
        status = _int(raw.get("KLHST_WKS_STATUS"))
        self.visible = bool(status & STATUS_VISIBLE)
        self.agent_installed = bool(status & STATUS_AGENT_INSTALLED)
        self.agent_alive = bool(status & STATUS_AGENT_ALIVE)
        self.protection_installed = bool(status & STATUS_RTP_INSTALLED)
        self.rtp_state = _int(raw.get("KLHST_WKS_RTP_STATE"))
        self.status = HOST_STATUS.get(_int(raw.get("KLHST_WKS_STATUS_ID")), "ok")
        self.status_mask = _int(raw.get("KLHST_WKS_STATUS_MASK"))
        # Текст статуса, заданного управляемым продуктом (бит 18): это текст продукта, показывается как есть; не строка — пусто.
        hsdp = unwrap(raw.get("KLHST_WKS_STATUS_HSDP"))
        self.status_text = hsdp.strip() if isinstance(hsdp, str) else ""
        self.last_seen_at = _dt(raw.get("KLHST_WKS_LAST_NAGENT_CONNECTED")) or _dt(raw.get("KLHST_WKS_LAST_VISIBLE"))
        self.bases_at = _dt(raw.get("KLHST_WKS_RTP_AV_BASES_TIME"))
        self.last_fullscan_at = _dt(raw.get("KLHST_WKS_LAST_FULLSCAN"))
        self.agent_version = _str(raw.get("KLHST_WKS_NAG_VERSION"))
        self.product_version = _str(raw.get("KLHST_WKS_RTP_AV_VERSION"))
        self.threats = _int(raw.get("KLHST_WKS_UNCURED_COUNT"))
        self.unassigned = bool(unwrap(raw.get("KLHST_WKS_FROM_UNASSIGNED")))
        # Продукт защиты — первый установленный продукт, кроме агента и сервера.
        products = export.host_products.get(self.host_id, {})
        self.product = next((p for p in products if p not in (PRODUCT_AGENT, PRODUCT_SERVER)), "")
        if self.product and not self.product_version:
            self.product_version = next(iter(products[self.product]), "")
        self.components: list[tuple[str, int]] = []
        for items in export.host_components.get(self.host_id, {}).values():
            for c in items:
                self.components.append((_str(c.get("KLHST_PRCST_COMPONENT_DN")), _int(c.get("KLHST_PRCST_COMPONENT_STATUS"))))
        # Расширенные поля хоста (блок 1): сборка ОС, архитектура, тип виртуализации, зависшая
        # перезагрузка, EDR, управление другим сервером — не входят в колонки `ksc_host`, кладутся в `extra`.
        self.os_build = _int(raw.get("KLHST_WKS_OS_BUILD_NUMBER"))
        self.cpu_arch = _int(raw.get("KLHST_WKS_CPU_ARCH"))
        self.vm_type = _int(raw.get("HST_VM_TYPE"))
        self.reboot_required = bool(unwrap(raw.get("KLHST_WKS_RBT_REQUIRED")))
        self.reboot_requested_at = _dt(raw.get("KLHST_WKS_RBT_REQUEST_TIME"))
        self.reboot_reason = _int(raw.get("KLHST_WKS_RBT_REQUEST_REASON"))
        self.edr_status = _int(raw.get("KLHST_WKS_EDR_STATUS"))
        self.managed_by_other_server = bool(unwrap(raw.get("KLHST_MANAGED_OTHER_SERVER")))
        # Теги — секция необязательная: `tags_collected` отличает «у хоста нет тегов» от «теги не собирались».
        tags_raw = export.host_tags.get(self.host_id) if export.host_tags is not None else None
        self.tags: list[str] = sorted({str(t) for t in (tags_raw or []) if str(t).strip()})
        self.tags_collected = export.host_tags is not None
        # Пользователи (сборщик 1.4) — «не собрано» на трёх уровнях: секции нет (`users_collected` False), у хоста нет
        # списка (`users` None: запрос отказал или у хоста нет агента), пустой список — никто не заходил.
        self.users_collected = export.host_users is not None
        users_raw = export.host_users.get(self.host_id) if export.host_users is not None else None
        self.users: list[HostUser] | None = None if users_raw is None else [HostUser.parse(u) for u in users_raw if isinstance(u, dict)]
        self.owner = _owner(_str(raw.get("KLHST_WKS_OWNER_ID")), users_raw)

    @property
    def extra(self) -> dict[str, Any]:
        """Расширенные поля хоста для карточки и списка (не колонки `ksc_host`)."""
        extra: dict[str, Any] = {
            "os_build": self.os_build, "cpu_arch": self.cpu_arch, "vm_type": self.vm_type,
            "reboot_required": self.reboot_required,
            "reboot_requested_at": self.reboot_requested_at.strftime("%Y-%m-%dT%H:%M:%SZ") if self.reboot_requested_at else None,
            "reboot_reason": self.reboot_reason, "edr_status": self.edr_status,
            "managed_by_other_server": self.managed_by_other_server,
            # Маска и текст статуса: по ним список и карточка хоста собирают причины; у строк старых снапшотов ключей нет.
            "status_mask": self.status_mask, "status_text": self.status_text,
        }
        if self.tags_collected:
            extra["tags"] = self.tags
        extra["users"] = None if self.users is None else [dataclasses.asdict(u) for u in self.users]
        extra["owner"] = self.owner
        extra["users_collected"] = self.users_collected
        return extra

    @property
    def protection(self) -> str:
        if not self.protection_installed:
            return "none"
        return "on" if self.rtp_state in RTP_RUNNING else "off"

    @property
    def status_reasons(self) -> list[str]:
        return status_reasons(self.status, self.status_mask, self.status_text)


class ExportIndex:
    def __init__(self, export: KscExport) -> None:
        self.export = export
        self.now = export.server.collected_at
        self.groups_by_id: dict[int, dict[str, Any]] = {_int(g.get("id")): g for g in export.groups}
        self.hosts: list[HostRecord] = [HostRecord(h, export, self.group_path(_int(h.get("KLHST_WKS_GROUPID")))) for h in export.hosts]
        #: Компьютеры AD для сверки; None — снапшота AD нет. Задаётся до первого обращения к `coverage`.
        self.ad_computers: list[AdComputer] | None = None

    @cached_property
    def coverage(self) -> Coverage | None:
        from api.modules.ksc.core.coverage import match

        return match(self.hosts, self.ad_computers) if self.ad_computers is not None else None

    def group_path(self, group_id: int) -> str:
        g = self.groups_by_id.get(group_id)
        if g is None:
            return ""
        full = _str(g.get("grp_full_name"))
        if full:
            return full
        parts: list[str] = []
        seen: set[int] = set()
        cur: dict[str, Any] | None = g
        while cur is not None and _int(cur.get("id")) not in seen:
            seen.add(_int(cur.get("id")))
            parts.append(_str(cur.get("name")))
            cur = self.groups_by_id.get(parent_id(cur))
        return "/".join(reversed(parts))

    @cached_property
    def hosts_by_group(self) -> dict[int, list[HostRecord]]:
        out: dict[int, list[HostRecord]] = {}
        for h in self.hosts:
            out.setdefault(h.group_id, []).append(h)
        return out

    def children(self, group_id: int) -> list[int]:
        return [gid for gid, g in self.groups_by_id.items() if parent_id(g) == group_id]

    def subtree(self, group_id: int) -> list[int]:
        out = [group_id]
        stack = [group_id]
        while stack:
            for child in self.children(stack.pop()):
                if child not in out:
                    out.append(child)
                    stack.append(child)
        return out
