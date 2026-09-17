"""Формат выгрузки `stools-ksc/1` и индекс по ней.

Секции — ответы Open API как есть (имена атрибутов KLHST_WKS_* и т. п.).
Типизированные значения KSC (`{"type": "datetime", "value": …}`) снимает
`unwrap`; всё, что нужно проверкам, — разобранные `HostRecord` в
`ExportIndex`.
"""
from __future__ import annotations

import datetime as dt
import gzip
import json
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from api.modules.ksc.core.coverage import AdComputer, Coverage

FORMAT = "stools-ksc/1"

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
    return value


class ServerInfo(BaseModel):
    name: str
    version: str = ""
    collected_at: dt.datetime
    collector: str = ""
    collector_version: str = ""
    user: str = ""
    host: str = ""


class KscExport(BaseModel):
    model_config = ConfigDict(extra="allow")

    format: str
    server: ServerInfo
    groups: list[dict[str, Any]] = Field(default_factory=list)
    hosts: list[dict[str, Any]] = Field(default_factory=list)
    host_products: dict[str, dict[str, Any]] = Field(default_factory=dict)
    host_components: dict[str, dict[str, list[dict[str, Any]]]] = Field(default_factory=dict)
    policies: list[dict[str, Any]] = Field(default_factory=list)
    effective_policies: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    tasks: list[dict[str, Any]] = Field(default_factory=list)
    licenses: list[dict[str, Any]] = Field(default_factory=list)
    static: dict[str, Any] = Field(default_factory=dict)
    domains: list[dict[str, Any]] = Field(default_factory=list)


class ExportFormatError(ValueError):
    pass


def load_export(data: bytes) -> KscExport:
    if data[:2] == b"\x1f\x8b":
        try:
            data = gzip.decompress(data)
        except (OSError, EOFError) as exc:
            raise ExportFormatError("файл не разобран как JSON выгрузки (битый gzip)") from exc
    try:
        raw = json.loads(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ExportFormatError("файл не разобран как JSON выгрузки") from exc
    if not isinstance(raw, dict) or raw.get("format") != FORMAT:
        found = raw.get("format") if isinstance(raw, dict) else "—"
        raise ExportFormatError(f"это не выгрузка формата {FORMAT}: в файле «{found}»")
    try:
        # Файл хранится как собран; обёртки контейнеров снимаются только в памяти.
        return KscExport.model_validate(strip_params(raw))
    except ValueError as exc:
        first = str(exc).splitlines()[0][:200]
        raise ExportFormatError(f"выгрузка неполная: {first}") from exc


def load_export_path(path: Path) -> KscExport:
    return load_export(path.read_bytes())


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

    @property
    def protection(self) -> str:
        if not self.protection_installed:
            return "none"
        return "on" if self.rtp_state in RTP_RUNNING else "off"

    @property
    def status_reasons(self) -> list[str]:
        return [text for bit, text in STATUS_MASK_REASONS.items() if self.status_mask & (1 << bit)]


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
