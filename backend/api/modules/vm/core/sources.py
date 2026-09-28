"""Разбор источников хостов (спека §5): CSV-экспорт MaxPatrol VM и JSON
первой итерации. Оба — потоково: файл на гигабайт не должен ложиться
в память целиком.

Каждый разборщик отдаёт `HostRow` — хост со списком его CVE. JSON первой
итерации хранит одну пару на запись; строки одного хоста там идут подряд,
но полагаться на это нельзя, поэтому группировка — на стороне конвейера
(services/importer.py), а здесь только чтение.
"""
from __future__ import annotations

import csv
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

#: Колонки экспорта MP VM. `Host.@Groups` в старых выгрузках отсутствует.
COL_HOST = "@Host"
COL_OS = "Host.OsName"
COL_GROUPS = "Host.@Groups"
COL_CVES = "Host.@Vulners.CVEs"
COL_CRIT = "Host.UF_Criticality"
COL_ZONE = "Host.UF_Zone"


@dataclass
class HostRow:
    hostname: str
    ip: str = ""
    os_name: str = ""
    groups: str = ""
    criticality: str = ""
    zone: str = ""
    cves: list[str] = field(default_factory=list)


def split_host(text: str) -> tuple[str, str]:
    """`server01 (10.1.2.3)` → (`server01`, `10.1.2.3`); без скобок IP пуст."""
    s = text.strip()
    head, sep, tail = s.rpartition("(")
    # Как прежняя регулярка: скобки в конце, внутри последних скобок нет «)»,
    # имя (без хвостовых пробелов) — в одну строку.
    if not sep or not tail.endswith(")") or ")" in tail[:-1] or "\n" in head.rstrip():
        return s, ""
    return head.strip(), tail[:-1].strip()


def split_cves(text: str) -> list[str]:
    """Только настоящие идентификаторы, без дублей, в верхнем регистре."""
    seen: dict[str, None] = {}
    for cve in CVE_RE.findall(text or ""):
        seen.setdefault(cve.upper(), None)
    return list(seen)


def _norm_crit(value: str) -> str:
    v = (value or "").strip()
    return v[:1].upper() + v[1:].lower() if v else ""


def _row_from_csv(row: dict[str, str]) -> HostRow | None:
    host_text = (row.get(COL_HOST) or "").strip()
    if not host_text:
        return None
    hostname, ip = split_host(host_text)
    return HostRow(
        hostname=hostname,
        ip=ip,
        os_name=(row.get(COL_OS) or "").strip(),
        groups=(row.get(COL_GROUPS) or "").strip(),
        criticality=_norm_crit(row.get(COL_CRIT) or ""),
        zone=(row.get(COL_ZONE) or "").strip(),
        cves=split_cves(row.get(COL_CVES) or ""),
    )


def iter_csv(fh: IO[str]) -> Iterator[HostRow]:
    """CSV с `;` и кавычками, как отдаёт экспорт MP VM. Разделитель
    определяется по заголовку: у ручных выгрузок встречается запятая."""
    header = fh.readline()
    if not header:
        return
    delimiter = ";" if header.count(";") >= header.count(",") else ","
    columns = [c.strip().strip('"') for c in next(csv.reader([header], delimiter=delimiter))]
    reader = csv.reader(fh, delimiter=delimiter)
    for values in reader:
        if not values or all(not v.strip() for v in values):
            continue
        row = dict(zip(columns, values, strict=False))
        parsed = _row_from_csv(row)
        if parsed is not None:
            yield parsed


def iter_csv_path(path: Path) -> Iterator[HostRow]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        yield from iter_csv(fh)


def _row_from_json(item: dict[str, Any]) -> HostRow | None:
    host_text = str(item.get("host") or "").strip()
    if not host_text:
        return None
    hostname, ip = split_host(host_text)
    return HostRow(
        hostname=hostname,
        ip=ip,
        os_name=str(item.get("os_name") or "").strip(),
        groups=str(item.get("groups") or "").strip(),
        criticality=_norm_crit(str(item.get("criticality") or "")),
        zone=str(item.get("zone") or "").strip(),
        cves=split_cves(str(item.get("cve") or "")),
    )


def iter_json(fh: IO[bytes]) -> Iterator[HostRow]:
    """Массив объектов первой итерации, читается потоково через ijson.
    Файл открыт снаружи: конвейер следит за `fh.tell()` ради прогресса."""
    import ijson

    for item in ijson.items(fh, "item"):
        if not isinstance(item, dict):
            continue
        parsed = _row_from_json(item)
        if parsed is not None:
            yield parsed


def iter_json_path(path: Path) -> Iterator[HostRow]:
    with path.open("rb") as fh:
        yield from iter_json(fh)


def iter_path(path: Path) -> Iterator[HostRow]:
    """Формат — по расширению: .json → JSON первой итерации, иначе CSV."""
    if path.suffix.lower() == ".json":
        return iter_json_path(path)
    return iter_csv_path(path)
