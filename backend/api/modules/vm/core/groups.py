"""Разбор выгрузки локальных групп из VM (спека 2026-10-23 §2).

CSV `;`, поля в кавычках, заголовок — имена полей PDQL как в `select`; строка на
участника, группа без участников — строка с пустыми полями участника. VM отдаёт всё
в нижнем регистре: SID приводится к верхнему, имена остаются как пришли.
"""
from __future__ import annotations

import csv
from collections.abc import Iterator
from dataclasses import dataclass
from typing import IO

#: Корневой тип PDQL по семейству ОС.
ROOT_TYPE = {"windows": "WindowsHost", "linux": "UnixHost"}


@dataclass
class VmGroupRow:
    os_family: str
    fqdn: str
    hostname: str
    ip: str
    group_name: str
    group_sid: str = ""
    group_gid: str = ""
    group_description: str = ""
    member_name: str = ""
    member_domain: str = ""
    member_sid: str = ""
    member_type: str = ""
    member_local: bool | None = None
    member_system: bool | None = None


def _bool(value: str) -> bool | None:
    v = value.strip().lower()
    return True if v == "true" else False if v == "false" else None


def iter_group_rows(fh: IO[str], family: str) -> Iterator[VmGroupRow]:
    """Колонки ищутся по имени из заголовка, порядок не важен. Строка без `Fqdn` и
    `Hostname` и строка без имени группы (хост без данных о группах) пропускаются."""
    root = ROOT_TYPE[family]
    reader = csv.reader(fh, delimiter=";")
    header = next(reader, None)
    if header is None:
        return
    columns = [c.strip().lstrip("﻿") for c in header]
    for values in reader:
        row = dict(zip(columns, values, strict=False))

        def get(field: str, row: dict[str, str] = row) -> str:
            return (row.get(f"{root}.{field}") or "").strip()

        fqdn, hostname, group_name = get("Fqdn"), get("Hostname"), get("Groups.Name")
        if not (fqdn or hostname) or not group_name:
            continue
        ip = get("IpAddress")
        if family == "windows":
            yield VmGroupRow(
                family, fqdn, hostname, ip, group_name,
                group_sid=get("Groups.SID").upper(),
                group_description=get("Groups.Description"),
                member_name=get("Groups.Members.Name"),
                member_domain=get("Groups.Members.Domain"),
                member_sid=get("Groups.Members.SID").upper(),
                member_type=get("Groups.Members.Type"),
                member_local=_bool(get("Groups.Members.IsLocal")),
                member_system=_bool(get("Groups.Members.IsSystem")),
            )
        else:
            user = get("Groups.Users")
            yield VmGroupRow(
                family, fqdn, hostname, ip, group_name,
                group_gid=get("Groups.GID"),
                member_name=user,
                member_type="account" if user else "",
                member_local=True if user else None,
            )
