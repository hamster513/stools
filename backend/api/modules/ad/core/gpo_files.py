"""Разбор файлов GPO из SYSVOL (спека §3.1): чистые функции без ввода-вывода.

Сборщик читает байты и декодирует текст, здесь — только разбор. Значения
паролей отсюда не выходят: у GPP остаётся факт `cpassword`, у автологона —
пустая строка вместо `DefaultPassword`.
"""
from __future__ import annotations

import csv
import io
import re
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass, replace
from typing import Any

MAX_GPO_FILE = 4 * 1024 * 1024

_GPP = ("Groups", "Services", "ScheduledTasks", "DataSources", "Drives", "Printers", "Files")
#: Имя (часть/файл) → путь относительно папки GPO. Services бывают только у компьютера, Drives — только у пользователя.
GPO_FILES: dict[str, str] = {
    "machine/Registry.pol": "Machine\\Registry.pol",
    "user/Registry.pol": "User\\Registry.pol",
    **{f"machine/{k}.xml": f"Machine\\Preferences\\{k}\\{k}.xml" for k in _GPP if k != "Drives"},
    **{f"user/{k}.xml": f"User\\Preferences\\{k}\\{k}.xml" for k in _GPP if k != "Services"},
    "machine/audit.csv": "Machine\\Microsoft\\Windows NT\\Audit\\audit.csv",
    "machine/scripts.ini": "Machine\\Scripts\\scripts.ini",
    "machine/psscripts.ini": "Machine\\Scripts\\psscripts.ini",
    "user/scripts.ini": "User\\Scripts\\scripts.ini",
    "user/psscripts.ini": "User\\Scripts\\psscripts.ini",
}

REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_MULTI_SZ = 1, 2, 4, 7


@dataclass(frozen=True)
class RegistryValue:
    key: str
    value: str
    type: int
    data: str | int | list[str] | None


# ---- Registry.pol ----------------------------------------------------------

_OPEN, _SEP, _CLOSE, _NUL = ("[".encode("utf-16-le"), ";".encode("utf-16-le"), "]".encode("utf-16-le"), b"\x00\x00")


def parse_registry_pol(data: bytes) -> list[RegistryValue]:
    """PReg: заголовок, затем записи [key;value;type;size;data]. Данные могут
    содержать «;» и «]», поэтому идём по размерам, а не режем по разделителям."""
    if len(data) < 8 or data[:4] != b"PReg" or struct.unpack_from("<I", data, 4)[0] != 1:
        raise ValueError("не файл Registry.pol (нет заголовка PReg версии 1)")
    out: list[RegistryValue] = []
    pos = 8
    while pos < len(data):
        pos = _expect(data, pos, _OPEN)
        key, pos = _string(data, pos)
        pos = _expect(data, pos, _SEP)
        value, pos = _string(data, pos)
        pos = _expect(data, pos, _SEP)
        type_, pos = _dword(data, pos)
        pos = _expect(data, pos, _SEP)
        size, pos = _dword(data, pos)
        pos = _expect(data, pos, _SEP)
        if pos + size > len(data):
            raise ValueError("Registry.pol обрезан")
        raw = data[pos:pos + size]
        pos = _expect(data, pos + size, _CLOSE)
        if value.startswith("**"):  # **del.X, **delvals. и прочие команды удаления
            continue
        out.append(RegistryValue(key, value, type_, _reg_data(type_, raw)))
    return out


def _expect(data: bytes, pos: int, token: bytes) -> int:
    if data[pos:pos + 2] != token:
        raise ValueError(f"Registry.pol повреждён: на смещении {pos} нет «{token.decode('utf-16-le')}»")
    return pos + 2


def _string(data: bytes, pos: int) -> tuple[str, int]:
    end = pos
    while data[end:end + 2] != _NUL:
        if end + 2 > len(data):
            raise ValueError("Registry.pol обрезан")
        end += 2
    return data[pos:end].decode("utf-16-le", errors="replace"), end + 2


def _dword(data: bytes, pos: int) -> tuple[int, int]:
    if pos + 4 > len(data):
        raise ValueError("Registry.pol обрезан")
    return struct.unpack_from("<I", data, pos)[0], pos + 4


def _reg_data(type_: int, raw: bytes) -> str | int | list[str] | None:
    # errors="replace": одно битое значение не должно терять весь файл.
    if type_ in (REG_SZ, REG_EXPAND_SZ):
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    if type_ == REG_DWORD:
        return struct.unpack("<I", raw)[0] if len(raw) == 4 else None
    if type_ == REG_MULTI_SZ:
        text = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        return text.split("\x00") if text else []
    return None


#: Белый список спеки §3.1: ключ (нижний регистр) → имена значений; None — все значения ключа.
_KEEP: dict[str, frozenset[str] | None] = {
    "software\\policies\\microsoft\\windows nt\\dnsclient": frozenset({"enablemulticast"}),
    "software\\policies\\microsoft\\windows\\networkprovider\\hardenedpaths": None,
    "software\\policies\\microsoft\\windows\\windowsupdate": frozenset({
        "wuserver", "setproxybehaviorforupdatedetection", "donotenforceenterprisetlscertpinningforupdatedetection"}),
    "software\\policies\\microsoft\\windows\\powershell\\scriptblocklogging": frozenset({"enablescriptblocklogging"}),
    "software\\policies\\microsoft\\windows\\powershell\\modulelogging": frozenset({"enablemodulelogging"}),
    "software\\microsoft\\windows nt\\currentversion\\winlogon": frozenset({"autoadminlogon", "defaultusername", "defaultpassword"}),
    "system\\currentcontrolset\\control\\lsa": frozenset({
        "lmcompatibilitylevel", "nolmhash", "restrictanonymous", "everyoneincludesanonymous", "limitblankpassworduse"}),
    "system\\currentcontrolset\\services\\ntds\\parameters": frozenset({"ldapserverintegrity"}),
    "system\\currentcontrolset\\services\\netlogon\\parameters": frozenset({"refusepasswordchange"}),
    "software\\microsoft\\windows nt\\currentversion\\setup\\recoveryconsole": frozenset({"securitylevel"}),
}
_WINLOGON = "software\\microsoft\\windows nt\\currentversion\\winlogon"


def keep_registry(key: str, value: str) -> bool:
    k = key.strip("\\").lower()
    if k not in _KEEP:
        return False
    names = _KEEP[k]
    return names is None or value.lower() in names


def redact(v: RegistryValue) -> RegistryValue:
    if v.key.strip("\\").lower() == _WINLOGON and v.value.lower() == "defaultpassword":
        return replace(v, data="")
    return v


# ---- GptTmpl.inf -----------------------------------------------------------

def parse_inf(text: str) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for raw in text.lstrip("﻿").splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1].strip().lower(), {})
            continue
        if current is None or "=" not in line or line.startswith(";"):
            continue
        key, _, value = line.partition("=")
        current[key.strip()] = value.strip()
    return sections


def inf_registry_values(sections: dict[str, dict[str, str]]) -> dict[str, tuple[int, str]]:
    """[Registry Values]: «MACHINE\\путь\\имя=тип,значение»."""
    out: dict[str, tuple[int, str]] = {}
    for key, raw in sections.get("registry values", {}).items():
        type_text, _, value = raw.partition(",")
        try:
            type_ = int(type_text.strip())
        except ValueError:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        out[key.lower()] = (type_, value)
    return out


def inf_group_membership(sections: dict[str, dict[str, str]]) -> list[tuple[str, str, list[str]]]:
    """[Group Membership]: «*SID__Members = …» и «*SID__Memberof = …»."""
    out: list[tuple[str, str, list[str]]] = []
    for key, raw in sections.get("group membership", {}).items():
        name, sep, kind = key.rpartition("__")
        if not sep or kind.lower() not in ("members", "memberof"):
            continue
        entries = [e.strip().lstrip("*") for e in raw.split(",") if e.strip()]
        out.append((name.strip().lstrip("*"), kind.lower(), entries))
    return out


# ---- Настройки GPP (XML) ---------------------------------------------------

_DOCTYPE = re.compile(r"<!doctype", re.IGNORECASE)
_USER_ATTRS = ("userName", "accountName", "runAs", "username")
_PATH_ATTRS = ("path", "fromPath")


def parse_gpp(file: str, scope: str, xml_text: str) -> list[dict[str, Any]]:
    """Запись — любой элемент с дочерним Properties. Значение cpassword не сохраняется."""
    if len(xml_text) > MAX_GPO_FILE:
        raise ValueError(f"{file}: файл больше {MAX_GPO_FILE // (1024 * 1024)} МБ")
    # Общего безопасного разбора XML в проекте нет: DTD (сущности, «миллиард смехов») отвергается до разбора.
    if _DOCTYPE.search(xml_text):
        raise ValueError(f"{file}: XML с DOCTYPE не разбирается")
    try:
        root = ET.fromstring(xml_text.lstrip("﻿"))
    except ET.ParseError as exc:
        raise ValueError(f"{file}: XML не разобран ({exc})") from exc
    out: list[dict[str, Any]] = []
    for el in root.iter():
        props = el.find("Properties")
        if props is None:
            continue
        members = props.find("Members")
        filters = el.find("Filters")
        out.append({
            "scope": scope,
            "file": file,
            "kind": el.tag,
            "name": el.get("name", ""),
            "user": _first(props, _USER_ATTRS),
            "cpassword": bool(props.get("cpassword")),
            "action": props.get("action", ""),
            "members": [
                {"name": m.get("name", ""), "sid": m.get("sid", ""), "action": m.get("action", "")}
                for m in (members.findall("Member") if members is not None else [])
            ],
            "group_sid": props.get("groupSid", ""),
            "group_name": props.get("groupName", ""),
            "path": _first(props, _PATH_ATTRS),
            # Нацеливание на уровне элемента: условия в узле Filters рядом с Properties; пустой Filters — без условий.
            "filtered": filters is not None and len(filters) > 0,
            # Замена состава группы: перед добавлением участников удаляются все пользователи и/или группы.
            "delete_all": "1" in (props.get("deleteAllUsers"), props.get("deleteAllGroups")),
        })
    return out


def _first(el: ET.Element, attrs: tuple[str, ...]) -> str:
    return next((v for v in (el.get(a) for a in attrs) if v), "")


# ---- audit.csv, scripts.ini, gPLink ----------------------------------------

_GUID_COL, _SETTING_COL = "Subcategory GUID", "Setting Value"


def parse_audit_csv(text: str) -> list[dict[str, Any]]:
    try:
        return _audit_rows(text)
    except csv.Error as exc:  # поле длиннее предела модуля csv и прочий мусор
        raise ValueError(f"audit.csv не разобран ({exc})") from exc


def _audit_rows(text: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text.lstrip("﻿")))
    if text.strip() and not {_GUID_COL, _SETTING_COL} <= set(reader.fieldnames or ()):
        raise ValueError("audit.csv: нет столбцов «Subcategory GUID» и «Setting Value»")
    out: list[dict[str, Any]] = []
    for row in reader:
        guid = (row.get(_GUID_COL) or "").strip().strip("{}").lower()
        try:
            setting = int((row.get(_SETTING_COL) or "").strip())
        except ValueError:
            continue  # строки параметров (Option:…) без подкатегории
        if guid:
            out.append({"subcategory": guid, "setting": setting})
    return out


_PHASES = ("logon", "logoff", "startup", "shutdown")
_SCRIPT_KEY = re.compile(r"^(\d+)cmdline$", re.IGNORECASE)


def parse_scripts_ini(text: str, scope: str) -> list[dict[str, str]]:
    """Команды сценариев. Параметры («<n>Parameters») не собираются: в них бывают пароли; поле — пустое для совместимости."""
    out: list[dict[str, str]] = []
    for section, values in parse_inf(text).items():
        if section not in _PHASES:
            continue
        commands: dict[int, str] = {}
        for key, value in values.items():
            m = _SCRIPT_KEY.match(key)
            if m:
                commands[int(m.group(1))] = value
        for n in sorted(commands):
            if commands[n]:
                out.append({"scope": scope, "phase": section, "command": commands[n], "parameters": ""})
    return out


_GPLINK = re.compile(r"\[LDAP://([^;\]]+);(\d+)\]", re.IGNORECASE)


def parse_gplink(value: str) -> list[tuple[str, bool, bool]]:
    """(DN GPO, выключена, принудительная) для каждой ссылки gPLink."""
    out: list[tuple[str, bool, bool]] = []
    for m in _GPLINK.finditer(value):
        opts = int(m.group(2))
        out.append((m.group(1).strip().lower(), bool(opts & 1), bool(opts & 2)))
    return out
