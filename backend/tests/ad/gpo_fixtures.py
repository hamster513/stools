"""Файлы GPO для тестов разбора и сборщиков: Registry.pol собирается из записей."""
from __future__ import annotations

import struct

LSA = "System\\CurrentControlSet\\Control\\Lsa"
WINLOGON = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"


def _u(text: str) -> bytes:
    return text.encode("utf-16-le")


def dword(n: int) -> bytes:
    return struct.pack("<I", n)


def sz(text: str) -> bytes:
    return _u(text + "\x00")


def preg(*entries: tuple[str, str, int, bytes]) -> bytes:
    """Registry.pol: заголовок PReg и версия 1, записи [key;value;type;size;data]."""
    out = b"PReg" + struct.pack("<I", 1)
    for key, value, type_, data in entries:
        out += _u("[") + _u(key + "\x00") + _u(";") + _u(value + "\x00") + _u(";") + struct.pack("<I", type_)
        out += _u(";") + struct.pack("<I", len(data)) + _u(";") + data + _u("]")
    return out


GROUPS = """<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="localadm" changed="2019-01-01 00:00:00">
    <Properties action="U" userName="localadm" cpassword="TEST_ONLY_NOT_A_REAL_PASSWORD"/>
  </User>
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)">
    <Properties action="U" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
      <Members><Member name="CORP\\Domain Users" action="ADD" sid="S-1-5-21-1000-2000-3000-513"/></Members>
    </Properties>
  </Group>
</Groups>"""

AUDIT_CSV = (
    "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\r\n"
    ",System,Audit Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,,3\r\n"
)
