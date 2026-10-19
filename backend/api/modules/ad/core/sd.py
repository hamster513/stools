"""Разбор nTSecurityDescriptor (MS-DTYP 2.4.6): владелец и DACL.

`Get-Acl AD:\\` в прототипе — это ровно чтение этого атрибута; здесь тот же
разбор без Windows API. SACL и флаги наследования контейнера не нужны:
проверки смотрят только на ACE в DACL.
"""
from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field

# Права ActiveDirectoryRights (System.DirectoryServices).
CREATE_CHILD = 0x1
DELETE_CHILD = 0x2
LIST_CHILDREN = 0x4
SELF_WRITE = 0x8
READ_PROPERTY = 0x10
WRITE_PROPERTY = 0x20
DELETE_TREE = 0x40
LIST_OBJECT = 0x80
EXTENDED_RIGHT = 0x100
DELETE = 0x10000
READ_CONTROL = 0x20000
WRITE_DACL = 0x40000
WRITE_OWNER = 0x80000
GENERIC_ALL = 0x10000000
GENERIC_EXECUTE = 0x20000000
GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000

RIGHT_NAMES: list[tuple[int, str]] = [
    (GENERIC_ALL, "GenericAll"),
    (GENERIC_WRITE, "GenericWrite"),
    (GENERIC_READ, "GenericRead"),
    (GENERIC_EXECUTE, "GenericExecute"),
    (WRITE_DACL, "WriteDacl"),
    (WRITE_OWNER, "WriteOwner"),
    (READ_CONTROL, "ReadControl"),
    (DELETE, "Delete"),
    (EXTENDED_RIGHT, "ExtendedRight"),
    (WRITE_PROPERTY, "WriteProperty"),
    (READ_PROPERTY, "ReadProperty"),
    (CREATE_CHILD, "CreateChild"),
    (DELETE_CHILD, "DeleteChild"),
    (DELETE_TREE, "DeleteTree"),
    (LIST_CHILDREN, "ListChildren"),
    (LIST_OBJECT, "ListObject"),
    (SELF_WRITE, "Self"),
]

ACE_ALLOWED = 0x00
ACE_DENIED = 0x01
ACE_ALLOWED_OBJECT = 0x05
ACE_DENIED_OBJECT = 0x06

ACE_FLAG_INHERITED = 0x10
ACE_FLAG_INHERIT_ONLY = 0x08

OBJ_TYPE_PRESENT = 0x1
OBJ_INHERITED_TYPE_PRESENT = 0x2


def describe_rights(mask: int) -> list[str]:
    return [name for bit, name in RIGHT_NAMES if mask & bit]


def sid_to_str(data: bytes) -> str:
    """Бинарный SID → S-1-5-21-…; MS-DTYP 2.4.2.2."""
    if len(data) < 8:
        raise ValueError("SID короче заголовка")
    revision, count = data[0], data[1]
    authority = int.from_bytes(data[2:8], "big")
    if len(data) < 8 + 4 * count:
        raise ValueError("SID обрезан")
    subs = struct.unpack_from(f"<{count}I", data, 8)
    return "S-" + "-".join(str(x) for x in (revision, authority, *subs))


def sid_len(data: bytes, offset: int) -> int:
    return 8 + 4 * data[offset + 1]


def str_to_sid(text: str) -> bytes:
    parts = text.split("-")
    if len(parts) < 3 or parts[0] != "S":
        raise ValueError(f"не SID: {text}")
    revision, authority = int(parts[1]), int(parts[2])
    subs = [int(p) for p in parts[3:]]
    return bytes([revision, len(subs)]) + authority.to_bytes(6, "big") + struct.pack(f"<{len(subs)}I", *subs)


@dataclass
class Ace:
    type: int
    flags: int
    mask: int
    sid: str
    object_type: uuid.UUID | None = None
    inherited_object_type: uuid.UUID | None = None

    @property
    def allow(self) -> bool:
        return self.type in (ACE_ALLOWED, ACE_ALLOWED_OBJECT)

    @property
    def inherited(self) -> bool:
        return bool(self.flags & ACE_FLAG_INHERITED)

    @property
    def inherit_only(self) -> bool:
        return bool(self.flags & ACE_FLAG_INHERIT_ONLY)

    def has(self, right: int) -> bool:
        return bool(self.mask & right)

    @property
    def rights(self) -> list[str]:
        return describe_rights(self.mask)


@dataclass
class SecurityDescriptor:
    owner: str | None = None
    group: str | None = None
    dacl: list[Ace] = field(default_factory=list)


def _parse_acl(data: bytes, offset: int) -> list[Ace]:
    _rev, _sbz1, _size, count, _sbz2 = struct.unpack_from("<BBHHH", data, offset)
    aces: list[Ace] = []
    pos = offset + 8
    for _ in range(count):
        ace_type, ace_flags, ace_size = struct.unpack_from("<BBH", data, pos)
        body = pos + 4
        if ace_type in (ACE_ALLOWED, ACE_DENIED):
            (mask,) = struct.unpack_from("<I", data, body)
            sid = sid_to_str(data[body + 4 : body + 4 + sid_len(data, body + 4)])
            aces.append(Ace(ace_type, ace_flags, mask, sid))
        elif ace_type in (ACE_ALLOWED_OBJECT, ACE_DENIED_OBJECT):
            mask, obj_flags = struct.unpack_from("<II", data, body)
            cursor = body + 8
            object_type = inherited_type = None
            if obj_flags & OBJ_TYPE_PRESENT:
                object_type = uuid.UUID(bytes_le=data[cursor : cursor + 16])
                cursor += 16
            if obj_flags & OBJ_INHERITED_TYPE_PRESENT:
                inherited_type = uuid.UUID(bytes_le=data[cursor : cursor + 16])
                cursor += 16
            sid = sid_to_str(data[cursor : cursor + sid_len(data, cursor)])
            aces.append(Ace(ace_type, ace_flags, mask, sid, object_type, inherited_type))
        # Остальные типы (audit, callback…) проверкам не нужны — пропускаем.
        pos += ace_size
    return aces


def parse_sd(data: bytes) -> SecurityDescriptor:
    """Self-relative дескриптор: заголовок с offset'ами владельца, группы, SACL, DACL."""
    if len(data) < 20:
        raise ValueError("дескриптор короче заголовка")
    _rev, _sbz, control, off_owner, off_group, _off_sacl, off_dacl = struct.unpack_from("<BBHIIII", data, 0)
    sd = SecurityDescriptor()
    if off_owner:
        sd.owner = sid_to_str(data[off_owner : off_owner + sid_len(data, off_owner)])
    if off_group:
        sd.group = sid_to_str(data[off_group : off_group + sid_len(data, off_group)])
    if off_dacl and control & 0x0004:  # SE_DACL_PRESENT
        sd.dacl = _parse_acl(data, off_dacl)
    return sd


# ---- Сборка дескриптора: нужна тестам и синтетической выгрузке ----------


def build_ace(
    sid: str,
    mask: int,
    *,
    allow: bool = True,
    flags: int = 0,
    object_type: uuid.UUID | None = None,
    inherited_object_type: uuid.UUID | None = None,
) -> bytes:
    sid_b = str_to_sid(sid)
    if object_type is None and inherited_object_type is None:
        body = struct.pack("<I", mask) + sid_b
        ace_type = ACE_ALLOWED if allow else ACE_DENIED
    else:
        obj_flags = (OBJ_TYPE_PRESENT if object_type else 0) | (OBJ_INHERITED_TYPE_PRESENT if inherited_object_type else 0)
        body = struct.pack("<II", mask, obj_flags)
        if object_type:
            body += object_type.bytes_le
        if inherited_object_type:
            body += inherited_object_type.bytes_le
        body += sid_b
        ace_type = ACE_ALLOWED_OBJECT if allow else ACE_DENIED_OBJECT
    return struct.pack("<BBH", ace_type, flags, 4 + len(body)) + body


def build_sd(aces: list[bytes], owner: str | None = "S-1-5-32-544") -> bytes:
    """owner=None — дескриптор без владельца и группы (прочитан без OWNER_SECURITY_INFORMATION)."""
    owner_b = str_to_sid(owner) if owner else b""
    acl_body = b"".join(aces)
    acl = struct.pack("<BBHHH", 2, 0, 8 + len(acl_body), len(aces), 0) + acl_body
    header_len = 20
    off_owner = header_len if owner else 0
    off_group = header_len + len(owner_b) if owner else 0
    off_dacl = header_len + 2 * len(owner_b)
    control = 0x8004  # SE_SELF_RELATIVE | SE_DACL_PRESENT
    header = struct.pack("<BBHIIII", 1, 0, control, off_owner, off_group, 0, off_dacl)
    return header + owner_b + owner_b + acl
