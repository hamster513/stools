from __future__ import annotations

import uuid

import pytest

from api.modules.ad.core import sd

DCSYNC_ALL = uuid.UUID("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
DA = "S-1-5-21-1-2-3-512"
USER = "S-1-5-21-1-2-3-1105"


def test_sid_roundtrip() -> None:
    for s in ("S-1-5-32-544", "S-1-1-0", "S-1-5-21-3623811015-3361044348-30300820-1013"):
        assert sd.sid_to_str(sd.str_to_sid(s)) == s
    with pytest.raises(ValueError):
        sd.str_to_sid("nope")


def test_parse_object_ace_and_plain_ace() -> None:
    blob = sd.build_sd(
        [
            sd.build_ace(DA, sd.EXTENDED_RIGHT, object_type=DCSYNC_ALL),
            sd.build_ace(USER, sd.GENERIC_ALL | sd.WRITE_DACL, flags=sd.ACE_FLAG_INHERITED),
            sd.build_ace("S-1-1-0", sd.READ_PROPERTY, allow=False),
        ],
        owner=DA,
    )
    parsed = sd.parse_sd(blob)
    assert parsed.owner == DA and parsed.group == DA
    assert len(parsed.dacl) == 3
    dcsync, ga, deny = parsed.dacl
    assert dcsync.allow and dcsync.object_type == DCSYNC_ALL and dcsync.has(sd.EXTENDED_RIGHT) and not dcsync.inherited
    assert ga.sid == USER and ga.inherited and ga.rights == ["GenericAll", "WriteDacl"]
    assert not deny.allow and deny.sid == "S-1-1-0"


def test_unknown_ace_types_are_skipped() -> None:
    # Audit-ACE (тип 2) между двумя обычными: размер известен, тело пропускается.
    import struct

    audit = struct.pack("<BBH", 2, 0, 4 + 4 + len(sd.str_to_sid(USER))) + struct.pack("<I", 1) + sd.str_to_sid(USER)
    blob = sd.build_sd([sd.build_ace(DA, sd.GENERIC_WRITE), audit, sd.build_ace(USER, sd.WRITE_OWNER)])
    parsed = sd.parse_sd(blob)
    assert [a.sid for a in parsed.dacl] == [DA, USER]


def test_short_blob_rejected() -> None:
    with pytest.raises(ValueError):
        sd.parse_sd(b"\x01\x00")
