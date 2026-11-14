"""Bounded OSV reader for github/advisory-database repository ZIP snapshots.

No member is extracted. Metadata, aliases and package ranges are retained even
when an advisory has no CVE, no package identity, or has been withdrawn.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import stat
import struct
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from cvss import CVSS2, CVSS3, CVSS4, CVSSError

MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_ENTRIES = 1_000_000
MAX_CENTRAL_BYTES = 256 * 1024 * 1024
GHSA_ID = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE)


@dataclass
class GhsaRecord:
    ghsa_id: str
    summary: str
    description: str
    cvss: float | None
    cvss_version: str
    cvss_vector: str
    severity: str
    published: dt.datetime | None
    modified: dt.datetime | None
    withdrawn: dt.datetime | None
    reviewed: bool
    references: list[dict[str, Any]]
    cwes: list[str]
    aliases: list[str] = field(default_factory=list)
    packages: list[dict[str, Any]] = field(default_factory=list)


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("GHSA: expected an object")  # noqa: TRY004 — invalid feed data
    return value


def _list(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError("GHSA: expected a list")  # noqa: TRY004 — invalid feed data
    return value


def _string(value: Any, limit: int | None = None) -> str:
    if not isinstance(value, str) or "\x00" in value or (limit is not None and len(value) > limit):
        raise ValueError("GHSA: invalid string")
    return value


def _strings(value: Any) -> list[str]:
    return list(dict.fromkeys(_string(item) for item in _list(value)))


def _identifier(value: Any) -> str:
    value = _string(value, 128)
    if GHSA_ID.fullmatch(value):
        return "GHSA-" + value[5:].lower()
    if value.upper().startswith("CVE-"):
        return value.upper()
    return value


def _date(value: Any) -> dt.datetime | None:
    if value is None:
        return None
    parsed = dt.datetime.fromisoformat(_string(value))
    return parsed.replace(tzinfo=dt.UTC) if parsed.tzinfo is None else parsed.astimezone(dt.UTC)


def _metrics(value: Any) -> tuple[float | None, str, str]:
    candidates = [_object(item) for item in _list(value)]
    priority = {"CVSS_V4": 4, "CVSS_V3": 3, "CVSS_V2": 2}
    candidates.sort(key=lambda item: priority.get(item.get("type", ""), 0), reverse=True)
    fallback: tuple[float | None, str, str] = (None, "", "")
    for item in candidates:
        kind, vector = item.get("type"), _string(item.get("score", ""))
        if kind not in priority or not vector:
            continue
        version = vector.split("/", 1)[0].removeprefix("CVSS:") if vector.startswith("CVSS:") else "2.0"
        if not fallback[2]:
            fallback = (None, version[:16], vector)
        try:
            calculator = {"CVSS_V4": CVSS4, "CVSS_V3": CVSS3, "CVSS_V2": CVSS2}[kind]
            score = float(calculator(vector).scores()[0])
            return score, version, vector
        except CVSSError:
            # Upstream occasionally contains incomplete vectors: retain them as
            # evidence but do not invent a numerical score.
            continue
    return fallback


def parse_advisory(value: Any, *, reviewed: bool) -> GhsaRecord:
    row = _object(value)
    identifier = _identifier(row.get("id"))
    if not GHSA_ID.fullmatch(identifier):
        raise ValueError("GHSA: invalid advisory id")
    metadata = _object(row.get("database_specific", {}))
    cvss, version, vector = _metrics(row.get("severity", []))
    severity = _string(metadata.get("severity") or "unknown").lower()
    severity = {"moderate": "medium"}.get(severity, severity)
    if severity not in {"none", "low", "medium", "high", "critical"}:
        severity = "unknown"
    references = [_object(item) for item in _list(row.get("references", []))]
    for reference in references:
        _string(reference.get("url"))
        _string(reference.get("type", ""))
    packages = []
    for position, affected_value in enumerate(_list(row.get("affected", []))):
        affected = _object(affected_value)
        package = _object(affected.get("package", {}))
        ranges = [_object(item) for item in _list(affected.get("ranges", []))]
        fixed = []
        for interval in ranges:
            _string(interval.get("type"))
            for event in _list(interval.get("events", [])):
                for key, event_version in _object(event).items():
                    _string(event_version)
                    if key == "fixed" and event_version not in fixed:
                        fixed.append(event_version)
        purl = package.get("purl")
        packages.append({
            "position": position, "ecosystem": _string(package.get("ecosystem", ""), 64),
            "name": _string(package.get("name", "")),
            "purl": _string(purl) if purl is not None else None,
            "ranges": ranges, "versions": _strings(affected.get("versions", [])),
            "fixed_versions": fixed,
        })
    return GhsaRecord(
        ghsa_id=identifier, summary=_string(row.get("summary", "")),
        description=_string(row.get("details", "")), cvss=cvss,
        cvss_version=version, cvss_vector=vector, severity=severity,
        published=_date(row.get("published")), modified=_date(row.get("modified")),
        withdrawn=_date(row.get("withdrawn")), reviewed=reviewed,
        references=references, cwes=_strings(metadata.get("cwe_ids", [])),
        aliases=list(dict.fromkeys(_identifier(item) for item in _list(row.get("aliases", []))
                                   if item != identifier)), packages=packages,
    )


def _preflight(path: Path, *, max_entries: int | None = None, max_central_bytes: int | None = None,
               max_archive_bytes: int | None = None) -> None:
    """Bound actual directory records before ZipFile allocates its ZipInfo list.

    Only ordinary single-disk ZIP/ZIP64 snapshots are accepted. Footer and
    central-directory fields follow PKWARE APPNOTE 4.3.12–4.3.16; member
    decoding, decompression and CRC validation remain with stdlib zipfile.
    """
    entries_limit = MAX_ENTRIES if max_entries is None else max_entries
    central_limit = MAX_CENTRAL_BYTES if max_central_bytes is None else max_central_bytes
    archive_limit = MAX_ARCHIVE_BYTES if max_archive_bytes is None else max_archive_bytes
    size = path.stat().st_size
    if size > archive_limit:
        raise ValueError("GHSA archive exceeds size limit")
    with path.open("rb") as stream:
        start = max(0, size - 65557)  # 22-byte EOCD + maximum ZIP comment.
        stream.seek(start)
        tail = stream.read(65557)
        offset = tail.rfind(b"PK\x05\x06")
        if offset < 0 or len(tail) - offset < 22:
            raise ValueError("Invalid GHSA ZIP footer")
        _, disk, directory_disk, local_count, count, central_size, central_offset, comment = struct.unpack_from("<4s4H2LH", tail, offset)
        footer_offset = start + offset
        if offset + 22 + comment != len(tail) or disk or directory_disk:
            raise ValueError("Invalid or multi-disk GHSA ZIP footer")
        if count == 65535 or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
            if footer_offset < 20:
                raise ValueError("Invalid GHSA ZIP64 locator")
            stream.seek(footer_offset - 20)
            signature, disk, zip64_offset, disks = struct.unpack("<4sLQL", stream.read(20))
            if signature != b"PK\x06\x07" or disk or disks != 1 or zip64_offset > footer_offset - 76:
                raise ValueError("Invalid GHSA ZIP64 locator")
            stream.seek(zip64_offset)
            header = stream.read(56)
            if len(header) != 56:
                raise ValueError("Invalid GHSA ZIP64 footer")
            signature, record_size, _, _, disk, directory_disk, local_count, count, central_size, central_offset = struct.unpack("<4sQ2H2L4Q", header)
            if (signature != b"PK\x06\x06" or record_size < 44 or disk or directory_disk
                    or zip64_offset + 12 + record_size != footer_offset - 20):
                raise ValueError("Invalid GHSA ZIP64 footer")
            footer_offset = zip64_offset
        if count > entries_limit or central_size > central_limit:
            raise ValueError("GHSA archive exceeds directory limit")
        if local_count != count or central_offset + central_size > footer_offset:
            raise ValueError("Invalid GHSA ZIP directory bounds")
        # Declared counts can lie. Scan the fixed headers using bounded reads
        # before allowing ZipFile to construct one Python object per entry.
        stream.seek(central_offset)
        end = central_offset + central_size
        actual = 0
        while stream.tell() < end:
            header = stream.read(46)
            if len(header) != 46 or header[:4] != b"PK\x01\x02":
                raise ValueError("Invalid GHSA ZIP directory entry")
            name_size, extra_size, comment_size = struct.unpack_from("<3H", header, 28)
            next_offset = stream.tell() + name_size + extra_size + comment_size
            if next_offset > end:
                raise ValueError("Invalid GHSA ZIP directory size")
            stream.seek(next_offset)
            actual += 1
            if actual > entries_limit:
                raise ValueError("GHSA archive exceeds entry limit")
        if actual != count:
            raise ValueError("Invalid GHSA ZIP entry count")


def iter_advisories(path: Path) -> Iterator[GhsaRecord]:
    _preflight(path)
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ENTRIES:
                raise ValueError("GHSA archive exceeds entry limit")
            total = 0
            paths: set[str] = set()
            count = 0
            for info in infos:
                name = info.orig_filename
                parts = PurePosixPath(name).parts
                mode = info.external_attr >> 16
                if (name.startswith("/") or "\\" in name or "\x00" in name
                        or ".." in parts or stat.S_ISLNK(mode)):
                    raise ValueError("GHSA archive has unsafe path")
                if name in paths:
                    raise ValueError("GHSA archive has duplicate path")
                paths.add(name)
                total += info.file_size
                if info.file_size > MAX_MEMBER_BYTES or total > MAX_TOTAL_BYTES:
                    raise ValueError("GHSA archive exceeds unpacked size limit")
                if info.is_dir():
                    continue
                if info.flag_bits & 1:
                    raise ValueError("GHSA archive contains encrypted members")
                if len(parts) < 4 or parts[1] != "advisories" or parts[2] not in {"github-reviewed", "unreviewed"}:
                    continue
                if not name.endswith(".json"):
                    continue
                with archive.open(info) as member:
                    raw = member.read(MAX_MEMBER_BYTES + 1)
                if len(raw) > MAX_MEMBER_BYTES:
                    raise ValueError("GHSA member exceeds size limit")
                record = parse_advisory(json.loads(raw), reviewed=parts[2] == "github-reviewed")
                if _identifier(PurePosixPath(name).stem) != record.ghsa_id:
                    raise ValueError("GHSA filename and advisory id disagree")
                count += 1
                yield record
            if not count:
                raise ValueError("GHSA archive contains no advisories")
    except (zipfile.BadZipFile, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid GHSA archive or JSON") from exc
