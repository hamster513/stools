"""Разбор справочников (спека §6): EPSS, NVD, ExploitDB, Metasploit.

Справочник CTID (CVE → техника ATT&CK) разбирается в `core/attack_map.py`:
он нужен и слою экспозиции, и загрузчику, а к риску отношения не имеет.

Все разборщики потоковые и работают с открытым файлом; gzip снимается
снаружи (`open_maybe_gzip`). Ничего не знают про базу.
"""
from __future__ import annotations

import csv
import datetime as dt
import gzip
import io
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, cast

from api.modules.vm.core.sources import CVE_RE

REF_NAMES = ("epss", "nvd", "exploitdb", "msf", "attack")


def open_maybe_gzip(path: Path) -> IO[bytes]:
    with path.open("rb") as probe:
        magic = probe.read(2)
    if magic == b"\x1f\x8b":
        return cast(IO[bytes], gzip.open(path, "rb"))
    return path.open("rb")


def _text(fh: IO[bytes]) -> IO[str]:
    return io.TextIOWrapper(fh, encoding="utf-8", errors="replace", newline="")


@dataclass
class EpssRecord:
    cve_id: str
    epss: float
    percentile: float


def parse_epss(fh: IO[bytes]) -> Iterator[EpssRecord]:
    """`#model_version…` в первых строках — комментарии, дальше CSV."""
    text = _text(fh)
    lines = (line for line in text if not line.startswith("#"))
    for row in csv.DictReader(lines):
        cve = (row.get("cve") or "").strip().upper()
        if not cve:
            continue
        try:
            yield EpssRecord(cve, float(row.get("epss") or 0), float(row.get("percentile") or 0))
        except ValueError:
            continue


@dataclass
class NvdRecord:
    cve_id: str
    year: int
    cvss_v3: float | None = None
    v3_av: str | None = None
    v3_pr: str | None = None
    v3_ui: str | None = None
    cvss_v2: float | None = None
    v2_av: str | None = None
    v2_ac: str | None = None
    v2_au: str | None = None
    description: str | None = None
    published: dt.date | None = None
    modified: dt.date | None = None


def _date(value: Any) -> dt.date | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(str(value)[:19]).date()
    except ValueError:
        return None


def _float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def nvd_record(cve: dict[str, Any]) -> NvdRecord | None:
    cve_id = str(cve.get("id") or "").upper()
    if not cve_id.startswith("CVE-"):
        return None
    try:
        year = int(cve_id.split("-")[1])
    except (IndexError, ValueError):
        return None
    rec = NvdRecord(cve_id=cve_id, year=year)
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            rec.description = d.get("value")
            break
    metrics = cve.get("metrics") or {}
    v3 = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [None])[0]
    if v3:
        data = v3.get("cvssData") or {}
        rec.cvss_v3 = _float(data.get("baseScore"))
        rec.v3_av = data.get("attackVector")
        rec.v3_pr = data.get("privilegesRequired")
        rec.v3_ui = data.get("userInteraction")
    v2 = (metrics.get("cvssMetricV2") or [None])[0]
    if v2:
        data = v2.get("cvssData") or {}
        rec.cvss_v2 = _float(data.get("baseScore"))
        rec.v2_av = data.get("accessVector")
        rec.v2_ac = data.get("accessComplexity")
        rec.v2_au = data.get("authentication")
    rec.published = _date(cve.get("published"))
    rec.modified = _date(cve.get("lastModified"))
    return rec


def parse_nvd(fh: IO[bytes]) -> Iterator[NvdRecord]:
    """Фид NVD 2.0: `{"vulnerabilities": [{"cve": {...}}]}`, потоково."""
    import ijson

    for item in ijson.items(fh, "vulnerabilities.item"):
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict):
            continue
        rec = nvd_record(cve)
        if rec is not None:
            yield rec


@dataclass
class ExploitRecord:
    exploit_id: int
    type: str
    verified: bool
    published: dt.date | None
    cve_ids: list[str] = field(default_factory=list)


def parse_exploitdb(fh: IO[bytes]) -> Iterator[ExploitRecord]:
    """`files_exploits.csv`: CVE лежат в колонке `codes` через `;`."""
    for row in csv.DictReader(_text(fh)):
        try:
            exploit_id = int(row.get("id") or "")
        except ValueError:
            continue
        codes = row.get("codes") or ""
        cves = sorted({c.upper() for c in CVE_RE.findall(codes)})
        yield ExploitRecord(
            exploit_id=exploit_id,
            type=(row.get("type") or "").strip().lower(),
            verified=(row.get("verified") or "0").strip() in ("1", "true", "True"),
            published=_date(row.get("date_published")),
            cve_ids=cves,
        )


@dataclass
class MsfRecord:
    fullname: str
    name: str
    rank: int
    cve_ids: list[str] = field(default_factory=list)


def parse_msf(fh: IO[bytes]) -> Iterator[MsfRecord]:
    """`modules_metadata_base.json`: объект «путь модуля → описание»,
    ссылки — пары `["CVE", "2021-44228"]`."""
    import ijson

    for key, info in ijson.kvitems(fh, ""):
        if not isinstance(info, dict):
            continue
        cves: set[str] = set()
        for ref in info.get("references") or []:
            if isinstance(ref, list) and len(ref) == 2 and str(ref[0]).upper() == "CVE":
                cves.add(f"CVE-{ref[1]}".upper())
            elif isinstance(ref, str):
                cves.update(c.upper() for c in CVE_RE.findall(ref))
        try:
            rank = int(info.get("rank") or 0)
        except (TypeError, ValueError):
            rank = 0
        yield MsfRecord(
            fullname=str(info.get("fullname") or key),
            name=str(info.get("name") or ""),
            rank=rank,
            cve_ids=sorted(cves),
        )
