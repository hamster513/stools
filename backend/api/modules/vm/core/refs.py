"""Разбор справочников (спека §6): EPSS, NVD, ExploitDB, Metasploit, CISA KEV.

Справочник CTID (CVE → техника ATT&CK) разбирается в `core/attack_map.py`:
он нужен и слою экспозиции, и загрузчику, а к риску отношения не имеет.

Все разборщики работают с открытым файлом; gzip снимается снаружи
(`open_maybe_gzip`), потолок распакованного объёма — `limited`. Ничего не знают
про базу. Потоковые все, кроме KEV: каталог мал (1–2 МБ) и читается целиком.
"""
from __future__ import annotations

import csv
import datetime as dt
import gzip
import io
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, cast

from api.modules.vm.core.sources import CVE_RE

REF_NAMES = ("epss", "nvd", "exploitdb", "msf", "attack", "kev", "ghsa")
# Trivy updates the scanner database on disk, outside the scoring catalogs.
DOWNLOADABLE_REFS = ("trivy", "oval", *REF_NAMES)


def open_maybe_gzip(path: Path) -> IO[bytes]:
    with path.open("rb") as probe:
        magic = probe.read(2)
    if magic == b"\x1f\x8b":
        return cast(IO[bytes], gzip.open(path, "rb"))
    return path.open("rb")


def _size(n: int) -> str:
    return f"{n // (1024 * 1024)} МБ" if n >= 1024 * 1024 else f"{n} байт"


class _Capped(io.RawIOBase):
    """Счётчик прочитанных байт поверх файла: gzip-бомба (мегабайт сжатого — гигабайты
    распакованного) останавливается на лимите, а не на конце диска или памяти."""

    def __init__(self, inner: IO[bytes], max_bytes: int) -> None:
        self._inner = inner
        self._max = max_bytes
        self._read = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        data = self._inner.read(len(buffer))
        self._read += len(data)
        if self._read > self._max:
            raise ValueError(f"файл справочника после распаковки больше лимита ({_size(self._max)}), загрузка прервана")
        buffer[: len(data)] = data
        return len(data)


def limited(fh: IO[bytes], max_bytes: int) -> IO[bytes]:
    """Тот же поток, но не больше `max_bytes` прочитанных байт: дальше — ValueError."""
    return cast(IO[bytes], io.BufferedReader(_Capped(fh, max_bytes)))


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
    configurations: list[dict[str, Any]] = field(default_factory=list)


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
    configs = cve.get("configurations")
    if isinstance(configs, list) and cve.get("vulnStatus") != "Rejected":
        rec.configurations = configs
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


@dataclass
class KevRecord:
    cve_id: str
    date_added: dt.date | None
    ransomware: bool
    vendor: str
    product: str
    name: str
    due_date: dt.date | None


def _kev_record(row: dict[str, Any]) -> KevRecord | None:
    cve = str(row.get("cveID") or "").strip().upper()
    if not cve.startswith("CVE-"):
        return None
    return KevRecord(
        cve_id=cve,
        date_added=_date(row.get("dateAdded")),
        # Known | Unknown — флаг только для подтверждённого использования вымогателями.
        ransomware=str(row.get("knownRansomwareCampaignUse") or "").strip().lower() == "known",
        vendor=str(row.get("vendorProject") or ""),
        product=str(row.get("product") or ""),
        name=str(row.get("vulnerabilityName") or ""),
        due_date=_date(row.get("dueDate")),
    )


def parse_kev(fh: IO[bytes]) -> Iterator[KevRecord]:
    """Каталог CISA KEV: JSON (`{"vulnerabilities": [...]}`) или CSV с теми же именами
    колонок. Формат — по первому непробельному байту, а не по имени файла: в архиве и
    при загрузке файлом расширение может быть любым."""
    data = fh.read()
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    if data.lstrip()[:1] in (b"{", b"["):
        doc = json.loads(data)
        items = doc.get("vulnerabilities") if isinstance(doc, dict) else doc
        rows = [i for i in items or [] if isinstance(i, dict)]
    else:
        rows = list(csv.DictReader(io.StringIO(data.decode("utf-8", errors="replace"), newline="")))
    for row in rows:
        rec = _kev_record(row)
        if rec is not None:
            yield rec
