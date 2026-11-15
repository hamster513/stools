"""Portable, stdlib-only STools reference updates; shared by API and offline kit.

Full snapshots must establish source checkpoints first for NVD/GHSA. This module
never falls back to a complete NVD feed or GHSA ZIP in updates mode.
"""
from __future__ import annotations

# Python 3.9 compatibility; all untrusted wire validation intentionally raises ValueError.
# ruff: noqa: UP017, FURB162, TRY004
import argparse
import copy
import csv
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener, urlopen

Json = dict[str, Any]
Progress = Callable[[str], None]

MANIFEST_NAME = "stools-reference-update.json"
MAX_BUNDLE_BYTES = 524288000
MAX_UNPACKED_BYTES = 1024 * 1024 * 1024
MAX_FILES = 100000
MAX_RESPONSE_BYTES = 128 * 1024 * 1024
GHSA_REPOSITORY = "https://github.com/github/advisory-database.git"
GHSA_RAW = "https://raw.githubusercontent.com/github/advisory-database"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_ID = re.compile(r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}")
CVE_ID = re.compile(r"CVE-(\d{4})-\d{4,}")
SHA256 = re.compile(r"[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{40}")
_CTID = "https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/"
SNAPSHOTS = {
    "epss": (("epss_scores-current.csv.gz", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"),),
    "kev": (("known_exploited_vulnerabilities.json", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),),
    "exploitdb": (("files_exploits.csv", "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"),),
    "msf": (("modules_metadata_base.json", "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"),),
    "attack": (
        ("kev-07.28.2025_attack-16.1-enterprise.json", _CTID + "mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json"),
        ("Att&ckToCveMappings.csv", _CTID + "src/mapex_convert/mappings/Att%26ckToCveMappings.csv"),
    ),
}
SOURCES = ("nvd", "ghsa", *SNAPSHOTS)


def _date(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("checkpoint timestamp must be ISO8601")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("checkpoint timestamp must be ISO8601") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)  # NVD timestamps are UTC without Z.
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def validate_checkpoint(name: str, checkpoint: object) -> None:
    """Validate a non-null source checkpoint without importing backend code."""
    if name not in SOURCES or not isinstance(checkpoint, dict):
        raise ValueError("unknown source or invalid checkpoint")
    if name == "ghsa":
        if set(checkpoint) != {"revision"} or not isinstance(checkpoint["revision"], str) or not REVISION.fullmatch(checkpoint["revision"]):
            raise ValueError("GHSA checkpoint requires an exact 40-character Git revision")
    elif name == "nvd":
        if set(checkpoint) != {"cursor", "years"}:
            raise ValueError("NVD checkpoint requires cursor and years")
        cursor = _date(checkpoint["cursor"])
        years = checkpoint["years"]
        if cursor.year < 2002 or not isinstance(years, list) or not years or len(years) > 200:
            raise ValueError("invalid NVD checkpoint")
        # The 2002 feed also contains CVE identifiers from 1999 through 2001.
        if any(type(year) is not int or not 1999 <= year <= 2200 for year in years) or len(set(years)) != len(years):
            raise ValueError("invalid NVD checkpoint years")
    else:
        if set(checkpoint) != {"validators"} or not isinstance(checkpoint["validators"], dict):
            raise ValueError("snapshot checkpoint requires validators")
        known_urls = {url for _, url in SNAPSHOTS[name]}
        for url, validators in checkpoint["validators"].items():
            if url not in known_urls or not isinstance(validators, dict) or set(validators) - {"etag", "last_modified", "sha256"}:
                raise ValueError("invalid snapshot source identity or validators")
            for key, value in validators.items():
                if not isinstance(value, str) or len(value) > 2048 or "\n" in value or "\r" in value:
                    raise ValueError("invalid HTTP validator")
                if key == "sha256" and not SHA256.fullmatch(value):
                    raise ValueError("invalid snapshot digest")


def validate_state(state: object) -> None:
    if not isinstance(state, dict) or set(state) != {"format", "version", "sources"} or state.get("format") != "stools-reference-state" or type(state.get("version")) is not int or state["version"] != 1 or not isinstance(state.get("sources"), dict):
        raise ValueError("unsupported reference state format/version")
    for name, checkpoint in state["sources"].items():
        if name not in SOURCES:
            raise ValueError("unknown reference source")
        if checkpoint is not None:
            validate_checkpoint(name, checkpoint)


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes


class HttpClient:
    """Capped reads and finite retries; NVD uses its public no-key rate limit."""

    def __init__(self, *, opener: Callable[..., Any] | None = None,
                 sleep: Callable[[float], None] = time.sleep, progress: Progress | None = None,
                 proxies: dict[str, str] | None = None) -> None:
        self.opener = opener or (build_opener(ProxyHandler(proxies)).open if proxies is not None else urlopen)
        self.sleep = sleep
        self.progress = progress or (lambda message: None)
        self.last_nvd: float | None = None

    def __call__(self, url: str, headers: dict[str, str]) -> HttpResponse:
        for attempt in range(4):
            self.progress("HTTP: " + url.split("?", 1)[0])
            if url.startswith(NVD_API) and self.last_nvd is not None:
                self._wait(max(0.0, 6.1 - (time.monotonic() - self.last_nvd)))
            if url.startswith(NVD_API):
                self.last_nvd = time.monotonic()
            try:
                request = Request(url, headers={"User-Agent": "STools-reference-updates/1", **headers})
                with self.opener(request, timeout=60) as reply:
                    parts = []
                    size = 0
                    while True:
                        self.progress("Reading " + url.split("?", 1)[0])
                        chunk = reply.read(1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > MAX_RESPONSE_BYTES:
                            raise ValueError("upstream response exceeds safe size limit")
                        parts.append(chunk)
                    return HttpResponse(reply.status, dict(reply.headers), b"".join(parts))
            except HTTPError as exc:
                if exc.code == 304:
                    return HttpResponse(304, dict(exc.headers), b"")
                if exc.code not in (429, 500, 502, 503, 504) or attempt == 3:
                    raise ValueError("upstream HTTP error " + str(exc.code)) from exc
                retry = exc.headers.get("Retry-After", "") if exc.headers else ""
                delay = min(120.0, float(retry)) if retry.isdigit() else min(60.0, 2.0 ** attempt)
            except (URLError, TimeoutError, ConnectionError) as exc:
                if attempt == 3:
                    raise ValueError("upstream request failed after retries") from exc
                delay = min(60.0, 2.0 ** attempt)
            self.progress("Retrying upstream request")
            self._wait(delay)
        raise ValueError("upstream request exhausted retries")


    def _wait(self, delay: float) -> None:
        while delay > 0:
            self.progress("Waiting for upstream rate limit")
            pause = min(1.0, delay)
            self.sleep(pause)
            delay -= pause


def _json(body: bytes) -> Json:
    try:
        result = json.loads(body)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("upstream returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise ValueError("upstream JSON must be an object")
    return result


def _path(path: str) -> str:
    if not isinstance(path, str) or len(path) > 512 or "\\" in path or "\x00" in path or path.startswith("/") or any(part in ("", ".", "..") for part in path.split("/")):
        raise ValueError("unsafe payload path")
    return path


def _advisory_id(path: str) -> str:
    _path(path)
    parts = PurePosixPath(path).parts
    advisory = PurePosixPath(path).stem
    if len(parts) != 6 or parts[4] != advisory or parts[0] != "advisories" or parts[1] not in ("github-reviewed", "unreviewed") or not re.fullmatch(r"\d{4}", parts[2]) or not re.fullmatch(r"\d{2}", parts[3]) or not path.endswith(".json") or not GHSA_ID.fullmatch(advisory):
        raise ValueError("invalid GHSA advisory path")
    return advisory


class GitAdvisorySource:
    """A bare, shallow, blob-filtered Git cache; no checkout, hooks or blob fetch."""

    def __init__(self, cache_dir: Path | str, progress: Progress | None = None, *,
                 remote: str = GHSA_REPOSITORY, proxies: dict[str, str] | None = None) -> None:
        self.path = Path(cache_dir) / "ghsa.git"
        self.progress = progress or (lambda message: None)
        self.remote = remote
        self.proxies = proxies

    def _git(self, *args: str, packet: bool = False) -> tuple[bytes, bytes]:
        self.progress("GHSA Git: " + args[0])
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "https:file"})
        if self.proxies is not None:
            # Match urllib's explicit policy without changing the parent process.
            # Credentials stay in child environment, never argv or progress text.
            env = {key: value for key, value in env.items()
                   if not key.lower().endswith("_proxy") or key.lower() == "no_proxy"}
            for scheme in ("http", "https"):
                if scheme in self.proxies:
                    env[scheme + "_proxy"] = self.proxies[scheme]
            proxy = self.proxies.get("https", "")
            env.update({"GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "http.proxy",
                        "GIT_CONFIG_VALUE_0": proxy, "GIT_CONFIG_KEY_1": "remote.origin.proxy",
                        "GIT_CONFIG_VALUE_1": proxy})
        if packet:
            env["GIT_TRACE_PACKET"] = "1"
        try:
            # File capture bounds memory for unexpectedly noisy/malicious upstreams.
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
                process = subprocess.Popen(["git", "-c", "core.hooksPath=" + os.devnull,
                    "-c", "protocol.version=2", "-c", "credential.helper=", "-C", str(self.path), *args],
                    env=env, stdout=output, stderr=error)
                started = time.monotonic()
                try:
                    while process.poll() is None:
                        self.progress("Waiting for GHSA Git: " + args[0])
                        if time.monotonic() - started > 180:
                            raise ValueError("GHSA Git request timed out")
                        try:
                            process.wait(timeout=0.5)
                        except subprocess.TimeoutExpired:
                            pass
                except BaseException:
                    process.kill()
                    process.wait()
                    raise
                if output.tell() > 32 * 1024 * 1024 or error.tell() > 4 * 1024 * 1024:
                    raise ValueError("Git response exceeds safe size limit")
                output.seek(0)
                error.seek(0)
                stdout, stderr = output.read(), error.read()
            if process.returncode:
                raise ValueError("GHSA Git command failed: " + args[0] + "; base checkpoint may be unavailable")
            if b"filtering not recognized" in stderr:
                raise ValueError("GHSA Git remote must support blob filtering")
            return stdout, stderr
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("GHSA updates require Git and reachable pinned base/target revisions") from exc

    def changes(self, base: str) -> tuple[str, list[str], list[str]]:
        if not isinstance(base, str) or not REVISION.fullmatch(base):
            raise ValueError("invalid GHSA base checkpoint")
        self.path.mkdir(parents=True, exist_ok=True)
        if not (self.path / "HEAD").exists():
            self._git("init", "--bare")
            self._git("config", "remote.origin.url", self.remote)
            self._git("config", "remote.origin.promisor", "true")
            self._git("config", "remote.origin.partialclonefilter", "blob:none")
        actual, _ = self._git("config", "--get", "remote.origin.url")
        bare, _ = self._git("rev-parse", "--is-bare-repository")
        if actual.decode().strip() != self.remote or bare.strip() != b"true":
            raise ValueError("GHSA Git cache has incompatible source identity")
        for item in (self.path / "objects").rglob("*"):
            if item.is_symlink():
                raise ValueError("GHSA Git cache must not contain symbolic links")
        self._check_size()
        refs, trace = self._git("ls-remote", "--exit-code", "origin", "refs/heads/main", packet=True)
        if not re.search(rb"fetch=[^\r\n]*\bfilter\b", trace):
            raise ValueError("GHSA Git remote does not advertise required blob filtering")
        target = refs.split(b"\t", 1)[0].decode()
        if not REVISION.fullmatch(target):
            raise ValueError("GHSA remote returned invalid target revision")
        if target == base:
            return target, [], []
        for revision in (base, target):
            self._git("fetch", "--depth=1", "--filter=blob:none", "--no-tags", "--no-write-fetch-head", "origin", revision)
            self._check_size()
            resolved, _ = self._git("rev-parse", "--verify", revision + "^{commit}")
            if resolved.strip().decode() != revision:
                raise ValueError("GHSA pinned revision mismatch")
        raw, _ = self._git("diff", "--name-status", "-z", "--no-renames", base, target, "--", "advisories")
        tokens = raw.split(b"\0")
        if tokens[-1] != b"" or (len(tokens) - 1) % 2:
            raise ValueError("invalid Git tree diff")
        changed, deleted = [], []
        for index in range(0, len(tokens) - 1, 2):
            status, path = tokens[index].decode(), tokens[index + 1].decode()
            if not path.endswith(".json"):
                continue
            _advisory_id(path)
            if status in ("A", "M"):
                changed.append(path)
            elif status == "D":
                deleted.append(path)
            else:
                raise ValueError("unsupported GHSA tree change " + status)
            if len(changed) + len(deleted) > MAX_FILES:
                raise ValueError("GHSA delta exceeds safe file count; create a fresh full baseline")
        return target, changed, deleted

    def _check_size(self) -> None:
        if sum(item.stat().st_size for item in self.path.rglob("*") if item.is_file()) > MAX_BUNDLE_BYTES:
            raise ValueError("GHSA Git cache exceeds size limit; remove the cache and retry")


class _Payloads:
    def __init__(self, archive: zipfile.ZipFile, progress: Progress) -> None:
        self.archive, self.progress = archive, progress
        self.paths: set[str] = set()
        self.size = 0

    def add(self, path: str, body: bytes) -> dict[str, str]:
        _path(path)
        self.progress("Packing " + path)
        if path in self.paths or len(self.paths) >= MAX_FILES or len(body) > MAX_RESPONSE_BYTES:
            raise ValueError("duplicate or oversized payload")
        self.size += len(body)
        if self.size > MAX_UNPACKED_BYTES:
            raise ValueError("update bundle exceeds unpacked size limit")
        self.paths.add(path)
        self.archive.writestr(path, body)
        return {"path": path, "sha256": hashlib.sha256(body).hexdigest()}


def _nvd(base: Json, now: datetime, http: Callable[[str, dict[str, str]], HttpResponse],
         payloads: _Payloads) -> tuple[Json, list[dict[str, str]], list[str]]:
    since = _date(base["cursor"])
    if since > now:
        raise ValueError("NVD checkpoint is later than this check")
    years = sorted(set(base["years"]) | set(range(since.year + 1, now.year + 1)))
    files, deleted = _nvd_window(since - timedelta(minutes=2), now, years, http, payloads)
    return {"cursor": _iso(now), "years": years}, files, deleted


def _nvd_window(since: datetime, now: datetime, years: Iterable[int],
                http: Callable[[str, dict[str, str]], HttpResponse], payloads: _Payloads, *,
                exclude_since: bool = False) -> tuple[list[dict[str, str]], list[str]]:
    """Collect bounded native pages, optionally excluding the initial boundary."""
    start = since
    files = []
    years = set(years)
    seen: dict[str, str] = {}
    window = 0
    while start < now:
        # Smaller ranges avoid expensive deep NVD offsets while staying below its 120-day cap.
        end = min(start + timedelta(days=7), now)
        offset, total, page = 0, None, 0
        window_ids = set()
        while total is None or offset < total:
            query = urlencode({"lastModStartDate": _iso(start), "lastModEndDate": _iso(end),
                               "startIndex": offset, "resultsPerPage": 2000})
            reply = http(NVD_API + "?" + query, {})
            if reply.status != 200:
                raise ValueError("NVD page request failed")
            data = _json(reply.body)
            rows = data.get("vulnerabilities")
            count = data.get("totalResults")
            if type(count) is not int or not 0 <= count <= 1000000 or data.get("startIndex") != offset or not isinstance(rows, list) or len(rows) > 2000 or (total is not None and count != total):
                raise ValueError("inconsistent NVD pagination")
            total = count
            if (not rows and offset < total) or offset + len(rows) > total:
                raise ValueError("incomplete NVD page")
            selected = []
            for row in rows:
                cve = row.get("cve") if isinstance(row, dict) else None
                identifier = cve.get("id") if isinstance(cve, dict) else None
                match = CVE_ID.fullmatch(identifier) if isinstance(identifier, str) else None
                if not isinstance(cve, dict) or match is None or not isinstance(identifier, str):
                    raise ValueError("invalid NVD CVE record")
                modified = _date(cve.get("lastModified"))
                if not start <= modified <= end:
                    raise ValueError("NVD record outside requested modification window")
                if identifier in window_ids:
                    raise ValueError("duplicate NVD ID within paginated window")
                window_ids.add(identifier)
                fingerprint = hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                if identifier in seen:
                    if seen[identifier] != fingerprint:
                        raise ValueError("NVD record changed between windows; retry")
                    continue
                seen[identifier] = fingerprint
                if len(seen) > 1000000:
                    raise ValueError("NVD delta exceeds safe row count")
                if int(match.group(1)) in years and not (exclude_since and modified == since):
                    selected.append(row)
            if selected:
                content = {**data, "vulnerabilities": selected}
                files.append(payloads.add(f"nvd/updates-{window:03d}-{page:04d}.json", json.dumps(content, separators=(",", ":")).encode()))
            offset += len(rows)
            page += 1
        start = end
        window += 1
        if window > 512:
            raise ValueError("NVD checkpoint is too old")
    return files, []


def _ghsa(base: Json, http: Callable[[str, dict[str, str]], HttpResponse], payloads: _Payloads,
          provider: GitAdvisorySource) -> tuple[Json, list[dict[str, str]], list[str]]:
    target, changed, removed = provider.changes(base["revision"])
    files, deleted = _ghsa_payloads(target, changed, removed, http, payloads)
    return {"revision": target}, files, deleted


def _ghsa_payloads(target: str, changed: Iterable[str], removed: Iterable[str],
                   http: Callable[[str, dict[str, str]], HttpResponse],
                   payloads: _Payloads) -> tuple[list[dict[str, str]], list[str]]:
    """Preserve native OSV bytes and distinguish moves from real deletions."""
    files, upserts = [], set()
    for path in changed:
        advisory = _advisory_id(path)
        reply = http(GHSA_RAW + "/" + target + "/" + path, {})
        if reply.status != 200 or len(reply.body) > 4 * 1024 * 1024:
            raise ValueError("GHSA advisory request failed or is oversized")
        data = _json(reply.body)
        if data.get("id") != advisory or not isinstance(data.get("affected"), list):
            raise ValueError("invalid native GHSA OSV record")
        _date(data.get("modified"))
        if advisory in upserts:
            raise ValueError("duplicate GHSA ID in target tree")
        upserts.add(advisory)
        files.append(payloads.add(path, reply.body))
    deleted = sorted({_advisory_id(path) for path in removed} - upserts)
    return files, deleted


def _validate_snapshot(name: str, filename: str, body: bytes) -> None:
    if filename.endswith(".gz"):
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
            plain = stream.read(MAX_RESPONSE_BYTES + 1)
        if len(plain) > MAX_RESPONSE_BYTES:
            raise ValueError("snapshot exceeds expanded size limit")
        body = plain
    if filename.endswith(".json"):
        data = _json(body)
        if name == "kev" and not isinstance(data.get("vulnerabilities"), list):
            raise ValueError("invalid KEV snapshot")
        if name == "attack":
            rows = data.get("mapping_objects")
            required = {"capability_id", "attack_object_id", "mapping_type"}
            if not isinstance(rows, list) or any(
                not isinstance(row, dict) or any(not isinstance(row.get(key), str) for key in required)
                for row in rows
            ):
                raise ValueError("invalid ATTACK snapshot: native CTID mapping_objects required")
    else:
        try:
            csv_stream = io.StringIO(body.decode("utf-8-sig"))
            lines: Iterable[str] = csv_stream if name == "attack" else (line for line in csv_stream if not line.startswith("#"))
            header = next(csv.reader(lines))
        except (UnicodeError, StopIteration, csv.Error) as exc:
            raise ValueError("invalid CSV snapshot") from exc
        if name == "attack" and not {"CVE ID", "Primary Impact", "Secondary Impact", "Exploitation Technique"}.issubset(header):
            raise ValueError("invalid ATTACK snapshot: native CTID CSV columns required")
        required = {"epss": {"cve", "epss", "percentile"}, "exploitdb": {"id", "file", "codes"}}.get(name, set())
        if not header or not required.issubset({column.lower() for column in header}):
            raise ValueError("invalid snapshot CSV header")


def _has_attack_mapping(filename: str, body: bytes) -> bool:
    """Check native mapping semantics; target-bundle membership is checked by the importer."""
    technique_pattern = r"T[0-9]{4}(?:\.[0-9]{3})?"
    if filename.endswith(".json"):
        supported = {"exploitation_technique", "primary_impact", "secondary_impact"}
        return any(
            CVE_ID.fullmatch(row["capability_id"].upper())
            and re.fullmatch(technique_pattern, row["attack_object_id"])
            and row["mapping_type"] in supported
            for row in _json(body)["mapping_objects"]
        )
    columns = ("Primary Impact", "Secondary Impact", "Exploitation Technique")
    for row in csv.DictReader(io.StringIO(body.decode("utf-8-sig"), newline="")):
        if not CVE_ID.fullmatch((row.get("CVE ID") or "").strip().upper()):
            continue
        if any(re.fullmatch(technique_pattern, technique.strip())
               for column in columns for technique in (row.get(column) or "").split(";")):
            return True
    return False


def _snapshots(name: str, base: Json | None, http: Callable[[str, dict[str, str]], HttpResponse],
               payloads: _Payloads, cache: Path) -> tuple[Json, list[dict[str, str]], list[str]]:
    old = (base or {}).get("validators", {})
    validators, fetched = {}, {}
    changed = base is None
    cache.mkdir(parents=True, exist_ok=True)
    for filename, url in SNAPSHOTS[name]:
        previous = old.get(url, {})
        headers = {}
        if previous.get("etag"):
            headers["If-None-Match"] = previous["etag"]
        if previous.get("last_modified"):
            headers["If-Modified-Since"] = previous["last_modified"]
        reply = http(url, headers)
        if reply.status == 304:
            if not headers or not previous.get("sha256"):
                raise ValueError("unverifiable 304 without prior source digest")
            validators[url] = copy.deepcopy(previous)
            continue
        if reply.status != 200:
            raise ValueError("snapshot request failed")
        _validate_snapshot(name, filename, reply.body)
        digest = hashlib.sha256(reply.body).hexdigest()
        response_headers = {key.lower(): value for key, value in reply.headers.items()}
        current = {"sha256": digest}
        for source, key in (("etag", "etag"), ("last-modified", "last_modified")):
            if response_headers.get(source):
                current[key] = response_headers[source]
        validators[url] = current
        fetched[url] = reply.body
        changed = changed or previous.get("sha256") != digest
        cache_path = cache / digest
        if not cache_path.exists():
            _atomic_write(cache_path, reply.body)
    keep = {item["sha256"] for item in validators.values()}
    for cached in cache.iterdir():
        if cached.is_file() and SHA256.fullmatch(cached.name) and cached.name not in keep:
            cached.unlink()
    if not changed:
        return {"validators": validators}, [], []
    files = []
    has_mapping = name != "attack"
    for filename, url in SNAPSHOTS[name]:
        body = fetched.get(url)
        if body is None:
            digest = validators[url]["sha256"]
            cached = cache / digest
            if cached.exists() and cached.stat().st_size <= MAX_RESPONSE_BYTES:
                body = cached.read_bytes()
            else:
                reply = http(url, {})
                if reply.status != 200:
                    raise ValueError("snapshot companion unavailable")
                body = reply.body
            if hashlib.sha256(body).hexdigest() != digest:
                raise ValueError("snapshot companion changed during update; retry")
            _validate_snapshot(name, filename, body)
        if name == "attack":
            has_mapping = has_mapping or _has_attack_mapping(filename, body)
        files.append(payloads.add(filename, body))
    if not has_mapping:
        raise ValueError("no supported ATTACK mappings in snapshot")
    return {"validators": validators}, files, []


def _sync_directory(path: Path) -> None:
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _atomic_write(path: Path, body: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".ref-state-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def build_update_bundle(
    out_path: Path | str, state: Json, sources: Iterable[str], cache_dir: Path | str,
    progress: Progress | None = None, *,
    http: Callable[[str, dict[str, str]], HttpResponse] | None = None,
    now: datetime | None = None, github: GitAdvisorySource | None = None,
    max_bytes: int = MAX_BUNDLE_BYTES, proxies: dict[str, str] | None = None,
) -> tuple[Json, Json]:
    """Return (manifest, next_state) after atomically publishing a new immutable ZIP.

    proxies=None inherits defaults; {} disables proxies for HTTP and Git.
    Does not mutate input state or persist a cursor. progress(message) may raise
    to cancel; injected transports are intended for bounded deterministic tests.
    """
    validate_state(state)
    sources = list(sources)
    if not sources or len(set(sources)) != len(sources) or any(name not in SOURCES for name in sources):
        raise ValueError("unknown, repeated, or empty source selection")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_BUNDLE_BYTES:
        raise ValueError("bundle limit cannot exceed 500 MiB")
    for name in sources:
        if name in ("nvd", "ghsa") and not state["sources"].get(name):
            raise ValueError(name + " updates require a trusted full-import checkpoint")
    out_path, cache_dir = Path(out_path), Path(cache_dir)
    if out_path.exists():
        raise FileExistsError("update archive already exists; use a new output filename")
    progress = progress or (lambda message: None)
    http = http or HttpClient(progress=progress, proxies=proxies)
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    next_state = copy.deepcopy(state)
    manifest: Json = {"format": "stools-reference-update", "version": 1, "created_at": _iso(now), "sources": []}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".ref-update-", suffix=".zip", dir=out_path.parent)
    os.close(descriptor)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            payloads = _Payloads(archive, progress)
            for name in sources:
                progress("Checking " + name)
                base = state["sources"].get(name)
                if name == "nvd":
                    target, files, deleted = _nvd(base, now, http, payloads)
                elif name == "ghsa":
                    target, files, deleted = _ghsa(base, http, payloads, github or GitAdvisorySource(cache_dir, progress, proxies=proxies))
                else:
                    target, files, deleted = _snapshots(name, base, http, payloads, cache_dir / "snapshots" / name)
                validate_checkpoint(name, target)
                mode = ("delta" if name in ("nvd", "ghsa") else "snapshot") if files or deleted else "unchanged"
                manifest["sources"].append({"name": name, "mode": mode, "base": base, "target": target, "files": files, "deleted_ids": deleted})
                next_state["sources"][name] = target
            archive.writestr(MANIFEST_NAME, json.dumps(manifest, ensure_ascii=False, separators=(",", ":")))
        if Path(temporary).stat().st_size > max_bytes:
            raise ValueError("update archive exceeds 500 MiB/server configured limit; select fewer sources")
        progress("Publishing update archive")
        with open(temporary, "rb") as stream:
            os.fsync(stream.fileno())
        os.link(temporary, out_path)  # Atomic create, refuses to overwrite a previous transfer.
        _sync_directory(out_path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return manifest, next_state


def run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path, help="STools exported state; advanced only after durable output")
    parser.add_argument("--out", required=True, type=Path, help="new immutable update ZIP")
    parser.add_argument("--sources", nargs="+", choices=SOURCES, default=list(SOURCES))
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--max-bytes", type=int, default=MAX_BUNDLE_BYTES)
    parser.add_argument("--no-proxy", action="store_true")
    args = parser.parse_args(argv)
    if args.out.exists():
        raise FileExistsError("update archive already exists; choose a new output filename")
    if args.state.stat().st_size > 1024 * 1024:
        raise ValueError("state file too large")
    lock = args.state.with_name(args.state.name + ".lock")
    descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    try:
        state = json.loads(args.state.read_text(encoding="utf-8"))
        progress = lambda message: print(message, file=sys.stderr, flush=True)
        manifest, next_state = build_update_bundle(args.out, state, args.sources,
            args.cache or args.state.parent / ".stools-reference-cache", progress,
            max_bytes=args.max_bytes, proxies={} if args.no_proxy else None)
        _atomic_write(args.state, (json.dumps(next_state, ensure_ascii=False, indent=2) + "\n").encode())
        print("Created " + str(args.out) + "; sources: " + ", ".join(item["name"] + "=" + item["mode"] for item in manifest["sources"]))
        return 0
    finally:
        lock.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        sys.exit(run_cli())
    except (ValueError, OSError, zipfile.BadZipFile, EOFError) as error:
        print("Update failed: " + str(error), file=sys.stderr)
        sys.exit(1)
