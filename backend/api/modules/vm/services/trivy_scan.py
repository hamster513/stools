"""Run the bundled vulnerability scanner on a local CycloneDX document."""

import fcntl
import json
import os
import selectors
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from api.modules.vm.core.host_sbom import bom_bytes

_BUNDLED_CACHE = Path("/opt/trivy-cache")
_SCAN_TIMEOUT = 120
_MAX_REPORT_BYTES = 64 << 20


class ScanError(RuntimeError):
    """Safe to show in an asset status; scanner output can contain private inventory."""


def _run_json(args, directory, timeout, limit):
    deadline = time.monotonic() + timeout
    env = {"HOME": str(directory), "TMPDIR": str(directory), "PATH": os.defpath,
           "TRIVY_DISABLE_TELEMETRY": "true"}
    try:
        with subprocess.Popen(args, cwd=directory, env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
            try:
                data = bytearray()
                with selectors.DefaultSelector() as selector:
                    selector.register(proc.stdout, selectors.EVENT_READ)
                    while True:
                        left = deadline - time.monotonic()
                        if left <= 0 or not selector.select(left):
                            raise ScanError("Превышено время проверки Trivy")
                        chunk = os.read(proc.stdout.fileno(), 65536)
                        if not chunk:
                            break
                        if len(data) + len(chunk) > limit:
                            raise ScanError("Отчёт Trivy превышает допустимый размер")
                        data.extend(chunk)
                if proc.wait(timeout=max(0, deadline - time.monotonic())) != 0:
                    raise ScanError("Trivy завершился с ошибкой")
            finally:
                if proc.poll() is None:
                    proc.kill()
        result = json.loads(data)
    except subprocess.TimeoutExpired:
        raise ScanError("Превышено время проверки Trivy") from None
    except (ValueError, UnicodeError):
        raise ScanError("Некорректный отчёт Trivy") from None
    except OSError:
        raise ScanError("Не удалось запустить Trivy") from None
    if not isinstance(result, dict):
        raise ScanError("Некорректный отчёт Trivy")
    return result


@lru_cache(maxsize=8)
def _scanner_version(binary, binary_signature):
    with tempfile.TemporaryDirectory() as work:
        result = _run_json([binary, "version", "--config=", "--format=json"], work, 10, 65536)
    version = result.get("Version")
    if not isinstance(version, str) or not version or len(version) > 40:
        raise ScanError("Не удалось определить версию Trivy")
    return version


def update_directory(data_dir: Path) -> Path:
    return data_dir / "trivy-updates"


def _original_cache(data_dir):
    local = Path(data_dir) / "trivy"
    return (local if os.path.lexists(local) else _BUNDLED_CACHE).resolve()


def cache_path(data_dir: Path) -> Path:
    pointer = update_directory(data_dir) / "current"
    return pointer.resolve() if os.path.lexists(pointer) else _original_cache(data_dir)


@contextmanager
def locked_cache(data_dir: Path, *, exclusive=False):
    # Pin the active snapshot until the scanner exits; only the pointer swap needs a writer lock.
    try:
        directory = os.open(update_directory(data_dir), os.O_RDONLY | os.O_DIRECTORY)
    except FileNotFoundError:
        if exclusive:
            raise
        yield _original_cache(data_dir)
        return
    try:
        fcntl.flock(directory, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield cache_path(data_dir)
    finally:
        os.close(directory)


def _context(cache):
    binary = shutil.which("trivy")
    if not binary:
        raise ScanError("Trivy не установлен")
    try:
        if not (cache / "db/trivy.db").stat().st_size:
            raise ValueError
        with (cache / "db/metadata.json").open("rb") as stream:
            metadata = json.loads(stream.read(4097))
        schema, updated = metadata["Version"], metadata["UpdatedAt"]
        if schema != 2 or not isinstance(updated, str) or len(updated) > 40:
            raise ValueError
        datetime.fromisoformat(updated)
        stat = os.stat(binary)
        scanner_version = _scanner_version(binary, (stat.st_size, stat.st_mtime_ns))
    except (KeyError, TypeError, ValueError, OSError):
        raise ScanError("База Trivy недоступна или повреждена") from None
    return binary, cache, scanner_version, f"Trivy {scanner_version} / DB v{schema} {updated}"


def database_revision(data_dir: Path) -> str:
    try:
        with locked_cache(data_dir) as cache:
            return _context(cache)[3]
    except ScanError:
        return ""


def scan_bom(bom: dict, data_dir: Path) -> dict:
    with locked_cache(data_dir) as cache:
        return scan_cached(bom, cache)


def scan_cached(bom: dict, cache: Path) -> dict:
    binary, cache, scanner_version, revision = _context(cache)
    eligible = {c["bom-ref"]: c["purl"] for c in bom["components"] if c.get("purl")}
    with tempfile.TemporaryDirectory() as directory:
        sbom = Path(directory) / "inventory.cdx.json"
        sbom.write_bytes(bom_bytes(bom))
        report = _run_json([
            binary, "sbom", "--quiet", "--config=", "--ignorefile=", "--cache-dir", str(cache),
            "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--skip-vex-repo-update",
            "--skip-version-check", "--disable-telemetry", "--scanners=vuln", "--list-all-pkgs",
            "--timeout=2m", "--format=json", str(sbom),
        ], directory, _SCAN_TIMEOUT, _MAX_REPORT_BYTES)
    if (report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "cyclonedx"
            or (eligible and not isinstance(report.get("Results"), list))):
        raise ScanError("Некорректный отчёт Trivy")
    checked = set()
    findings = []
    try:
        for group in report.get("Results", []):
            for pkg in group.get("Packages", []):
                ref = pkg["Identifier"]["BOMRef"]
                if ref not in eligible:
                    raise ValueError
                checked.add(ref)
            for hit in group.get("Vulnerabilities", []):
                ref = hit["PkgIdentifier"]["BOMRef"]
                if ref not in checked:
                    raise ValueError
                findings.append({"vuln_id": hit["VulnerabilityID"], "package": hit["PkgName"],
                                 "installed_version": hit["InstalledVersion"],
                                 "fixed_version": hit.get("FixedVersion", ""),
                                 "severity": hit.get("Severity", "UNKNOWN").lower(),
                                 "purl": eligible[ref]})
    except (AttributeError, KeyError, TypeError, ValueError):
        raise ScanError("Некорректный отчёт пакетов Trivy") from None
    return {"checked": len(checked), "findings": findings, "db_version": revision,
            "scanner_version": scanner_version}
