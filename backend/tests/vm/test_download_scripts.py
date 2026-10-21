"""Скрипты скачивания справочников (спека 2026-10-21 §3, §8): один zip с именами, которые узнаёт `classify`.

Настоящие ленты здесь не качаются: адреса подменяются на локальный http.server с фикстурами,
переименованными в настоящие имена файлов. PowerShell — в контейнере (как у сборщика AD),
sh — прямо на хосте.
"""
from __future__ import annotations

import functools
import gzip
import os
import shutil
import subprocess
import sys
import threading
import zipfile
from collections.abc import Iterator
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from api.modules.vm.services.bundle import classify

FIXTURES = Path(__file__).parent / "fixtures"
SCRIPTS = Path(__file__).resolve().parents[3] / "frontend" / "public" / "vm"
PS1 = SCRIPTS / "download-references.ps1"
SH = SCRIPTS / "download-references.sh"
IMAGE = "mcr.microsoft.com/powershell:lts-alpine-3.20"
CTID_JSON = "kev-07.28.2025_attack-16.1-enterprise.json"
CTID_CSV = "Att&ckToCveMappings.csv"

#: Имя в архиве → (справочник, фикстура, сжать gzip-ом).
FEEDS: dict[str, tuple[str, str, bool]] = {
    "epss_scores-current.csv.gz": ("epss", "epss.csv", True),
    "nvdcve-2.0-2019.json.gz": ("nvd", "nvd-2019.json", True),
    "nvdcve-2.0-2021.json.gz": ("nvd", "nvd-2021.json", True),
    "files_exploits.csv": ("exploitdb", "exploits.csv", False),
    "modules_metadata_base.json": ("msf", "msf.json", False),
    CTID_JSON: ("attack", "ctid-kev.json", False),
    CTID_CSV: ("attack", "attack_to_cve.csv", False),
    "known_exploited_vulnerabilities.json": ("kev", "kev.json", False),
}
ALL = set(FEEDS)
REF_NAMES = ("epss", "nvd", "exploitdb", "msf", "attack", "kev")


def _names(feed: str) -> set[str]:
    return {name for name, (ref, _, _) in FEEDS.items() if ref == feed}


class _Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def www(tmp_path: Path) -> Path:
    root = tmp_path / "www"
    root.mkdir()
    for name, (_, fixture, gz) in FEEDS.items():
        data = (FIXTURES / fixture).read_bytes()
        (root / name).write_bytes(gzip.compress(data) if gz else data)
    return root


@pytest.fixture
def port(www: Path) -> Iterator[int]:
    # 0.0.0.0: контейнер ходит на хост через host-gateway, как в тесте сборщика AD.
    server = ThreadingHTTPServer(("0.0.0.0", 0), functools.partial(_Quiet, directory=str(www)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()


def _check_zip(path: Path, www: Path, expected: set[str]) -> None:
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        assert sorted(names) == sorted(expected)
        for name in names:
            # Плоский архив: ни папок, ни обратных слэшей — сервер берёт имя как есть.
            assert "/" not in name and "\\" not in name, name
            assert classify(name) == FEEDS[name][0], name
            assert zf.read(name) == (www / name).read_bytes(), name


# --- PowerShell в контейнере -------------------------------------------------------------------


def _image_present() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, check=False).returncode == 0


needs_pwsh = pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")


def _ps(tmp_path: Path, port: int, args: str, bases: dict[str, str] | None = None) -> tuple[int, str, Path]:
    """Запуск через -Command: хеш-таблицу -BaseUrls через -File не передать."""
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    urls = {name: f"http://host.docker.internal:{port}" for name in REF_NAMES} | (bases or {})
    table = "; ".join(f"{k} = '{v}'" for k, v in urls.items())
    command = f"& /s/{PS1.name} -Out /out/refs.zip {args} -BaseUrls @{{ {table} }}; exit $LASTEXITCODE"
    cmd = ["docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway",
           "-v", f"{SCRIPTS}:/s:ro", "-v", f"{out}:/out", IMAGE, "pwsh", "-NoProfile", "-Command", command]
    run = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
    return run.returncode, run.stdout + run.stderr, out / "refs.zip"


def test_ps1_has_bom_and_no_disabled_tls_checks() -> None:
    raw = PS1.read_bytes()
    # Без BOM Windows PowerShell 5.1 читает файл в ANSI и портит русский текст.
    assert raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8-sig")
    assert "ServerCertificateValidationCallback" not in text and "SkipCertificateCheck" not in text
    assert "STools-references/1" in text and "GetSystemWebProxy" in text


@needs_pwsh
def test_ps1_packs_every_feed(tmp_path: Path, www: Path, port: int) -> None:
    code, log, archive = _ps(tmp_path, port, "-Years 2019,2021")
    assert code == 0, log
    assert "прокси: системный" in log
    _check_zip(archive, www, ALL)


@needs_pwsh
def test_ps1_skip_and_failed_feed(tmp_path: Path, www: Path, port: int) -> None:
    """-Skip исключает ленту; закрытый порт — предупреждение, остальное упаковано, код 0."""
    code, log, archive = _ps(tmp_path, port, "-Years 2019 -Skip epss -NoProxy", {"kev": "http://127.0.0.1:1"})
    assert code == 0, log
    assert "прокси: нет" in log
    assert "known_exploited_vulnerabilities.json" in log and "не вошло" in log
    _check_zip(archive, www, ALL - _names("epss") - _names("kev") - {"nvdcve-2.0-2021.json.gz"})


@needs_pwsh
def test_ps1_nothing_packed_exits_1(tmp_path: Path, port: int) -> None:
    skip = ",".join(n for n in REF_NAMES if n != "kev")
    code, log, archive = _ps(tmp_path, port, f"-Skip {skip}", {"kev": "http://127.0.0.1:1"})
    assert code == 1, log
    assert not archive.exists()


# --- sh на хосте -------------------------------------------------------------------------------

needs_sh = pytest.mark.skipif(not shutil.which("curl") or not (shutil.which("zip") or shutil.which("python3")),
                              reason="нужны curl и zip или python3")


def _sh(tmp_path: Path, port: int, env: dict[str, str], path: str | None = None) -> tuple[int, str, Path]:
    archive = tmp_path / "refs.zip"
    full = {"PATH": path or os.environ["PATH"], "HOME": str(tmp_path), "OUT": str(archive),
            "VM_REFS_BASE": f"http://127.0.0.1:{port}", "NVD_YEARS": "2019 2021", **env}
    run = subprocess.run(["sh", str(SH)], cwd=tmp_path, env=full, capture_output=True, text=True, timeout=120, check=False)
    return run.returncode, run.stdout + run.stderr, archive


@needs_sh
def test_sh_packs_every_feed(tmp_path: Path, www: Path, port: int) -> None:
    code, log, archive = _sh(tmp_path, port, {})
    assert code == 0, log
    _check_zip(archive, www, ALL)


@needs_sh
def test_sh_skip_and_failed_feed(tmp_path: Path, www: Path, port: int) -> None:
    (www / "known_exploited_vulnerabilities.json").unlink()  # 404 — лента недоступна
    code, log, archive = _sh(tmp_path, port, {"SKIP": "epss"})
    assert code == 0, log
    assert "known_exploited_vulnerabilities.json" in log and "не вошло" in log
    _check_zip(archive, www, ALL - _names("epss") - _names("kev"))


@needs_sh
def test_sh_nothing_packed_exits_1(tmp_path: Path, port: int) -> None:
    code, log, archive = _sh(tmp_path, port, {"SKIP": "epss nvd exploitdb msf attack", "VM_REFS_BASE": "http://127.0.0.1:1"})
    assert code == 1, log
    assert not archive.exists()


@pytest.mark.skipif(not shutil.which("curl"), reason="нужен curl")
def test_sh_falls_back_to_python_zipfile(tmp_path: Path, www: Path, port: int) -> None:
    """Без `zip` в PATH архив собирает python3: каталог с одними нужными утилитами."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("sh", "curl", "date", "mktemp", "rm", "mv", "mkdir", "tr", "sed", "cat"):
        found = shutil.which(tool)
        assert found, tool
        (bin_dir / tool).symlink_to(found)
    (bin_dir / "python3").symlink_to(os.path.realpath(sys.executable))
    code, log, archive = _sh(tmp_path, port, {}, path=str(bin_dir))
    assert code == 0, log
    assert "python3" in log
    _check_zip(archive, www, ALL)
