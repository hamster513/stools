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
    "advisory-database.zip": ("ghsa", "ghsa", False),
}
ALL = set(FEEDS)
REF_NAMES = ("epss", "nvd", "exploitdb", "msf", "attack", "kev", "ghsa")


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
        if fixture == "ghsa":
            with zipfile.ZipFile(root / name, "w") as archive:
                archive.writestr("advisory-database-main/README.md", "test snapshot")
            continue
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


def _check_one_zip(path: Path, www: Path, expected: set[str]) -> None:
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        assert sorted(names) == sorted(expected)
        for name in names:
            # Плоский архив: ни папок, ни обратных слэшей — сервер берёт имя как есть.
            assert "/" not in name and "\\" not in name, name
            assert classify(name) == FEEDS[name][0], name
            assert zf.read(name) == (www / name).read_bytes(), name


def _check_zip(path: Path, www: Path, expected: set[str]) -> None:
    ghsa = {"advisory-database.zip"} & expected
    regular = expected - ghsa
    companion = path.with_name(path.stem + "-ghsa.zip")
    if regular and ghsa:
        _check_one_zip(path, www, regular)
        _check_one_zip(companion, www, ghsa)
        with zipfile.ZipFile(companion) as archive:
            assert archive.getinfo("advisory-database.zip").compress_type == zipfile.ZIP_DEFLATED
    else:
        _check_one_zip(path, www, expected)
        assert not companion.exists()


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
def test_ps1_year_range_and_bad_year(tmp_path: Path, www: Path, port: int) -> None:
    """«2019-2021» — три года (2020 на сервере нет: 404, остальные упакованы); мусор — понятная ошибка, код 1."""
    skip = "-Skip epss,exploitdb,msf,attack,kev,ghsa"
    code, log, archive = _ps(tmp_path, port, f"-Years 2019-2021 {skip}")
    assert code == 0, log
    assert "nvdcve-2.0-2020.json.gz (HTTP 404)" in log
    _check_zip(archive, www, _names("nvd"))
    archive.unlink()
    code, log, archive = _ps(tmp_path, port, f"-Years 2019,20x1 {skip}")
    assert code == 1 and "непонятный год в -Years: 20x1" in log, log
    assert not archive.exists()


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
    # OUT без «.zip»: скрипт дописывает расширение сам, и путь в выводе совпадает с файлом.
    full = {"PATH": path or os.environ["PATH"], "HOME": str(tmp_path), "OUT": str(tmp_path / "refs"),
            "VM_REFS_BASE": f"http://127.0.0.1:{port}", "NVD_YEARS": "2019 2021", **env}
    run = subprocess.run(["sh", str(SH)], cwd=tmp_path, env=full, capture_output=True, text=True, timeout=120, check=False)
    return run.returncode, run.stdout + run.stderr, archive


@needs_sh
def test_sh_packs_every_feed(tmp_path: Path, www: Path, port: int) -> None:
    code, log, archive = _sh(tmp_path, port, {})
    assert code == 0, log
    assert "прокси: нет" in log and f"архив: {archive}" in log
    _check_zip(archive, www, ALL)


@needs_sh
def test_sh_skip_and_failed_feed(tmp_path: Path, www: Path, port: int) -> None:
    (www / "known_exploited_vulnerabilities.json").unlink()  # 404 — лента недоступна
    # Значение прокси не печатается; адрес не используется — до 127.0.0.1 curl идёт напрямую.
    code, log, archive = _sh(tmp_path, port, {"SKIP": "epss", "https_proxy": "http://user:secret@proxy.invalid:3128",
                                              "no_proxy": "127.0.0.1"})
    assert code == 0, log
    assert "прокси: из переменных окружения" in log and "secret" not in log and "proxy.invalid" not in log
    assert "known_exploited_vulnerabilities.json" in log and "не вошло" in log
    _check_zip(archive, www, ALL - _names("epss") - _names("kev"))


@needs_sh
def test_sh_nothing_packed_exits_1(tmp_path: Path, port: int) -> None:
    code, log, archive = _sh(tmp_path, port, {"SKIP": "epss nvd exploitdb msf attack", "VM_REFS_BASE": "http://127.0.0.1:1"})
    assert code == 1, log
    assert not archive.exists()


def _bin(tmp_path: Path, tools: tuple[str, ...]) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in tools:
        found = shutil.which(tool)
        assert found, tool
        (bin_dir / tool).symlink_to(found)
    return bin_dir


@pytest.mark.skipif(not shutil.which("curl"), reason="нужен curl")
def test_sh_needs_zip_or_python_before_download(tmp_path: Path, port: int) -> None:
    code, log, archive = _sh(tmp_path, port, {}, path=str(_bin(tmp_path, ("sh", "curl", "date", "tr"))))
    assert code == 1 and "нужен zip или python3" in log, log
    assert "→" not in log and not archive.exists()


@pytest.mark.skipif(not shutil.which("curl"), reason="нужен curl")
def test_sh_falls_back_to_python_zipfile(tmp_path: Path, www: Path, port: int) -> None:
    """Без `zip` в PATH архив собирает python3: каталог с одними нужными утилитами."""
    bin_dir = _bin(tmp_path, ("sh", "curl", "date", "mktemp", "rm", "mv", "mkdir", "tr", "sed", "cat", "wc"))
    (bin_dir / "python3").symlink_to(os.path.realpath(sys.executable))
    code, log, archive = _sh(tmp_path, port, {}, path=str(bin_dir))
    assert code == 0, log
    assert "python3" in log
    _check_zip(archive, www, ALL)


@needs_sh
@pytest.mark.parametrize("skip", ["epss nvd exploitdb msf attack kev", "ghsa"])
def test_sh_one_output_for_single_group(tmp_path: Path, www: Path, port: int, skip: str) -> None:
    code, log, archive = _sh(tmp_path, port, {"SKIP": skip})
    assert code == 0, log
    _check_zip(archive, www, _names("ghsa") if skip != "ghsa" else ALL - _names("ghsa"))


@needs_pwsh
@pytest.mark.parametrize("skip", ["epss,nvd,exploitdb,msf,attack,kev", "ghsa"])
def test_ps1_one_output_for_single_group(tmp_path: Path, www: Path, port: int, skip: str) -> None:
    code, log, archive = _ps(tmp_path, port, f"-Years 2019,2021 -Skip {skip}")
    assert code == 0, log
    _check_zip(archive, www, _names("ghsa") if skip != "ghsa" else ALL - _names("ghsa"))


@needs_sh
def test_sh_refuses_oversized_output(tmp_path: Path, port: int) -> None:
    code, log, archive = _sh(tmp_path, port, {"VM_REFS_MAX_BUNDLE_BYTES": "1"})
    assert code == 1 and "лимит" in log
    assert not archive.exists() and not archive.with_name("refs-ghsa.zip").exists()


@needs_pwsh
def test_ps1_refuses_oversized_output(tmp_path: Path, port: int) -> None:
    code, log, archive = _ps(tmp_path, port, "-Years 2019,2021 -MaxBundleBytes 1")
    assert code == 1 and "лимит" in log
    assert not archive.exists() and not archive.with_name("refs-ghsa.zip").exists()
