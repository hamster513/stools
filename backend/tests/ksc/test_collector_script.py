"""Раздача скрипта, BOM, и прогон в контейнере PowerShell против поддельного KSC."""
from __future__ import annotations

import gzip
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.modules.ksc.core.export import load_export
from tests.ksc.fake_ksc import MFA_SECRET, PASSWORD, USER, totp_code
from tests.ksc.synthetic import build_export

SCRIPT = Path("api/modules/ksc/collector/STools-KSC-Collector.ps1")
IMAGE = "mcr.microsoft.com/powershell:lts-alpine-3.20"


def test_collector_script_download(auth_client: TestClient) -> None:
    r = auth_client.get("/api/ksc/collector.ps1")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert "stools-ksc/1" in r.text and "Session.StartSession" in r.text and "KSCBasic" in r.text


def test_collector_script_has_utf8_bom(auth_client: TestClient) -> None:
    assert auth_client.get("/api/ksc/collector.ps1").content.startswith(b"\xef\xbb\xbf")


def _image_present() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, check=False).returncode == 0


def _run_script(tmp_path: Path, port: int, variant: str, config: dict[str, object] | None = None) -> Path:
    """Поднимает поддельный KSC на порту и прогоняет скрипт в контейнере; отдаёт файл выгрузки.

    С `config` скрипт получает только `-ConfigPath`: сервер, учётка, пароль и секрет
    второго фактора берутся из файла."""
    env = {**os.environ, "STOOLS_FAKE_VARIANT": variant}
    server = subprocess.Popen([sys.executable, "-m", "tests.ksc.fake_ksc_http", str(port)], cwd=Path.cwd(), env=env)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        out = tmp_path / (variant or "default")
        out.mkdir()
        docker = ["docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway"]
        mounts = ["-v", f"{SCRIPT.resolve().parent}:/script:ro", "-v", f"{out}:/out", IMAGE, "pwsh", "-File", "/script/STools-KSC-Collector.ps1"]
        if config is None:
            cmd = [*docker, "-e", f"STOOLS_KSC_PASSWORD={PASSWORD}", *mounts, "-Server", "host.docker.internal", "-Port", str(port),
                   "-Scheme", "http", "-User", USER, "-Internal", "-OutputPath", "/out/ksc.json.gz"]
        else:
            (out / "config.json").write_text(json.dumps({**config, "port": port}), encoding="utf-8")
            cmd = [*docker, *mounts, "-ConfigPath", "/out/config.json"]
        run = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
        assert run.returncode == 0, run.stdout + run.stderr
    finally:
        server.terminate()
    return out / "ksc.json.gz"


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_output_matches_online_format(tmp_path: Path) -> None:
    path = _run_script(tmp_path, 18299, "")
    export = load_export(path.read_bytes())
    expected = build_export()
    assert export.format == "stools-ksc/1" and export.server.name == "ksc01" and export.server.collector == "powershell"
    assert len(export.hosts) == len(expected["hosts"]) and {h["KLHST_WKS_DN"] for h in export.hosts} == {h["KLHST_WKS_DN"] for h in expected["hosts"]}
    assert set(export.host_products) == set(expected["host_products"]) and len(export.policies) == 3 and len(export.tasks) == 2 and len(export.licenses) == 1
    assert set(export.effective_policies) == {"0", "1", "2", "3", "4"} and export.static["KLADMSRV_SERVER_HOSTNAME"] == "ksc01"
    raw = json.loads(gzip.decompress(path.read_bytes()))
    assert raw["hosts"][0]["KLHST_WKS_LAST_VISIBLE"]["type"] == "datetime"  # обёртки KSC сохранены как есть


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_survives_missing_fields(tmp_path: Path) -> None:
    """Set-StrictMode: обращение к отсутствующему свойству было бы фатальным."""
    export = load_export(_run_script(tmp_path, 18300, "sparse").read_bytes())
    assert export.server.name == "ksc01" and export.server.version == "" and export.licenses == []
    assert len(export.hosts) == len(build_export()["hosts"])
    ws01 = next(h for h in export.hosts if h["KLHST_WKS_DN"] == "WS01")
    assert "KLHST_WKS_STATUS" not in ws01 and "h-ws01" not in export.host_products  # без статуса агента продукты не спрашиваем


def test_fake_totp_matches_rfc6238() -> None:
    # Вектор из RFC 6238 (SHA1, T=59 с): 94287082 → шесть младших цифр.
    assert totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", at=59) == "287082"


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_passes_second_factor_with_config_file(tmp_path: Path) -> None:
    """KSC с двухфакторным входом: пароль даёт 401 + KSCMFA, сессию — только код TOTP.
    Всё, включая секрет второго фактора, скрипт берёт из файла настроек."""
    config = {"server": "host.docker.internal", "scheme": "http", "user": USER, "password": PASSWORD, "internal": True,
              "totp_secret": MFA_SECRET, "output_path": "/out/ksc.json.gz"}
    export = load_export(_run_script(tmp_path, 18301, "mfa", config).read_bytes())
    assert export.server.name == "ksc01" and len(export.hosts) == len(build_export()["hosts"])
    raw = gzip.decompress((tmp_path / "mfa" / "ksc.json.gz").read_bytes()).decode()
    assert PASSWORD not in raw and MFA_SECRET not in raw  # секреты в выгрузку не попадают


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_writes_config_template(tmp_path: Path) -> None:
    cmd = ["docker", "run", "--rm", "-v", f"{SCRIPT.resolve().parent}:/script:ro", "-v", f"{tmp_path}:/out", IMAGE,
           "pwsh", "-File", "/script/STools-KSC-Collector.ps1", "-InitConfig", "/out/ksc-config.json"]
    run = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    assert run.returncode == 0, run.stdout + run.stderr
    template = json.loads((tmp_path / "ksc-config.json").read_text(encoding="utf-8-sig"))
    assert set(template) == {"server", "port", "user", "password", "internal", "domain", "totp_secret", "skip_tls_check", "skip_products", "page_size", "output_path"}
    assert template["port"] == 13299 and template["password"] == "" and template["totp_secret"] == ""


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_explains_broken_config_and_accepts_directory_output(tmp_path: Path) -> None:
    script = ["-v", f"{SCRIPT.resolve().parent}:/script:ro", "-v", f"{tmp_path}:/out", IMAGE, "pwsh", "-File", "/script/STools-KSC-Collector.ps1"]
    # Одиночная обратная черта перед кавычкой ломает JSON — скрипт должен сказать об этом по-человечески.
    (tmp_path / "bad.json").write_text('{"server": "x", "output_path": ".\\"}'.replace("\\\\", "\\"), encoding="utf-8")
    run = subprocess.run(["docker", "run", "--rm", *script, "-ConfigPath", "/out/bad.json"], capture_output=True, text=True, timeout=120, check=False)
    assert run.returncode != 0 and "не разобран как JSON" in (run.stdout + run.stderr) and "удваивать" in (run.stdout + run.stderr)
    # Каталог вместо файла: выгрузка ложится в него под именем по умолчанию.
    config = {"server": "host.docker.internal", "scheme": "http", "user": USER, "password": PASSWORD, "internal": True, "output_path": "/out/"}  # /out — каталог прогона
    with pytest.raises(FileNotFoundError):
        _run_script(tmp_path, 18302, "", config).read_bytes()  # ksc.json.gz там нет — имя по умолчанию другое
    files = list((tmp_path / "default").glob("ksc-ksc01-*.json.gz"))
    assert len(files) == 1 and load_export(files[0].read_bytes()).server.name == "ksc01"
