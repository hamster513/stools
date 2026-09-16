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
from tests.ksc.fake_ksc import PASSWORD, USER
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


def _run_script(tmp_path: Path, port: int, variant: str) -> Path:
    """Поднимает поддельный KSC на порту и прогоняет скрипт в контейнере; отдаёт файл выгрузки."""
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
        cmd = [
            "docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway",
            "-v", f"{SCRIPT.resolve().parent}:/script:ro", "-v", f"{out}:/out", IMAGE,
            "pwsh", "-File", "/script/STools-KSC-Collector.ps1", "-Server", "host.docker.internal", "-Port", str(port), "-Scheme", "http",
            "-User", USER, "-PlainPassword", PASSWORD, "-Internal", "-OutputPath", "/out/ksc.json.gz",
        ]
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
