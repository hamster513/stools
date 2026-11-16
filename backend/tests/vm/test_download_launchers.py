"""The offline kit must retain executable entry points after ZIP extraction."""

import shutil
import stat
import subprocess
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def test_python_entry_point_runs_directly_from_shell(tmp_path):
    script = tmp_path / "offline_download.py"
    shutil.copy2(ROOT / "frontend/public/offline/offline_download.py", script)
    script.chmod(0o755)
    result = subprocess.run(
        ["/bin/sh", "-c", "./offline_download.py --lang en --help"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "--datasets" in result.stdout


def test_built_zip_retains_safe_modes_and_direct_launchers(tmp_path):
    if not shutil.which("node") or not shutil.which("unzip"):
        pytest.skip("node and unzip required")
    inputs = tmp_path / "input"
    inputs.mkdir()
    for name in ["download-stools.sh", "offline_download.py", "README.md"]:
        shutil.copy2(ROOT / "frontend/public/offline" / name, inputs / name)
    archive = tmp_path / "kit.zip"
    js = """import {pathToFileURL} from 'node:url';
const {writeKit} = await import(pathToFileURL(process.argv[1]));
writeKit(process.argv[2], ['download-stools.sh','offline_download.py','README.md'], process.argv[3]);"""
    command = [
        "node",
        "--input-type=module",
        "-e",
        js,
        str(ROOT / "frontend/scripts/write-kit.mjs"),
        str(inputs),
        str(archive),
    ]
    subprocess.run(command, check=True, capture_output=True, timeout=10)
    first = archive.read_bytes()
    subprocess.run(command, check=True, capture_output=True, timeout=10)
    assert first == archive.read_bytes()
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        for name in z.namelist():
            info = z.getinfo(name)
            assert info.create_system == 3
            expected = 0o755 if name != "README.md" else 0o644
            assert info.external_attr >> 16 == stat.S_IFREG | expected
    output = tmp_path / "extracted"
    subprocess.run(
        ["unzip", "-q", str(archive), "-d", str(output)],
        check=True,
        capture_output=True,
        timeout=10,
    )
    for name in ["offline_download.py", "download-stools.sh"]:
        result = subprocess.run(
            ["/bin/sh", "-c", f"./{name} --lang en --help"],
            cwd=output,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        assert "--datasets" in result.stdout
