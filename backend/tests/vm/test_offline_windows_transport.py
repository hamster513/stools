"""Native HTTP worker fixtures; PS7 on Unix does not verify Windows PAC/domain auth."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

WORKER = Path(__file__).resolve().parents[3] / "frontend/public/offline/system-http.ps1"
IMAGE = "mcr.microsoft.com/powershell:lts-alpine-3.20"


@pytest.fixture(scope="module")
def runtime() -> str:
    native = shutil.which("pwsh") or shutil.which("powershell")
    if native:
        return native
    if shutil.which("docker"):
        result = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", IMAGE],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if result.returncode == 0:
            return "docker:" + result.stdout.strip()
    pytest.skip("PowerShell or the existing PowerShell Docker image is required")


@pytest.fixture
def server() -> Iterator[tuple[int, list[dict[str, str]]]]:
    requests: list[dict[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: Any) -> None:
            pass

        def do_GET(self) -> None:
            requests.append(dict(self.headers))
            path = urlsplit(self.path).path
            body, status, headers = b"fixture-data", 200, {}
            if path == "/redirect":
                status, headers = 302, {"Location": "/ok"}
            elif path == "/cross-origin":
                status, headers = 302, {"Location": self.headers["X-Test-Destination"]}
            elif path == "/loop":
                status, headers = 302, {"Location": "/loop"}
            elif path == "/unsafe":
                status, headers = 302, {"Location": "file:///private/fixture-secret"}
            elif path == "/credential-redirect":
                status, headers = 302, {"Location": "http://fixture:secret@example.invalid/"}
            elif path == "/big" or path == "/stream":
                body = b"x" * 4096
            elif path == "/cached":
                status, body = 304, b""
                headers["ETag"] = '"fixture-etag"'
            elif path == "/error":
                status, body = 503, b"private-server-error"
            elif path == "/slow":
                time.sleep(2)
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            if path != "/stream":
                self.send_header("Content-Length", str(4096 if path == "/cached" else len(body)))
            self.end_headers()
            if path == "/slow-body":
                time.sleep(2)
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    httpd = ThreadingHTTPServer(("0.0.0.0", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd.server_port, requests
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


def _url(runtime: str, port: int, path: str = "/ok") -> str:
    host = "host.docker.internal" if runtime.startswith("docker:") else "127.0.0.1"
    return f"http://{host}:{port}{path}"


def _run(
    runtime: str, tmp_path: Path, url: str, *, env: dict[str, str] | None = None,
    **changes: Any,
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any], bytes | None]:
    prefix = "/work" if runtime.startswith("docker:") else str(tmp_path)
    request = {
        "action": "fetch", "url": url, "headers": {"User-Agent": "STools-offline-fixture"},
        "response_path": f"{prefix}/response.bin", "metadata_path": f"{prefix}/metadata.json",
        "max_bytes": 1024, "timeout": 5, "no_proxy": True,
    } | changes
    (tmp_path / "request.json").write_text(json.dumps(request), encoding="utf-8")
    child_env = {
        key: value for key, value in os.environ.items()
        if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
    } | (env or {})
    if runtime.startswith("docker:"):
        command = [
            "docker", "run", "--rm", "--platform", runtime.split(":", 1)[1],
            "--add-host=host.docker.internal:host-gateway",
            "-v", f"{WORKER.parent}:/scripts:ro", "-v", f"{tmp_path}:/work",
        ]
        for key, value in (env or {}).items():
            command += ["-e", f"{key}={value}"]
        command += [IMAGE, "pwsh", "-NoProfile", "-NonInteractive", "-File",
                    "/scripts/system-http.ps1", "-RequestFile", "/work/request.json"]
    else:
        command = [runtime, "-NoProfile", "-NonInteractive", "-File", str(WORKER),
                   "-RequestFile", str(tmp_path / "request.json")]
    result = subprocess.run(
        command, capture_output=True, text=True, env=child_env, timeout=25, check=False,
    )
    metadata_path = tmp_path / "metadata.json"
    metadata = json.loads(metadata_path.read_text("utf-8-sig")) if metadata_path.exists() else {}
    response = tmp_path / "response.bin"
    body = response.read_bytes() if response.exists() else None
    return result, metadata, body


def test_worker_native_proxy_credentials_and_tls_contract() -> None:
    source = WORKER.read_text(encoding="utf-8-sig")
    assert "GetSystemWebProxy" in source
    assert "DefaultNetworkCredentials" in source
    assert "DefaultProxyCredentials" in source
    assert "UseDefaultCredentials = $false" in source
    assert "UseProxy = $false" in source
    assert "AllowAutoRedirect = $false" in source
    assert "ServerCertificateCustomValidationCallback" not in source
    assert "ServerCertificateValidationCallback" not in source
    assert "SkipCertificateCheck" not in source
    assert "Read-Host" not in source


@pytest.mark.parametrize("path,status,body", [
    ("/ok", 200, b"fixture-data"), ("/redirect", 200, b"fixture-data"),
    ("/cached", 304, b""), ("/error", 503, b"private-server-error"),
])
def test_fetch_streams_status_and_headers(
    runtime: str, tmp_path: Path, server: tuple[int, list[dict[str, str]]],
    path: str, status: int, body: bytes,
) -> None:
    result, metadata, actual = _run(runtime, tmp_path, _url(runtime, server[0], path))
    assert result.returncode == 0, result.stderr
    assert result.stdout == result.stderr == ""
    assert metadata["status"] == status
    assert metadata["bytes"] == len(body)
    assert actual == body
    assert metadata["final_url"].endswith("/ok" if path == "/redirect" else path)
    if status == 304:
        assert metadata["headers"]["etag"] == '"fixture-etag"'
    assert server[1][-1]["User-Agent"] == "STools-offline-fixture"


@pytest.mark.parametrize("path,error", [
    ("/big", "response_too_large"), ("/stream", "response_too_large"),
    ("/loop", "redirect_limit"), ("/unsafe", "invalid_url"),
    ("/credential-redirect", "invalid_url"),
])
def test_fetch_rejects_unsafe_or_unbounded_responses(
    runtime: str, tmp_path: Path, server: tuple[int, list[dict[str, str]]],
    path: str, error: str,
) -> None:
    result, metadata, body = _run(runtime, tmp_path, _url(runtime, server[0], path))
    assert result.returncode == 1
    assert metadata == {"error": error}
    assert body is None
    assert result.stdout == result.stderr == ""
    assert len(server[1]) <= 6
    assert sorted(path.name for path in tmp_path.iterdir()) == ["metadata.json", "request.json"]


@pytest.mark.parametrize("url", ["file:///private/fixture-secret", "http://fixture:secret@localhost/"])
def test_fetch_rejects_unsafe_initial_urls(runtime: str, tmp_path: Path, url: str) -> None:
    result, metadata, body = _run(runtime, tmp_path, url)
    assert result.returncode == 1
    assert metadata == {"error": "invalid_url"}
    assert body is None
    assert result.stdout == result.stderr == ""


def test_direct_ignores_proxy_only_for_worker(
    runtime: str, tmp_path: Path, server: tuple[int, list[dict[str, str]]],
) -> None:
    result, metadata, body = _run(
        runtime, tmp_path, _url(runtime, server[0]), env={"HTTP_PROXY": "http://127.0.0.1:9"},
    )
    assert result.returncode == 0, result.stderr
    assert metadata["status"] == 200 and body == b"fixture-data"


def test_environment_proxy_and_bypass(
    runtime: str, tmp_path: Path, server: tuple[int, list[dict[str, str]]],
) -> None:
    proxy = _url(runtime, server[0], "")
    result, metadata, body = _run(
        runtime, tmp_path, "http://fixture.invalid/ok", env={"HTTP_PROXY": proxy}, no_proxy=False,
    )
    assert result.returncode == 0, result.stderr
    assert metadata["status"] == 200 and body == b"fixture-data"
    second = tmp_path / "bypass"
    second.mkdir()
    result, metadata, body = _run(
        runtime, second, _url(runtime, server[0]), no_proxy=False,
        env={"HTTP_PROXY": "http://127.0.0.1:9", "NO_PROXY": urlsplit(proxy).hostname or ""},
    )
    assert result.returncode == 0, result.stderr
    assert metadata["status"] == 200 and body == b"fixture-data"


@pytest.mark.parametrize("direct", [True, False])
def test_resolve_proxy_is_private(runtime: str, tmp_path: Path, direct: bool) -> None:
    proxy = "http://fixtureuser:fixturepass@proxy.invalid:8080/"
    result, metadata, body = _run(
        runtime, tmp_path, "https://example.invalid/source", action="resolve_proxy",
        no_proxy=direct, env={"HTTPS_PROXY": proxy},
    )
    assert result.returncode == 0, result.stderr
    assert metadata == {"proxy": None if direct else proxy, "bypassed": direct}
    assert body is None
    assert result.stdout == result.stderr == ""


def test_cross_origin_redirect_removes_secrets(
    runtime: str, tmp_path: Path, server: tuple[int, list[dict[str, str]]],
) -> None:
    destination = f"http://host.docker.internal:{server[0]}/ok" if runtime.startswith("docker:") else (
        f"http://localhost:{server[0]}/ok"
    )
    # A distinct authority even when Docker's hostname remains the same: explicit user headers
    # must not be forwarded when redirecting to the second server's port.
    server_handler = _RedirectTarget()
    second = ThreadingHTTPServer(("0.0.0.0", 0), server_handler.handler)
    thread = threading.Thread(target=second.serve_forever, daemon=True)
    thread.start()
    destination = destination.replace(f":{server[0]}/", f":{second.server_port}/")
    try:
        result, metadata, _ = _run(
            runtime, tmp_path, _url(runtime, server[0], "/cross-origin"), headers={
                "Authorization": "Bearer fixture-secret", "X-Api-Key": "fixture-secret",
                "X-Test-Destination": destination, "User-Agent": "STools-offline-fixture",
            },
        )
        assert result.returncode == 0, result.stderr
        assert metadata["status"] == 200
        assert "Authorization" not in server_handler.headers
        assert "X-Api-Key" not in server_handler.headers
    finally:
        second.shutdown()
        second.server_close()
        thread.join()


class _RedirectTarget:
    def __init__(self) -> None:
        self.headers: dict[str, str] = {}
        target = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                pass

            def do_GET(self) -> None:
                target.headers = dict(self.headers)
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.handler = Handler


@pytest.mark.parametrize("path", ["/slow", "/slow-body"])
def test_timeout_has_no_partial_body(
    runtime: str, tmp_path: Path, server: tuple[int, list[dict[str, str]]], path: str,
) -> None:
    result, metadata, body = _run(runtime, tmp_path, _url(runtime, server[0], path), timeout=0.2)
    assert result.returncode == 1
    assert metadata == {"error": "timeout"}
    assert body is None
    assert result.stdout == result.stderr == ""


def test_worker_refuses_existing_response(
    runtime: str, tmp_path: Path, server: tuple[int, list[dict[str, str]]],
) -> None:
    (tmp_path / "response.bin").write_bytes(b"keep-existing")
    result, metadata, body = _run(runtime, tmp_path, _url(runtime, server[0]))
    assert result.returncode == 1
    assert metadata == {"error": "invalid_output_path"}
    assert body == b"keep-existing"
    assert not server[1]
