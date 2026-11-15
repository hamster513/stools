import importlib
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def transport(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "frontend/public/offline"))
    sys.modules.pop("offline_http", None)
    return importlib.import_module("offline_http")


@pytest.fixture
def origin():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/body")
                self.end_headers()
                return
            if self.path == "/file":
                self.send_response(302)
                self.send_header("Location", "file:///etc/passwd")
                self.end_headers()
                return
            self.send_response(200)
            if self.path != "/unknown":
                self.send_header("Content-Length", "100" if self.path == "/truncated" else "4")
            self.end_headers()
            self.wfile.write(b"data")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


@pytest.mark.parametrize("route", ["/body", "/redirect"])
def test_direct_download_ignores_broken_system_proxy(
    transport, monkeypatch, origin, tmp_path, route
):
    monkeypatch.setattr(
        transport.urllib.request, "getproxies", lambda: {"http": "http://127.0.0.1:1"}
    )
    target = tmp_path / "data"
    transport.Transport(no_proxy=True).download(origin + route, target, limit=4)
    assert target.read_bytes() == b"data"


@pytest.mark.parametrize("route", ["/body", "/unknown", "/truncated", "/file"])
def test_failed_or_oversized_transfer_leaves_no_output(transport, origin, tmp_path, route):
    target = tmp_path / "data"
    with pytest.raises((ValueError, transport.urllib.error.URLError)):
        transport.Transport(no_proxy=True).download(origin + route, target, limit=3)
    assert not target.exists()


def test_truncated_transfer_is_rejected_even_below_cap(transport, origin, tmp_path):
    target = tmp_path / "data"
    with pytest.raises(ValueError, match="incomplete_response"):
        transport.Transport(no_proxy=True).download(origin + "/truncated", target, limit=1000)
    assert not target.exists()


def test_existing_target_is_never_overwritten(transport, origin, tmp_path):
    target = tmp_path / "data"
    target.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        transport.Transport(no_proxy=True).download(origin + "/body", target, limit=4)
    assert target.read_bytes() == b"existing"


def test_all_proxy_expands_without_overriding_specific_proxy(transport, monkeypatch):
    configured = {"all": "http://proxy:8123", "https": "http://secure:8124", "no": ".example.org"}
    monkeypatch.setattr(transport.urllib.request, "getproxies", lambda: configured.copy())
    seen = []
    monkeypatch.setattr(
        transport.urllib.request, "build_opener", lambda *args: seen.append(args[0].proxies)
    )
    transport.Transport()
    assert seen[0]["http"] == configured["all"]
    assert seen[0]["https"] == configured["https"]
    assert seen[0]["no"] == configured["no"]
