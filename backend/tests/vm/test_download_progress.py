"""Diagnose a blocked full download before it completes, without leaking URLs."""

import importlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


@pytest.fixture
def http_module(monkeypatch):
    from pathlib import Path

    monkeypatch.syspath_prepend(
        str(Path(__file__).resolve().parents[3] / "frontend/public/offline")
    )
    module = importlib.import_module("offline_http")
    monkeypatch.setattr(module, "PROGRESS_INTERVAL", 0.05, raising=False)
    return module


@pytest.fixture
def slow_origin():
    release = threading.Event()
    arrived = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.path.startswith("/headers"):
                arrived.set()
                release.wait(3)
            self.send_response(200)
            self.end_headers()  # Like GitHub codeload, no Content-Length.
            try:
                self.wfile.write(b"PK12")
                self.wfile.flush()
                arrived.set()
                if not self.path.startswith("/headers"):
                    release.wait(3)
                self.wfile.write(b"3456")
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", release, arrived
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        worker.join()


@pytest.mark.parametrize("route,expected", [("/headers", "Ожидание ответа"), ("/body", "4 B")])
def test_live_progress_before_headers_or_end_of_unknown_size_body(
    http_module, slow_origin, tmp_path, route, expected
):
    origin, release, arrived = slow_origin
    observed = threading.Event()
    messages, errors = [], []

    def progress(message):
        messages.append(message)
        if expected in message:
            observed.set()

    def download():
        try:
            http_module.Transport(no_proxy=True, progress=progress).download(
                origin + route + "?token=private-value",
                tmp_path / "advisory-database.zip",
                limit=100,
                timeout=2,
            )
        except (OSError, ValueError) as exc:
            errors.append(exc)

    worker = threading.Thread(target=download)
    worker.start()
    try:
        assert arrived.wait(2)
        assert observed.wait(1), messages
        assert worker.is_alive(), "Progress must arrive before the download completes"
    finally:
        release.set()
        worker.join(4)
    assert not worker.is_alive() and not errors
    assert (tmp_path / "advisory-database.zip").read_bytes() == b"PK123456"
    output = "\n".join(messages)
    assert "private-value" not in output and "?token" not in output
    assert "HTTP 200" in output and "8 B" in output


def test_stalled_body_reports_safe_timeout_and_removes_partial_file(
    http_module, slow_origin, tmp_path
):
    origin, _, _ = slow_origin
    messages = []
    target = tmp_path / "advisory-database.zip"
    with pytest.raises((TimeoutError, OSError, ValueError)):
        http_module.Transport(no_proxy=True, progress=messages.append).download(
            origin + "/body?token=private-value", target, limit=100, timeout=0.2
        )
    assert not target.exists()
    output = "\n".join(messages)
    assert "4 B" in output and "тайм-аут" in output.lower()
    assert "private-value" not in output


def test_full_ghsa_announces_packaging_and_keeps_upstream_zip(http_module, tmp_path):
    import datetime as dt
    import io
    import zipfile
    from types import SimpleNamespace

    sources = importlib.import_module("offline_sources")
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as archive:
        archive.comment = b"a" * 40
        archive.writestr("advisory-database-main/advisories/example.json", "{}")
    messages = []
    target = tmp_path / "ghsa.zip"
    sources.full_reference(
        "ghsa",
        target,
        SimpleNamespace(download=lambda url, path, **kw: path.write_bytes(raw.getvalue())),
        dt.datetime.now(dt.UTC),
        messages.append,
    )
    with zipfile.ZipFile(target) as archive:
        assert archive.read("advisory-database.zip") == raw.getvalue()
        assert archive.getinfo("advisory-database.zip").compress_type == zipfile.ZIP_STORED
    assert any("Упаковка" in message for message in messages)
    assert any("Готово" in message for message in messages)


def test_quiet_keeps_english_network_diagnostics_in_log(http_module, slow_origin, tmp_path, capsys):
    cli = importlib.import_module("offline_download")
    origin, release, _ = slow_origin
    release.set()

    def execute(name, config, run_dir, progress):
        target = run_dir / "advisory-database.zip"
        http_module.Transport(no_proxy=True, progress=progress, lang=config.lang).download(
            origin + "/body", target, limit=100, timeout=2
        )
        return {"status": "ok", "archive": target.name}

    assert (
        cli.main(
            [
                "--datasets",
                "ghsa",
                "--mode",
                "full",
                "--lang",
                "en",
                "--quiet",
                "--output",
                str(tmp_path),
            ],
            execute=execute,
        )
        == 0
    )
    assert capsys.readouterr().out == ""
    log = next(tmp_path.glob("stools-*/run.log")).read_text()
    assert "HTTP 200" in log and "Downloaded" in log and "8 B" in log and "size unknown" in log


def test_native_transfer_has_live_progress_without_printing_worker_payload(
    http_module, tmp_path, monkeypatch
):
    import sys

    fake = tmp_path / "native-worker"
    fake.write_text(
        "#!"
        + sys.executable
        + "\n"
        + """import json,sys,time
from pathlib import Path
request=json.loads(Path(sys.argv[-1]).read_text())
body=Path(request['response_path'])
part=body.with_name('body-download.part')
part.write_bytes(b'PK12')
(body.parent/'metadata.part').write_bytes(b'x' * 8192)
time.sleep(0.2)
part.rename(body)
Path(request['metadata_path']).write_text(json.dumps({'status':200,'headers':{'content-length':'4'},'bytes':4,'final_url':'https://example.org/?token=private-value'}))
"""
    )
    fake.chmod(0o700)
    monkeypatch.setenv("STOOLS_POWERSHELL", str(fake))
    messages = []
    target = tmp_path / "advisory-database.zip"
    http_module.Transport(native=True, progress=messages.append, lang="en").download(
        "https://example.org/?token=private-value", target, limit=100, timeout=2
    )
    assert target.read_bytes() == b"PK12"
    assert any("4 B" in m and "HTTP" not in m for m in messages)
    assert "100.0%" in messages[-1] and "HTTP 200" in messages[-1]
    assert "private-value" not in "\n".join(messages)


@pytest.mark.parametrize("error,category", [("dns", "DNS"), ("tls", "TLS"), ("http", "HTTP 403")])
def test_network_error_categories_never_echo_exception_secrets(
    http_module, tmp_path, error, category
):
    from types import SimpleNamespace

    errors = {
        "dns": http_module.urllib.error.URLError(
            http_module.socket.gaierror("secret-proxy-password")
        ),
        "tls": http_module.urllib.error.URLError(http_module.ssl.SSLError("secret-proxy-password")),
        "http": http_module.urllib.error.HTTPError(
            "https://example.org/?secret-proxy-password", 403, "secret-proxy-password", {}, None
        ),
    }

    def fail(*a, **kw):
        raise errors[error]

    messages = []
    client = http_module.Transport(native=False, progress=messages.append, lang="en")
    client.opener = SimpleNamespace(open=fail)
    with pytest.raises(OSError):
        client.download(
            "https://example.org/?secret-proxy-password", tmp_path / "db.zip", limit=100
        )
    assert category in messages[-1] and "secret-proxy-password" not in "\n".join(messages)


def test_cancelled_transfer_stops_progress_and_removes_partial_output(http_module, tmp_path):
    from contextlib import contextmanager
    from types import SimpleNamespace

    def cancel(_size):
        raise KeyboardInterrupt

    @contextmanager
    def open_response(*args, **kwargs):
        yield SimpleNamespace(
            url="https://example.org/archive.zip", status=200, headers={}, read=cancel
        )

    messages = []
    client = http_module.Transport(native=False, progress=messages.append, lang="en")
    client.opener = SimpleNamespace(open=open_response)
    target = tmp_path / "archive.zip"
    with pytest.raises(KeyboardInterrupt):
        client.download("https://example.org/archive.zip", target, limit=100)
    assert not target.exists()
    assert "Cancelled" in messages[-1]
    assert not any(t.name.endswith("(_watch)") for t in threading.enumerate())
