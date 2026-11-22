"""Bounded HTTP transport, with the Windows native proxy implementation."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message
from pathlib import Path

MAX_RESPONSE = 128 * 1024 * 1024


PROGRESS_INTERVAL = 5


def _amount(size):
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


def _error_description(exc, lang):
    ru = lang == "ru"
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}"
    if isinstance(reason, (TimeoutError, socket.timeout)) or str(reason) == "timeout":
        return (
            "тайм-аут: сервер не отвечает или перестал передавать данные"
            if ru
            else "timeout: no response or data from the server"
        )
    if isinstance(reason, ssl.SSLError):
        return "ошибка TLS/сертификата" if ru else "TLS/certificate error"
    if isinstance(reason, socket.gaierror):
        return (
            "ошибка DNS: имя сервера не разрешается"
            if ru
            else "DNS error: cannot resolve server"
        )
    if isinstance(reason, ConnectionError):
        return (
            "соединение разорвано или отклонено"
            if ru
            else "connection interrupted or refused"
        )
    if isinstance(exc, ValueError) and str(exc) in {
        "response_too_large",
        "incomplete_response",
        "invalid_proxy",
        "proxy_error",
        "transport_error",
        "native_proxy_transport_failed",
        "redirect_limit",
        "unsafe_redirect",
    }:
        return str(exc)
    return type(exc).__name__  # Exception text may contain proxy credentials or tokens.


class _DownloadProgress:
    def __init__(self, transport, url, target, timeout):
        self.transport = transport
        self.label = target.name
        self.host = urllib.parse.urlsplit(url).hostname
        self.timeout = timeout
        self.size = 0
        self.expected = None
        self.status = None
        self.started = self.last_data = time.monotonic()
        self.sample = None
        self.stopped = threading.Event()
        self.worker = threading.Thread(target=self._watch, daemon=True)

    def text(self, ru, en):
        return ru if self.transport.lang == "ru" else en

    def emit(self, message):
        self.transport.progress(f"{self.label}: {message}")

    def received(self, size):
        if size > self.size:
            self.size, self.last_data = size, time.monotonic()

    def headers(self, status, headers):
        self.status = status
        length = next(
            (v for k, v in headers.items() if k.lower() == "content-length"), None
        )
        self.expected = int(length) if length and str(length).isdigit() else None
        self.emit(self.snapshot())

    def snapshot(self):
        elapsed = max(time.monotonic() - self.started, 0.001)
        idle = time.monotonic() - self.last_data
        stage = (
            self.text("Получение", "Receiving")
            if self.status or self.size
            else self.text("Ожидание ответа", "Waiting for response")
        )
        total = (
            f" / {_amount(self.expected)} ({100 * self.size / self.expected:.1f}%)"
            if self.expected
            else self.text(" / размер неизвестен", " / size unknown")
        )
        status = f"HTTP {self.status}; " if self.status else ""
        return (
            f"{status}{stage}: {_amount(self.size)}{total}; {_amount(self.size / elapsed)}/s; "
            + self.text(
                f"прошло {elapsed:.0f} с, без новых данных {idle:.0f} с",
                f"elapsed {elapsed:.0f}s, no new data {idle:.0f}s",
            )
        )

    def _watch(self):
        while not self.stopped.wait(PROGRESS_INTERVAL):
            sample = self.sample
            if sample:
                self.received(sample())
            self.emit(self.snapshot())

    def __enter__(self):
        proxy = (
            self.text("напрямую", "direct")
            if self.transport.no_proxy
            else self.text("системные настройки", "system settings")
        )
        self.emit(
            self.text(
                f"Сервер {self.host}; прокси: {proxy}; тайм-аут {self.timeout} с",
                f"Server {self.host}; proxy: {proxy}; timeout {self.timeout}s",
            )
        )
        self.emit(self.snapshot())
        self.worker.start()
        return self

    def __exit__(self, kind, exc, tb):
        self.stopped.set()
        self.worker.join()
        if exc:
            error = (
                self.text("Отменено", "Cancelled")
                if isinstance(exc, KeyboardInterrupt)
                else _error_description(exc, self.transport.lang)
            )
            self.emit(self.text("Ошибка: ", "Error: ") + error + "; " + self.snapshot())
        else:
            self.emit(self.text("Скачано; ", "Downloaded; ") + self.snapshot())


def checked_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError("invalid_url")
    if any(ord(char) < 32 for char in url):
        raise ValueError("invalid_url")
    return url


class Redirects(urllib.request.HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        checked_url(newurl)
        old, new = urllib.parse.urlsplit(req.full_url), urllib.parse.urlsplit(newurl)
        if old.scheme == "https" and new.scheme != "https":
            raise ValueError("unsafe_redirect")
        if old.hostname in {"dl.astralinux.ru", "redos.red-soft.ru"} and old.netloc != new.netloc:
            raise ValueError("unsafe_redirect")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and (old.scheme, old.netloc) != (new.scheme, new.netloc):
            redirected.remove_header("Authorization")
        return redirected


class Transport:
    def __init__(
        self,
        *,
        no_proxy: bool = False,
        progress=None,
        native: bool | None = None,
        lang="ru",
    ):
        self.no_proxy = no_proxy
        self.lang = lang
        self.progress = progress or (lambda _: None)
        self.native = sys.platform == "win32" if native is None else native
        proxies = {} if no_proxy else urllib.request.getproxies()
        if proxies.get("all"):
            for scheme in ("http", "https"):
                proxies.setdefault(scheme, proxies["all"])
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler(proxies), Redirects()
        )

    @contextlib.contextmanager
    def _native(
        self,
        url: str,
        *,
        headers=None,
        limit=MAX_RESPONSE,
        timeout=60,
        action="fetch",
        observer=None,
    ):
        executable = (
            os.environ.get("STOOLS_POWERSHELL")
            or shutil.which("powershell.exe")
            or shutil.which("pwsh")
        )
        if not executable:
            raise ValueError("Windows proxy transport requires PowerShell")
        with tempfile.TemporaryDirectory(prefix="stools-http-") as directory:
            directory = Path(directory)
            request = {
                "action": action,
                "url": checked_url(url),
                "headers": headers or {},
                "response_path": str(directory / "response.bin"),
                "metadata_path": str(directory / "metadata.json"),
                "max_bytes": limit,
                "timeout": timeout,
                "no_proxy": self.no_proxy,
            }
            path = directory / "request.json"
            path.write_text(json.dumps(request), encoding="utf-8")
            path.chmod(0o600)
            if observer:

                def sample():
                    # The native worker writes the body into its private temporary directory.
                    sizes = []
                    for body in directory.glob("body-*.part"):
                        try:
                            sizes.append(body.stat().st_size)
                        except FileNotFoundError:
                            pass
                    return max(sizes, default=0)

                observer.sample = sample
            try:
                process = subprocess.run(
                    [
                        executable,
                        "-NoProfile",
                        "-NonInteractive",
                        "-File",
                        str(Path(__file__).with_name("system-http.ps1")),
                        "-RequestFile",
                        str(path),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=timeout + 30,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                raise ValueError("timeout") from None
            metadata_path = Path(request["metadata_path"])
            if not metadata_path.exists() or metadata_path.stat().st_size > 256 * 1024:
                raise ValueError("native_proxy_transport_failed")
            metadata = json.loads(metadata_path.read_text(encoding="utf-8-sig"))
            if process.returncode or metadata.get("error"):
                known = {
                    "invalid_request",
                    "invalid_url",
                    "invalid_output_path",
                    "invalid_headers",
                    "invalid_proxy",
                    "proxy_error",
                    "transport_error",
                    "timeout",
                    "response_too_large",
                    "redirect_limit",
                    "unsafe_redirect",
                }
                raise ValueError(
                    metadata.get("error")
                    if metadata.get("error") in known
                    else "native_proxy_transport_failed"
                )
            if observer and action == "fetch":
                observer.sample = None
                observer.received(int(metadata.get("bytes", 0)))
                observer.headers(int(metadata["status"]), metadata.get("headers", {}))
            yield metadata, Path(request["response_path"])

    def git_proxies(self, url: str = "https://github.com/") -> dict[str, str] | None:
        if self.no_proxy:
            return {}
        if not self.native:
            return None
        with self._native(url, action="resolve_proxy") as (metadata, _):
            value = metadata.get("proxy")
            if value and urllib.parse.urlsplit(value).username is None:
                parts = urllib.parse.urlsplit(value)
                value = urllib.parse.urlunsplit(
                    (
                        parts.scheme,
                        ":@" + parts.netloc,
                        parts.path,
                        parts.query,
                        parts.fragment,
                    )
                )
            return {"https": value, "http": value} if value else {}

    @contextlib.contextmanager
    def open(self, request, timeout=60):
        url = checked_url(
            request.full_url if isinstance(request, urllib.request.Request) else request
        )
        if not self.native:
            with self.opener.open(request, timeout=timeout) as response:
                checked_url(response.url)
                yield response
            return
        headers = (
            dict(request.header_items())
            if isinstance(request, urllib.request.Request)
            else {}
        )
        with self._native(url, headers=headers, timeout=timeout) as (metadata, path):
            status = int(metadata["status"])
            response_headers = Message()
            for key, value in metadata.get("headers", {}).items():
                response_headers[key] = value
            if status >= 300:
                raise urllib.error.HTTPError(
                    url, status, "HTTP error", response_headers, None
                )
            with path.open("rb") as stream:

                class Response:
                    headers = response_headers

                    def read(self, size=-1):
                        return stream.read(size)

                response = Response()
                response.status = status
                yield response

    def download(
        self, url: str, target: Path, *, limit: int, timeout=60, headers=None
    ) -> dict:
        checked_url(url)
        if target.exists():
            raise FileExistsError("download target exists")
        with _DownloadProgress(self, url, target, timeout) as observer:
            return self._download(
                url,
                target,
                limit=limit,
                timeout=timeout,
                headers=headers,
                observer=observer,
            )

    def _download(
        self,
        url: str,
        target: Path,
        *,
        limit: int,
        timeout=60,
        headers=None,
        observer=None,
    ) -> dict:
        checked_url(url)
        if target.exists():
            raise FileExistsError("download target exists")
        headers = {
            "User-Agent": "STools-offline/1",
            "Accept-Encoding": "identity",
            **(headers or {}),
        }
        if self.native:
            with self._native(
                url, headers=headers, limit=limit, timeout=timeout, observer=observer
            ) as (
                metadata,
                path,
            ):
                status = int(metadata["status"])
                if status >= 300:
                    raise urllib.error.HTTPError(
                        url, status, "HTTP error", metadata.get("headers", {}), None
                    )
                with path.open("rb") as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                return metadata.get("headers", {})
        request = urllib.request.Request(url, headers=headers)
        try:
            with (
                self.opener.open(request, timeout=timeout) as response,
                target.open("xb") as output,
            ):
                checked_url(response.url)
                if observer:
                    observer.headers(response.status, response.headers)
                expected = response.headers.get("Content-Length")
                expected = int(expected) if expected and expected.isdigit() else None
                if expected is not None and expected > limit:
                    raise ValueError("response_too_large")
                size = 0
                read = getattr(response, "read1", response.read)
                while chunk := read(64 * 1024):
                    size += len(chunk)
                    if size > limit:
                        raise ValueError("response_too_large")
                    output.write(chunk)
                    if observer:
                        observer.received(size)
                if expected is not None and size != expected:
                    raise ValueError("incomplete_response")
                return dict(response.headers)
        except BaseException:
            target.unlink(missing_ok=True)
            raise

    def fetch(self, url: str, limit: int, timeout: int) -> bytes:
        with tempfile.TemporaryDirectory(prefix="stools-fetch-") as directory:
            target = Path(directory) / "body"
            self._download(url, target, limit=limit, timeout=timeout)
            return target.read_bytes()
