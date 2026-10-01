"""Сканер без базы: адреса цели, проба хоста (ICMP, TCP, PTR), прогресс и отмена, подсказка ОС.

Пакеты уходят только на 127.0.0.1 и в контейнер-цель на мосту Docker; остальное — подменённая проба.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from api.modules.assets.core import scanner
from api.modules.assets.core.scanner import (
    HostResult,
    ScanCancelled,
    ScanTarget,
    addresses,
    icmp_available,
    os_hint,
    probe,
    scan,
)


def target(cidr: str, **kw: object) -> ScanTarget:
    values: dict[str, object] = {"exclude": [], "ports": [22], "concurrency": 4, "icmp_timeout": 0.2, "tcp_timeout": 0.2}
    values.update(kw)
    return ScanTarget(cidr=cidr, **values)  # type: ignore[arg-type]


async def no_ptr(_ip: str) -> str:
    return ""


# ---- Адреса ---------------------------------------------------------------


def test_addresses_skip_network_broadcast_exclude_and_own() -> None:
    t = target("10.10.0.0/29", exclude=["10.10.0.2", "10.10.0.4/31"])
    assert addresses(t, ["10.10.0.6"]) == ["10.10.0.1", "10.10.0.3"]


def test_addresses_of_single_host_and_point_to_point() -> None:
    assert addresses(target("10.10.0.5/32"), []) == ["10.10.0.5"]
    assert addresses(target("10.10.0.4/31"), []) == ["10.10.0.4", "10.10.0.5"]


def test_wide_networks_rejected() -> None:
    assert len(addresses(target("10.10.0.0/16"), [])) == 65534
    with pytest.raises(ValueError, match="/16"):
        addresses(target("10.0.0.0/8"), [])
    with pytest.raises(ValueError):
        addresses(target("2001:db8::/64"), [])


def test_os_hint_by_ttl() -> None:
    assert os_hint(128) == "Windows" and os_hint(117) == "Windows"
    assert os_hint(64) == "Linux/сетевое" and os_hint(52) == "Linux/сетевое"
    assert os_hint(255) == "сетевое устройство" and os_hint(240) == "сетевое устройство"
    assert os_hint(None) == ""


def test_icmp_available_does_not_crash() -> None:
    assert isinstance(icmp_available(), bool)


# ---- Проба хоста ----------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_probe_finds_open_port_and_sends_nothing() -> None:
    received: list[bytes] = []

    async def run() -> HostResult | None:
        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            received.append(await reader.read(100))  # b"" — сканер закрыл соединение, ничего не отправив
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        async def ptr(ip: str) -> str:
            return "ws01.corp.local" if ip == "127.0.0.1" else ""

        async with server:
            result = await probe("127.0.0.1", target("127.0.0.1/32", ports=[port, _free_port()]), resolver=ptr, use_icmp=False)
            await asyncio.sleep(0.1)
        assert result is not None
        assert result.ports == [port]
        return result

    result = asyncio.run(run())
    assert result is not None and result.icmp is None and result.ptr == "ws01.corp.local"
    assert received == [b""]


@pytest.fixture
def black_hole_port() -> Iterator[int]:
    """Порт на 127.0.0.1, соединение с которым не устанавливается и не отвергается — висит.
    Linux: очередь listen(0) забита, SYN отбрасывается; macOS: порт занят, но не слушает."""
    held: list[socket.socket] = []

    def hangs(port: int) -> bool:
        probe_sock = socket.socket()
        probe_sock.settimeout(0.3)
        try:
            probe_sock.connect(("127.0.0.1", port))
        except TimeoutError:
            return True
        except OSError:
            return False
        held.append(probe_sock)
        return False

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(0)
    held.append(srv)
    port = int(srv.getsockname()[1])
    found = None
    for _ in range(8):
        if hangs(port):
            found = port
            break
    if found is None:
        idle = socket.socket()
        idle.bind(("127.0.0.1", 0))
        held.append(idle)
        if hangs(int(idle.getsockname()[1])):
            found = int(idle.getsockname()[1])
    try:
        if found is None:
            pytest.skip("на этой системе не получить локальный порт, который молчит")
        yield found
    finally:
        for s in held:
            s.close()


def test_probe_silent_host_returns_none_within_timeout(black_hole_port: int) -> None:
    t = target("127.0.0.1/32", ports=[black_hole_port], tcp_timeout=0.2)
    started = time.monotonic()
    result = asyncio.run(probe("127.0.0.1", t, resolver=no_ptr, use_icmp=False))
    assert result is None
    assert time.monotonic() - started < 1.5


# ---- Проход по сети -------------------------------------------------------


@pytest.fixture
def fake_probe(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Проба без сети: живы .1 и .3."""
    calls: list[str] = []

    async def fake(ip: str, _target: ScanTarget, *, resolver: object, use_icmp: bool | None = None) -> HostResult | None:
        calls.append(ip)
        await asyncio.sleep(0)
        if ip in ("10.10.0.1", "10.10.0.3"):
            return HostResult(ip=ip, icmp=True, ttl=128, rtt_ms=1.0, ports=[445], ptr="")
        return None

    monkeypatch.setattr(scanner, "probe", fake)
    return calls


def test_scan_collects_alive_and_reports_progress(fake_probe: list[str]) -> None:
    progress: list[tuple[int, int]] = []
    found = asyncio.run(scan(target("10.10.0.0/29"), on_progress=lambda d, t: progress.append((d, t)),
                             cancelled=lambda: False, resolver=no_ptr, own_ips=[]))
    assert [h.ip for h in found] == ["10.10.0.1", "10.10.0.3"]
    assert sorted(fake_probe) == [f"10.10.0.{i}" for i in range(1, 7)]
    assert progress[-1] == (6, 6) and [d for d, _ in progress] == sorted(d for d, _ in progress)


def test_scan_stops_between_addresses_when_cancelled(fake_probe: list[str]) -> None:
    progress: list[int] = []
    with pytest.raises(ScanCancelled):
        asyncio.run(scan(target("10.10.0.0/29", concurrency=1), on_progress=lambda d, _t: progress.append(d),
                         cancelled=lambda: len(progress) >= 2, resolver=no_ptr, own_ips=[]))
    assert len(fake_probe) == 2


# ---- Контейнер-цель -------------------------------------------------------

TARGET_DIR = Path(__file__).parent / "target"
SCANNER_PY = Path(scanner.__file__)
IMAGE = "stools-scan-target:test"

#: Сканер запускается во втором контейнере на том же мосту: с macOS (Docker Desktop) до адреса
#: контейнера не дойти ни ICMP, ни TCP, а так проверка одинакова везде. sysctl — как в compose.
IN_CONTAINER = """
import asyncio, dataclasses, json, sys
sys.path.insert(0, "/scan")
import scanner
async def no_ptr(ip):
    return ""
t = scanner.ScanTarget(cidr=sys.argv[1] + "/32", exclude=[], ports=[22, 80, 445], concurrency=4, icmp_timeout=1.0, tcp_timeout=1.0)
found = asyncio.run(scanner.scan(t, on_progress=lambda d, n: None, cancelled=lambda: False, resolver=no_ptr, own_ips=[]))
print(json.dumps({"icmp": scanner.icmp_available(), "hosts": [dataclasses.asdict(h) for h in found]}))
"""


def _docker(*args: str, timeout: float = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, check=False)


@pytest.fixture(scope="module")
def target_ip() -> Iterator[str]:
    if not shutil.which("docker") or _docker("info", timeout=15).returncode != 0:
        pytest.skip("нужен docker")
    if _docker("image", "inspect", IMAGE).returncode != 0:
        built = _docker("build", "-q", "-t", IMAGE, str(TARGET_DIR), timeout=50)
        if built.returncode != 0:
            pytest.skip(f"образ цели не собрался (нет python:3.13-slim?): {built.stderr.strip()[-200:]}")
    run = _docker("run", "-d", "--rm", IMAGE)
    assert run.returncode == 0, run.stderr
    container = run.stdout.strip()
    try:
        for _ in range(50):
            if "ready" in _docker("logs", container).stdout:
                break
            time.sleep(0.1)
        ip = _docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container).stdout.strip()
        assert ip, "у контейнера-цели нет адреса"
        yield ip
    finally:
        _docker("rm", "-f", container)


def test_scan_container_target(target_ip: str) -> None:
    out = _docker(
        "run", "--rm", "--sysctl", "net.ipv4.ping_group_range=0 2147483647",
        "-v", f"{SCANNER_PY}:/scan/scanner.py:ro", IMAGE, "python", "-c", IN_CONTAINER, target_ip,
    )
    assert out.returncode == 0, out.stderr
    report = json.loads(out.stdout)
    assert len(report["hosts"]) == 1
    host = report["hosts"][0]
    assert host["ip"] == target_ip and host["ports"] == [22, 445]
    if report["icmp"]:
        assert host["icmp"] is True and isinstance(host["ttl"], int) and host["rtt_ms"] is not None
    else:
        assert host["icmp"] is None


@pytest.mark.skipif(not icmp_available(), reason="непривилегированный ICMP-сокет не открывается")
def test_icmp_echo_to_loopback() -> None:
    answered, ttl, rtt = asyncio.run(scanner.icmp_echo("127.0.0.1", 1.0))
    assert answered is True and isinstance(ttl, int) and rtt is not None
