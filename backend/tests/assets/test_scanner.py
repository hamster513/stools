"""Сканер без базы: адреса цели, проба хоста (ICMP, TCP, PTR), прогресс и отмена, подсказка ОС.

Пакеты уходят только на 127.0.0.1 и в контейнер-цель на мосту Docker; остальное — подменённая проба.
"""
from __future__ import annotations

import asyncio
import errno
import hashlib
import itertools
import json
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from api.modules.assets.core import scanner
from api.modules.assets.core.scanner import (
    HostResult,
    ScanCancelled,
    ScanTarget,
    addresses,
    count_addresses,
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


def test_exclude_wider_than_cidr_leaves_nothing() -> None:
    assert addresses(target("10.10.0.0/29", exclude=["10.10.0.0/16"]), []) == []
    assert addresses(target("10.10.0.0/29", exclude=["2001:db8::/32"]), []) == [f"10.10.0.{i}" for i in range(1, 7)]


def test_own_addresses_include_ipv6(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if6 = tmp_path / "if_inet6"
    if6.write_text(
        "00000000000000000000000000000001 01 80 10 80       lo\n"
        "fe800000000000000000000000000005 02 40 20 80     eth0\n"
        "20010db8000000000000000000000007 02 40 00 80     eth0\n",
        encoding="ascii",
    )
    monkeypatch.setattr(scanner, "PROC_IF_INET6", str(if6))
    monkeypatch.setattr(scanner, "PROC_FIB_TRIE", str(tmp_path / "нет"))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.10.0.6", 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::9%eth0", 0, 0, 2)),
    ])
    own = scanner.own_addresses()
    assert {"::1", "fe80::5", "2001:db8::7", "10.10.0.6", "fe80::9"} <= set(own)
    assert addresses(target("2001:db8::/125"), own) == [f"2001:db8::{i}" for i in range(1, 8) if i != 7]


@pytest.mark.parametrize(("cidr", "exclude"), [
    ("10.0.0.0/24", []),
    ("10.0.0.0/24", ["10.0.0.0/25", "10.0.0.5", "10.0.0.0/26", "10.0.0.255"]),
    ("10.0.0.0/24", ["10.0.0.0/16"]),
    ("10.0.0.0/24", ["10.1.0.0/24", "fd00::/64", ""]),
    ("10.0.0.0/24", ["10.0.0.128/25", "10.0.0.0/25"]),
    ("10.0.0.0/31", []),
    ("10.0.0.0/31", ["10.0.0.1"]),
    ("10.0.0.7/32", []),
    ("10.0.0.0/30", ["10.0.0.0"]),
    ("10.0.0.0/16", ["10.0.128.0/17", "10.0.1.0/24"]),
    ("fd00::/120", ["fd00::", "fd00::80/121", "fd00::ff"]),
    ("fd00::/127", []),
    ("fd00::1/128", []),
])
def test_count_addresses_matches_address_list(cidr: str, exclude: list[str]) -> None:
    """Число адресов считается арифметикой, без списка: то же, что даёт сам список."""
    t = target(cidr, exclude=exclude)
    assert count_addresses(t) == len(addresses(t, []))


def test_count_addresses_rejects_what_scanner_rejects() -> None:
    for cidr in ("10.0.0.0/15", "fd00::/64"):
        with pytest.raises(ValueError):
            count_addresses(target(cidr))


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


def _refusing_socket(monkeypatch: pytest.MonkeyPatch, refuse: Any) -> None:
    """socket.socket, который отказывает (как при EMFILE или запрете ICMP), когда `refuse(family, type, proto)`."""
    real = socket.socket

    def make(family: int = -1, type: int = -1, proto: int = -1, fileno: int | None = None) -> socket.socket:
        if fileno is None and refuse(family, type, proto):
            raise OSError(errno.EMFILE, "Too many open files")
        return real(family, type, proto, fileno)

    monkeypatch.setattr(socket, "socket", make)


def test_icmp_socket_error_means_no_icmp_and_ports_still_probed(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run() -> HostResult | None:
        async def close(_r: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.close()

        server = await asyncio.start_server(close, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        _refusing_socket(monkeypatch, lambda _f, _t, proto: proto == socket.IPPROTO_ICMP)
        async with server:
            return await probe("127.0.0.1", target("127.0.0.1/32", ports=[port]), resolver=no_ptr, use_icmp=True)

    result = asyncio.run(run())
    assert result is not None and result.icmp is False and result.ttl is None and len(result.ports) == 1


def test_tcp_socket_error_means_port_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _refusing_socket(monkeypatch, lambda family, type_, _p: family == socket.AF_INET and type_ == socket.SOCK_STREAM)
    assert asyncio.run(scanner.tcp_open("127.0.0.1", 9, 0.5)) is False


def test_connect_error_on_one_address_does_not_stop_scan() -> None:
    async def run() -> list[HostResult]:
        async def close(_r: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.close()

        server = await asyncio.start_server(close, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        loop = asyncio.get_running_loop()
        real_connect = loop.sock_connect

        async def connect(sock: socket.socket, address: tuple[str, int]) -> None:
            if address[0] == "127.0.0.2":
                raise OSError(errno.ENETUNREACH, "Network is unreachable")
            await real_connect(sock, address)

        loop.sock_connect = connect  # type: ignore[method-assign]
        async with server:
            return await scan(target("127.0.0.0/30", ports=[port]), on_progress=lambda _d, _t: None,
                              cancelled=lambda: False, resolver=no_ptr, own_ips=[], use_icmp=False)

    assert [h.ip for h in asyncio.run(run())] == ["127.0.0.1"]


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

    async def fake(ip: str, _target: ScanTarget, *, resolver: object, use_icmp: bool | None = None, **_kw: object) -> HostResult | None:
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


# ---- Сокеты и темп ---------------------------------------------------------


def test_open_sockets_capped_for_whole_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    """Параллельность × порты больше предела — одновременно открыто не больше MAX_SOCKETS."""
    monkeypatch.setattr(scanner, "MAX_SOCKETS", 5)
    now = [0]
    peak = [0]

    async def held() -> None:
        now[0] += 1
        peak[0] = max(peak[0], now[0])
        await asyncio.sleep(0.01)
        now[0] -= 1

    async def fake_icmp(_ip: str, _timeout: float) -> tuple[bool, int | None, float | None]:
        await held()
        return False, None, None

    async def fake_tcp(_ip: str, _port: int, _timeout: float) -> bool:
        await held()
        return False

    monkeypatch.setattr(scanner, "icmp_echo", fake_icmp)
    monkeypatch.setattr(scanner, "tcp_open", fake_tcp)
    t = target("10.10.0.0/29", ports=[1, 2, 3, 4], concurrency=6, rate_per_s=5000)
    assert asyncio.run(scan(t, on_progress=lambda _d, _t: None, cancelled=lambda: False, resolver=no_ptr,
                            own_ips=[], use_icmp=True)) == []
    assert peak[0] == 5


def test_packet_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[float] = []

    async def fake_tcp(_ip: str, _port: int, _timeout: float) -> bool:
        sent.append(time.monotonic())
        return False

    monkeypatch.setattr(scanner, "tcp_open", fake_tcp)
    t = target("10.10.0.0/29", ports=[1], concurrency=6, rate_per_s=20)
    asyncio.run(scan(t, on_progress=lambda _d, _t: None, cancelled=lambda: False, resolver=no_ptr, own_ips=[], use_icmp=False))
    gaps = [b - a for a, b in itertools.pairwise(sent)]
    assert len(sent) == 6 and min(gaps) >= 0.045, gaps


def test_open_files_limit_raised() -> None:
    resource = pytest.importorskip("resource")
    scanner.raise_open_files_limit()
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    assert soft == hard or soft >= 4 * scanner.MAX_SOCKETS


# ---- Контейнер-цель -------------------------------------------------------

TARGET_DIR = Path(__file__).parent / "target"
SCANNER_PY = Path(scanner.__file__)
#: Тег — хеш файлов цели: правка listen.py или Dockerfile пересобирает образ, а не берёт старый.
IMAGE = "stools-scan-target:" + hashlib.sha256(
    b"".join((TARGET_DIR / name).read_bytes() for name in ("Dockerfile", "listen.py"))
).hexdigest()[:12]
LABEL = "stools-test=1"
BUILD_TIMEOUT_S = 120
#: Своя сеть Docker с известной адресацией: в /29 сканера только цель, остальные адреса мёртвые
#: (шлюз .1 и сам сканер .20 вне /29).
SUBNET = "172.31.213.0/24"
SCAN_CIDR = "172.31.213.8/29"
TARGET_IP = "172.31.213.10"
SCANNER_IP = "172.31.213.20"

#: Сканер запускается во втором контейнере на той же сети: с macOS (Docker Desktop) до адреса
#: контейнера не дойти ни ICMP, ни TCP, а так проверка одинакова везде. sysctl — как в compose.
IN_CONTAINER = """
import asyncio, dataclasses, json, sys
sys.path.insert(0, "/scan")
import scanner
async def no_ptr(ip):
    return ""
t = scanner.ScanTarget(cidr=sys.argv[1], exclude=[], ports=[22, 80, 445], concurrency=8, icmp_timeout=1.0, tcp_timeout=1.0)
found = asyncio.run(scanner.scan(t, on_progress=lambda d, n: None, cancelled=lambda: False, resolver=no_ptr, own_ips=[]))
print(json.dumps({"icmp": scanner.icmp_available(), "own": scanner.own_addresses(),
                  "hosts": [dataclasses.asdict(h) for h in found]}))
"""


def _docker(*args: str, timeout: float = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, check=False)


@pytest.fixture(scope="module")
def target_net() -> Iterator[str]:
    """Имя сети Docker с запущенной целью; сеть и контейнеры помечены LABEL и удаляются в finally."""
    if not shutil.which("docker") or _docker("info", timeout=15).returncode != 0:
        pytest.skip("нужен docker")
    if _docker("image", "inspect", IMAGE).returncode != 0:
        try:
            built = _docker("build", "-q", "--label", LABEL, "-t", IMAGE, str(TARGET_DIR), timeout=BUILD_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            pytest.fail(f"образ цели не собрался за {BUILD_TIMEOUT_S} с")
        if built.returncode != 0:
            pytest.fail(f"образ цели не собрался: {built.stderr.strip()[-300:]}")
    suffix = f"{os.getpid()}"
    net, container = f"stools-test-scan-{suffix}", f"stools-test-target-{suffix}"
    created = _docker("network", "create", "--label", LABEL, "--subnet", SUBNET, net)
    assert created.returncode == 0, f"сеть {SUBNET} для теста не создана: {created.stderr.strip()}"
    try:
        run = _docker("run", "-d", "--label", LABEL, "--name", container, "--network", net, "--ip", TARGET_IP, IMAGE)
        assert run.returncode == 0, run.stderr
        for _ in range(50):
            if "ready" in _docker("logs", container).stdout:
                break
            time.sleep(0.1)
        else:
            pytest.fail("цель не поднялась за 5 с")
        yield net
    finally:
        _docker("rm", "-f", container)
        _docker("network", "rm", net)


def test_scan_container_target(target_net: str) -> None:
    name = f"stools-test-scanner-{os.getpid()}"
    try:
        out = _docker(
            "run", "--rm", "--label", LABEL, "--name", name, "--network", target_net, "--ip", SCANNER_IP,
            "--sysctl", "net.ipv4.ping_group_range=0 2147483647",
            "-v", f"{SCANNER_PY}:/scan/scanner.py:ro", IMAGE, "python", "-c", IN_CONTAINER, SCAN_CIDR,
        )
    finally:
        _docker("rm", "-f", name)
    assert out.returncode == 0, out.stderr
    report = json.loads(out.stdout)
    assert report["icmp"] is True
    assert SCANNER_IP in report["own"]
    # Мёртвые адреса /29 (.9, .11–.14) в живые не попали: ответ цели не засчитан чужой пробе.
    assert [h["ip"] for h in report["hosts"]] == [TARGET_IP]
    host = report["hosts"][0]
    assert host["ports"] == [22, 445]
    assert host["icmp"] is True and isinstance(host["ttl"], int) and host["rtt_ms"] is not None


@pytest.mark.skipif(not icmp_available(), reason="непривилегированный ICMP-сокет не открывается")
def test_icmp_echo_to_loopback() -> None:
    answered, ttl, rtt = asyncio.run(scanner.icmp_echo("127.0.0.1", 1.0))
    assert answered is True and isinstance(ttl, int) and rtt is not None
