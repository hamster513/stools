"""Сканер сети (спека Assets §3): ICMP echo, TCP-рукопожатие, PTR. Без базы и без внешних библиотек.

Безопасность: только адреса цели (CIDR минус исключения, адрес сети, широковещательный и свои
адреса); на хост — один ICMP echo и по одному connect на порт, соединение закрывается сразу,
данных не отправляется; никаких повторов. Модуль импортирует только стандартную библиотеку:
тест гоняет его в чистом контейнере рядом с целью.

ICMP — непривилегированный сокет `SOCK_DGRAM`/`IPPROTO_ICMP` (Linux: `net.ipv4.ping_group_range`
должен включать группу процесса). Ядро Linux само ставит идентификатор и пропускает в сокет
только ответы на его запросы; TTL ответа приходит вспомогательными данными `IP_RECVTTL`.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import struct
import sys
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field

#: Шире /16 — 65 тысяч адресов на проход; такую сеть описывают частями (как и в описании сетей).
MAX_IPV4_PREFIX = 16
#: Для IPv6 тот же потолок по числу адресов: /64 перебором не сканируют.
MAX_ADDRESSES = 2**16

#: Python знает IP_RECVTTL не на всех платформах; значения из заголовков ядра.
IP_RECVTTL = getattr(socket, "IP_RECVTTL", 24 if sys.platform == "darwin" else 12)
IP_TTL = getattr(socket, "IP_TTL", 4 if sys.platform == "darwin" else 2)

Resolver = Callable[[str], Awaitable[str]]


class ScanCancelled(Exception):
    """Отмена между адресами; часть результатов отброшена."""


@dataclass(slots=True)
class ScanTarget:
    cidr: str
    exclude: list[str]
    ports: list[int]
    concurrency: int
    #: Секунды.
    icmp_timeout: float
    tcp_timeout: float


@dataclass(slots=True)
class HostResult:
    ip: str
    #: None — ICMP не проверялся (сокет недоступен, IPv6).
    icmp: bool | None
    ttl: int | None
    rtt_ms: float | None
    ports: list[int] = field(default_factory=list)
    ptr: str = ""


# ---- Адреса ---------------------------------------------------------------


def addresses(target: ScanTarget, own_ips: Iterable[str]) -> list[str]:
    """CIDR минус исключения, адрес сети, широковещательный и `own_ips`. Шире /16 — ValueError."""
    net = ipaddress.ip_network(target.cidr.strip(), strict=False)
    if net.version == 4 and net.prefixlen < MAX_IPV4_PREFIX:
        raise ValueError(f"сеть {net} шире /{MAX_IPV4_PREFIX} — сканер её не берёт")
    if net.num_addresses > MAX_ADDRESSES:
        raise ValueError(f"сеть {net}: больше {MAX_ADDRESSES} адресов — сканер её не берёт")
    excluded = [ipaddress.ip_network(e.strip(), strict=False) for e in target.exclude if e.strip()]
    own = {ipaddress.ip_address(ip) for ip in own_ips if _is_ip(ip)}
    return [
        str(addr) for addr in net.hosts()
        if addr not in own and not any(addr.version == x.version and addr in x for x in excluded)
    ]


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def own_addresses() -> list[str]:
    """Адреса этого хоста (контейнера API): по имени и, в Linux, все локальные из fib_trie."""
    found: set[str] = set()
    try:
        found.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    try:
        with open("/proc/net/fib_trie", encoding="ascii") as f:
            last = ""
            for line in f:
                text = line.strip()
                if text.startswith("|--"):
                    last = text[3:].strip()
                elif "/32 host LOCAL" in text and last:
                    found.add(last)
    except OSError:
        pass
    return sorted(found)


# ---- ICMP -----------------------------------------------------------------


def _icmp_socket() -> socket.socket:
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)


def icmp_available() -> bool:
    """Открывается ли непривилегированный ICMP-сокет; пакетов не шлёт."""
    try:
        _icmp_socket().close()
    except OSError:
        return False
    return True


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total: int = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _echo_request(ident: int, seq: int, payload: bytes) -> bytes:
    # Linux пересчитывает сумму и подменяет идентификатор сам; macOS — нет, поэтому считаем.
    header = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    return struct.pack("!BBHHH", 8, 0, _checksum(header + payload), ident, seq) + payload


def _ttl_from(ancdata: list[tuple[int, int, bytes]]) -> int | None:
    for level, kind, data in ancdata:
        if level == socket.IPPROTO_IP and kind in (IP_TTL, IP_RECVTTL) and data:
            return data[0] if len(data) == 1 else int.from_bytes(data[:4], sys.byteorder)
    return None


async def _readable(loop: asyncio.AbstractEventLoop, sock: socket.socket, timeout: float) -> bool:
    ready: asyncio.Future[None] = loop.create_future()

    def wake() -> None:
        if not ready.done():
            ready.set_result(None)

    loop.add_reader(sock.fileno(), wake)
    try:
        await asyncio.wait_for(ready, timeout)
    except TimeoutError:
        return False
    finally:
        loop.remove_reader(sock.fileno())
    return True


async def icmp_echo(ip: str, timeout: float) -> tuple[bool, int | None, float | None]:
    """Один echo: (ответил, TTL ответа или None, RTT мс)."""
    loop = asyncio.get_running_loop()
    payload = b"stools" + os.urandom(8)
    with _icmp_socket() as sock:
        sock.setblocking(False)
        try:
            sock.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, 1)
        except OSError:
            pass
        started = time.monotonic()
        await loop.sock_sendto(sock, _echo_request(os.getpid() & 0xFFFF, 1, payload), (ip, 0))
        deadline = started + timeout
        while (left := deadline - time.monotonic()) > 0:
            if not await _readable(loop, sock, left):
                break
            try:
                data, ancdata, _flags, addr = sock.recvmsg(2048, socket.CMSG_SPACE(4))
            except BlockingIOError:
                continue
            ttl = _ttl_from(ancdata)
            if data and data[0] >> 4 == 4:  # macOS отдаёт ответ вместе с IP-заголовком
                ttl = ttl if ttl is not None else data[8]
                data = data[(data[0] & 0x0F) * 4:]
            if addr[0] == ip and len(data) >= 8 and data[0] == 0 and data[8:] == payload:
                return True, ttl, round((time.monotonic() - started) * 1000, 2)
    return False, None, None


# ---- TCP и PTR ------------------------------------------------------------


async def tcp_open(ip: str, port: int, timeout: float) -> bool:
    """Рукопожатие и сразу закрытие; данных не отправляется."""
    loop = asyncio.get_running_loop()
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.setblocking(False)
        try:
            await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout)
        except (OSError, TimeoutError):
            return False
    return True


async def system_ptr(ip: str, timeout: float = 2.0) -> str:
    """PTR через системный резолвер; нет записи или таймаут — пусто."""
    loop = asyncio.get_running_loop()
    try:
        name, _ = await asyncio.wait_for(loop.getnameinfo((ip, 0), socket.NI_NAMEREQD), timeout)
    except (OSError, TimeoutError):
        return ""
    return "" if _is_ip(name) else name.rstrip(".").lower()


def os_hint(ttl: int | None) -> str:
    """Подсказка ОС по TTL ответа (с учётом убывания на маршрутизаторах): начальные 64, 128, 255."""
    if ttl is None:
        return ""
    if ttl <= 64:
        return "Linux/сетевое"
    if ttl <= 128:
        return "Windows"
    return "сетевое устройство"


# ---- Хост и сеть ----------------------------------------------------------


async def probe(ip: str, target: ScanTarget, *, resolver: Resolver, use_icmp: bool | None = None) -> HostResult | None:
    """ICMP, затем TCP по всем портам; жив, если ответил на ICMP или открыт хоть один порт.
    None — не ответил. `use_icmp=None` — проверить доступность сокета здесь же."""
    icmp: bool | None = None
    ttl: int | None = None
    rtt: float | None = None
    if use_icmp is None:
        use_icmp = icmp_available()
    if use_icmp and ":" not in ip:
        icmp, ttl, rtt = await icmp_echo(ip, target.icmp_timeout)
    opened = await asyncio.gather(*(tcp_open(ip, port, target.tcp_timeout) for port in target.ports))
    ports = sorted(port for port, ok in zip(target.ports, opened, strict=True) if ok)
    if not icmp and not ports:
        return None
    return HostResult(ip=ip, icmp=icmp, ttl=ttl, rtt_ms=rtt, ports=ports, ptr=await resolver(ip))


async def scan(
    target: ScanTarget,
    *,
    on_progress: Callable[[int, int], None],
    cancelled: Callable[[], bool],
    resolver: Resolver | None = None,
    own_ips: Iterable[str] | None = None,
    use_icmp: bool | None = None,
) -> list[HostResult]:
    """Проход по адресам цели: `concurrency` проб одновременно, каждый адрес один раз.
    `on_progress(сделано, всего)` после каждого адреса; `cancelled()` проверяется перед
    каждым следующим адресом — тогда ScanCancelled. Живые — по возрастанию адреса."""
    ips = addresses(target, own_addresses() if own_ips is None else own_ips)
    if use_icmp is None:
        use_icmp = icmp_available()
    resolve = resolver or system_ptr
    pending = iter(ips)
    found: list[HostResult] = []
    done = 0
    stop = False

    async def worker() -> None:
        nonlocal done, stop
        while not stop:
            if cancelled():
                stop = True
                return
            ip = next(pending, None)
            if ip is None:
                return
            result = await probe(ip, target, resolver=resolve, use_icmp=use_icmp)
            if result is not None:
                found.append(result)
            done += 1
            on_progress(done, len(ips))

    await asyncio.gather(*(worker() for _ in range(max(1, min(target.concurrency, len(ips) or 1)))))
    if stop:
        raise ScanCancelled()
    return sorted(found, key=lambda h: ipaddress.ip_address(h.ip))
