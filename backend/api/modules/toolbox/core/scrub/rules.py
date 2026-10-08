"""Правила замены: сохранение регистра, кандидаты псевдонимов, нумерация, сборка составных, замена.

Правила адресов и слов перенесены из `backend/tools/export_scrub.py`; скрипт заморожен,
поэтому логика скопирована, а не импортирована.
"""
from __future__ import annotations

import hashlib
import hmac
from bisect import bisect_left
from collections.abc import Callable, Iterable
from ipaddress import IPv4Address, IPv4Network, IPv6Address

from api.modules.toolbox.core.scrub.types import Ctx, Match

#: Частные сети для автозамены: (сеть, сколько старших бит не трогать). Последний октет не меняется.
AUTO = tuple((IPv4Network(n), keep) for n, keep in (("10.0.0.0/8", 8), ("172.16.0.0/12", 12), ("192.168.0.0/16", 16)))
#: Служебные адреса (в том числе маски и групповые): не меняются.
SERVICE = tuple(IPv4Network(n) for n in ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3"))
#: Части составных совпадений и разделитель между их псевдонимами.
SEPARATORS: dict[tuple[str, ...], str] = {("host", "domain"): ".", ("user", "domain"): "@", ("domain", "user"): "\\"}
NUMBERED = ("host", "user", "word")


def keep_case(found: str, alias: str) -> str:
    if found.isupper():
        return alias.upper()
    return alias.lower() if found.islower() else alias


def _digest(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode(), hashlib.sha256).digest()


def _auto(value: int, keep: int, key: bytes) -> int:
    # Бит меняется по хешу старших бит адреса: адреса одной /24 получают одну и ту же /24.
    out = value
    for bit in range(keep, 24):
        out ^= (_digest(key, f"{bit}:{value >> (32 - bit)}")[0] & 1) << (31 - bit)
    # Адрес, совпавший сам с собой, сдвигается вместе с соседней подсетью.
    return out ^ (1 << 8) if out == value else out


def _ip4(key: str, hmac_key: bytes, taken: Callable[[str], bool], ctx: Ctx) -> str:
    ip = IPv4Address(key)
    for old, new in ctx.subnets:
        if ip in old:
            return str(IPv4Address(int(new.network_address) | (int(ip) & int(old.hostmask))))
    for net, keep in AUTO:
        if ip in net:
            base, size = int(net.network_address), net.num_addresses
            out = _auto(int(ip), keep, hmac_key)
            for _ in range(size >> 8):
                alias = str(IPv4Address(out))
                if not taken(alias):
                    return alias
                # Занятый — в соседнюю /24 той же зоны: зона и последний октет сохраняются.
                out = base + (out - base + 256) % size
            raise RuntimeError(f"{net}: свободных псевдонимов не осталось")
    # «12.0.0.0» вне таблицы — почти всегда номер версии, не меняется.
    if any(ip in net for net in SERVICE) or key.endswith(".0.0"):
        return key
    low = int.from_bytes(_digest(hmac_key, key)[:2], "big")
    for _ in range(65536):
        alias = f"8.8.{low >> 8}.{low & 255}"
        if not taken(alias):
            return alias
        low = (low + 1) % 65536
    raise RuntimeError("8.8.0.0/16: свободных псевдонимов не осталось")


def candidate(kind: str, key: str, hmac_key: bytes, taken: Callable[[str], bool], ctx: Ctx) -> str:
    """Кандидат псевдонима по ключу значения; `taken` — занят ли псевдоним другим значением."""
    if kind == "ip4":
        return _ip4(key, hmac_key, taken, ctx)
    if kind == "secret":
        return f"<secret-{hashlib.sha256(key.encode()).hexdigest()[:8]}>"
    if kind not in ("ip6", "mac", "sid"):
        raise ValueError(f"{kind}: псевдоним назначается по номеру (Aliases.propose)")
    attempt = 0
    while True:
        digest = _digest(hmac_key, f"{kind}:{attempt}:{key}")
        if kind == "ip6":
            alias = IPv6Address((0x20010DB8 << 96) | int.from_bytes(digest[:12], "big")).compressed
        elif kind == "mac":
            # 02: — локально назначенный адрес, у настоящего производителя такого нет.
            alias = "02:" + ":".join(f"{b:02x}" for b in digest[:5])
        else:
            a, b, c = (int.from_bytes(digest[i:i + 4], "big") for i in (0, 4, 8))
            alias = f"S-1-5-21-{a}-{b}-{c}"
        if not taken(alias):
            return alias
        attempt += 1


def numbered(kind: str, n: int, key: str = "") -> str:
    """Псевдоним по порядковому номеру; домен без точки в ключе — NetBIOS, пишется заглавными."""
    if kind == "domain":
        return f"DOM{n}" if key and "." not in key else f"dom{n}.example"
    if kind in NUMBERED:
        return f"{kind}-{n:04d}"
    raise ValueError(f"{kind}: псевдоним не нумеруется")


def compose(match: Match, alias_of: Callable[[str, str], str]) -> str:
    """Псевдоним совпадения; составное собирается из псевдонимов частей."""
    if not match.parts:
        return alias_of(match.kind, match.value)
    if match.kind == "sid":
        # RID (500 — администратор, 512 — Domain Admins) не секрет и нужен для разбора.
        return alias_of("sid", match.value) + "-" + dict(match.parts)["rid"]
    separator = SEPARATORS[tuple(kind for kind, _ in match.parts)]
    return separator.join(alias_of(kind, value) for kind, value in match.parts)


def without_overlaps(matches: Iterable[Match], rank: Callable[[Match], tuple[int, ...]]) -> list[Match]:
    """Непересекающиеся совпадения: при пересечении остаётся то, у которого меньше `rank`. По start."""
    starts: list[int] = []
    ends: list[int] = []
    kept: list[Match] = []
    for m in sorted(matches, key=rank):
        # Принятые не пересекаются и отсортированы — достаточно соседа слева от m.end.
        i = bisect_left(starts, m.end)
        if i and ends[i - 1] > m.start:
            continue
        starts.insert(i, m.start)
        ends.insert(i, m.end)
        kept.insert(i, m)
    return kept


def replace(text: str, matches: list[Match], alias_of: Callable[[Match], str]) -> str:
    """Один проход слева направо, длинные совпадения раньше коротких; вставленное повторно не ищется."""
    out: list[str] = []
    pos = 0
    for m in without_overlaps(matches, lambda m: (m.start - m.end, m.start)):
        alias = alias_of(m)
        # Псевдоним секрета — метка <secret-xxxxxxxx>, регистр значения в неё не переносится.
        out += (text[pos:m.start], alias if m.kind == "secret" else keep_case(text[m.start:m.end], alias))
        pos = m.end
    out.append(text[pos:])
    return "".join(out)
