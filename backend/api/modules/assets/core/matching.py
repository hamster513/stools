"""Привязка наблюдения к активу и каноническая карточка (спека §2).

Чистые функции над dataclass-ами, без базы: правила проверяются юнит-тестами,
а сервис подаёт сюда кандидатов, которых нашёл по индексам.

Имя сравнивается коротким (`ws01`), домен — DNS-суффиксом (`corp.local`);
NetBIOS-домен (`CORP`) переводится в DNS-домен по карте из выгрузок AD, а без карты —
по первой метке, если такой известный домен один. Если правилу удовлетворяют несколько
активов, совпадения нет: склеить не тот хост хуже, чем завести новый актив.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

#: Поля карточки, которые пересчитываются из наблюдений и закрепляются.
FIELDS = ("name", "fqdn", "domain", "ip", "os")

#: Порядок источников при равном `seen_at` (спека §2): у VM `seen_at` — время импорта, он последний.
PRECEDENCE = {"dns": 4, "scan": 3, "ksc": 2, "ad": 1, "vm": 0}

_EPOCH = dt.datetime.min.replace(tzinfo=dt.UTC)


@dataclass(slots=True)
class Observed:
    """То, что видит источник (без базы)."""

    source: str
    source_key: str
    name: str = ""
    fqdn: str = ""
    domain: str = ""
    ip: str = ""
    ips: list[str] = field(default_factory=list)
    os: str = ""
    seen_at: dt.datetime | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    #: Источник перестал отдавать хост: в канонические поля наблюдение не идёт.
    gone_at: dt.datetime | None = None


@dataclass(slots=True)
class Candidate:
    """Актив с его наблюдениями, как их видит сопоставитель."""

    asset_id: int
    name: str
    fqdn: str
    domain: str
    ip: str
    observations: list[Observed]


def is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip())
    except ValueError:
        return False
    return True


def normalize_ip(text: str) -> str:
    """Адрес в одном написании (`2001:DB8:0::5` → `2001:db8::5`); не адрес — пусто."""
    try:
        return ipaddress.ip_address(text.strip()).compressed
    except ValueError:
        return ""


def normalize_name(name: str) -> tuple[str, str]:
    """'WS01$' → ('ws01', ''); 'ws01.corp.local' → ('ws01', 'corp.local'); 'CORP\\\\ws01' → ('ws01', 'corp'); IP → ('', '')."""
    text = name.strip().rstrip(".").lower()
    if not text or is_ip(text):
        return "", ""
    if "\\" in text:
        domain, _, short = text.rpartition("\\")
        return short.rstrip("$"), domain
    short, _, domain = text.partition(".")
    return short.rstrip("$"), domain


def normalize_fqdn(fqdn: str) -> str:
    """FQDN без точки (рабочая группа в KSC) и адрес вместо имени — не FQDN."""
    text = fqdn.strip().rstrip(".").lower()
    return text if "." in text and not is_ip(text) else ""


def _resolver(domain_map: Mapping[str, str], known: Iterable[str]) -> Callable[[str], str]:
    """NetBIOS-домен → DNS-домен: по карте AD, иначе по первой метке, если такой домен один."""
    dotted = set(domain_map.values()) | {d for d in known if "." in d}

    def resolve(domain: str) -> str:
        if not domain or "." in domain:
            return domain
        if domain in domain_map:
            return domain_map[domain]
        hits = [d for d in dotted if d.partition(".")[0] == domain]
        return hits[0] if len(hits) == 1 else domain

    return resolve


@dataclass(slots=True)
class _Keys:
    fqdns: set[str]
    #: (короткое имя, домен или '') — домен у имени свой: у VM его нет, у KSC есть.
    names: set[tuple[str, str]]
    ips: set[str]

    @property
    def shorts(self) -> set[str]:
        return {s for s, _ in self.names}


def _keys(name: str, fqdn: str, domain: str, ip: str, ips: Iterable[str] = ()) -> _Keys:
    fq = normalize_fqdn(fqdn)
    short, name_domain = normalize_name(name)
    # Имя с точкой (у VM другого нет) — тоже FQDN.
    if not fq and name_domain and "." in name_domain:
        fq = f"{short}.{name_domain}"
    dom = domain.strip().rstrip(".").lower() or name_domain
    names: set[tuple[str, str]] = set()
    if fq:
        f_short, _, f_domain = fq.partition(".")
        names.add((f_short, f_domain))
        dom = dom or f_domain
    if short:
        names.add((short, dom))
    return _Keys({fq} if fq else set(), names, {a for a in (normalize_ip(x) for x in (ip, *ips)) if a})


def _obs_keys(o: Observed) -> _Keys:
    return _keys(o.name, o.fqdn, o.domain, o.ip, o.ips)


def _candidate_keys(c: Candidate) -> _Keys:
    total = _keys(c.name, c.fqdn, c.domain, c.ip)
    for o in c.observations:
        k = _obs_keys(o)
        total.fqdns |= k.fqdns
        total.names |= k.names
        # Адрес, который актив держал когда-то, не склеивает (правило 5 — только живые).
        if o.gone_at is None:
            total.ips |= k.ips
    return total


def tokens(o: Observed) -> set[str]:
    """Ключи поиска кандидатов: FQDN, короткие имена, адреса (для индексов сервиса)."""
    k = _obs_keys(o)
    return {f"f:{f}" for f in k.fqdns} | {f"n:{s}" for s in k.shorts} | {f"i:{ip}" for ip in k.ips}


def candidate_tokens(c: Candidate) -> set[str]:
    k = _candidate_keys(c)
    return {f"f:{f}" for f in k.fqdns} | {f"n:{s}" for s in k.shorts} | {f"i:{ip}" for ip in k.ips}


def _rule(obs: _Keys, cand: _Keys, rule: int, resolve: Callable[[str], str]) -> bool:
    if rule == 2:
        return bool(obs.fqdns & cand.fqdns)
    if rule == 3:
        return any(
            od and cd and os_ == cs and resolve(od) == resolve(cd)
            for os_, od in obs.names for cs, cd in cand.names
        )
    if rule == 4:
        common = obs.shorts & cand.shorts
        if not common:
            return False
        obs_domains = {d for s, d in obs.names if s in common and d}
        cand_domains = {d for s, d in cand.names if s in common and d}
        return not obs_domains or not cand_domains
    if rule == 5:
        return bool(obs.ips & cand.ips) and (not obs.shorts or not cand.shorts)
    return False


def match(
    obs: Observed, candidates: Iterable[Candidate], domain_map: Mapping[str, str] | None = None,
) -> tuple[int | None, int]:
    """(asset_id, номер сработавшего правила 1–5) или (None, 0). Правила проверяются по порядку
    по всем кандидатам: совпадение по FQDN у одного важнее совпадения по адресу у другого.
    Правилу удовлетворяют несколько активов — (None, 0); для правила 5 из них выбирается тот,
    чей канонический IP и есть адрес наблюдения, если такой один. `domain_map` — NetBIOS → DNS
    из выгрузок AD."""
    pool = list(candidates)
    for c in pool:
        if any(o.source == obs.source and o.source_key == obs.source_key for o in c.observations):
            return c.asset_id, 1
    mine = _obs_keys(obs)
    keyed = [(c, _candidate_keys(c)) for c in pool]
    known = {d for _, d in mine.names} | {d for _, k in keyed for _, d in k.names}
    resolve = _resolver({k.lower(): v.lower() for k, v in (domain_map or {}).items()}, known)
    for rule in (2, 3, 4, 5):
        hits = [c for c, theirs in keyed if _rule(mine, theirs, rule, resolve)]
        if rule == 5 and len(hits) > 1:
            hits = [c for c in hits if normalize_ip(c.ip) in mine.ips]
        if len(hits) == 1:
            return hits[0].asset_id, rule
        if hits:
            return None, 0
    return None, 0


def _seen(o: Observed) -> dt.datetime:
    return o.seen_at or _EPOCH


def _freshness(o: Observed) -> tuple[dt.datetime, int]:
    return _seen(o), PRECEDENCE.get(o.source, -1)


def canonical(observations: list[Observed], pinned: dict[str, bool], current: dict[str, str]) -> dict[str, Any]:
    """name, fqdn, domain, ip, os, first_seen, last_seen по спеке §2; закреплённые поля из current.
    Если живых наблюдений нет совсем, карточка держит последнее известное, а не пустеет."""
    live = [o for o in observations if o.gone_at is None] or list(observations)
    fresh_first = sorted(live, key=_freshness, reverse=True)
    card: dict[str, Any] = {}
    for name in FIELDS:
        if pinned.get(name):
            card[name] = current.get(name, "")
        elif name == "ip":
            card[name] = next((a for a in (normalize_ip(o.ip) for o in fresh_first) if a), "")
        else:
            card[name] = next((getattr(o, name) for o in fresh_first if getattr(o, name)), "")
    all_seen = [o.seen_at for o in observations if o.seen_at]
    live_seen = [o.seen_at for o in live if o.seen_at]
    card["first_seen"] = min(all_seen) if all_seen else None
    card["last_seen"] = max(live_seen) if live_seen else None
    return card
