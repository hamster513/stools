"""Привязка наблюдения к активу и каноническая карточка (спека §2).

Чистые функции над dataclass-ами, без базы: правила проверяются юнит-тестами,
а сервис подаёт сюда кандидатов, которых нашёл по индексам.

Имя сравнивается коротким (`ws01`), домен — DNS-суффиксом (`corp.local`);
NetBIOS-домен (`CORP`) совпадает с DNS-доменом, первая метка которого — он же.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

#: Поля карточки, которые пересчитываются из наблюдений и закрепляются.
FIELDS = ("name", "fqdn", "domain", "ip", "os")

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


def same_domain(a: str, b: str) -> bool:
    if a == b:
        return True
    if "." not in a:
        return a == b.partition(".")[0]
    if "." not in b:
        return b == a.partition(".")[0]
    return False


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
    return _Keys({fq} if fq else set(), names, {x for x in (ip, *ips) if x})


def _obs_keys(o: Observed) -> _Keys:
    return _keys(o.name, o.fqdn, o.domain, o.ip, o.ips)


def _candidate_keys(c: Candidate) -> _Keys:
    total = _keys(c.name, c.fqdn, c.domain, c.ip)
    for o in c.observations:
        k = _obs_keys(o)
        total.fqdns |= k.fqdns
        total.names |= k.names
        total.ips |= k.ips
    return total


def tokens(o: Observed) -> set[str]:
    """Ключи поиска кандидатов: FQDN, короткие имена, адреса (для индексов сервиса)."""
    k = _obs_keys(o)
    return {f"f:{f}" for f in k.fqdns} | {f"n:{s}" for s in k.shorts} | {f"i:{ip}" for ip in k.ips}


def candidate_tokens(c: Candidate) -> set[str]:
    k = _candidate_keys(c)
    return {f"f:{f}" for f in k.fqdns} | {f"n:{s}" for s in k.shorts} | {f"i:{ip}" for ip in k.ips}


def _rule(obs: _Keys, cand: _Keys, rule: int) -> bool:
    if rule == 2:
        return bool(obs.fqdns & cand.fqdns)
    if rule == 3:
        return any(
            od and cd and os_ == cs and same_domain(od, cd)
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


def match(obs: Observed, candidates: Iterable[Candidate]) -> tuple[int | None, int]:
    """(asset_id, номер сработавшего правила 1–5) или (None, 0). Правила проверяются по порядку
    по всем кандидатам: совпадение по FQDN у одного важнее совпадения по адресу у другого."""
    pool = list(candidates)
    for c in pool:
        if any(o.source == obs.source and o.source_key == obs.source_key for o in c.observations):
            return c.asset_id, 1
    mine = _obs_keys(obs)
    keyed = [(c, _candidate_keys(c)) for c in pool]
    for rule in (2, 3, 4, 5):
        for c, theirs in keyed:
            if _rule(mine, theirs, rule):
                return c.asset_id, rule
    return None, 0


def _seen(o: Observed) -> dt.datetime:
    return o.seen_at or _EPOCH


def canonical(observations: list[Observed], pinned: dict[str, bool], current: dict[str, str]) -> dict[str, Any]:
    """name, fqdn, domain, ip, os, first_seen, last_seen по спеке §2; закреплённые поля из current.
    Если живых наблюдений нет совсем, карточка держит последнее известное, а не пустеет."""
    live = [o for o in observations if o.gone_at is None] or list(observations)
    fresh_first = sorted(live, key=_seen, reverse=True)
    card: dict[str, Any] = {}
    for name in FIELDS:
        if pinned.get(name):
            card[name] = current.get(name, "")
        else:
            card[name] = next((getattr(o, name) for o in fresh_first if getattr(o, name)), "")
    all_seen = [o.seen_at for o in observations if o.seen_at]
    live_seen = [o.seen_at for o in live if o.seen_at]
    card["first_seen"] = min(all_seen) if all_seen else None
    card["last_seen"] = max(live_seen) if live_seen else None
    return card
