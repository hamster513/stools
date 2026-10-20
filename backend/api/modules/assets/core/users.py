"""Пользователи как активы: личность учётки (спека §3) и расхождения (§5). Без базы.

Личность:
- `user_key(seen, domain_map) -> (sid, name_key) | None` — ключи учётки. `name_key` —
  `<dns-домен>\\<sam>` в нижнем регистре (NetBIOS-домен → DNS по `domain_map` из выгрузок AD),
  у локальной — `local:<asset_id хоста>\\<sam>`: локальные учётки между хостами не склеиваются,
  и SID у них ключом не служит (SID машины повторяется на клонах без sysprep). None — не
  пользователь: группа (`group`), запись без SID и без имени, локальная без хоста и SID.
- `match_user(key, by_sid, by_name) -> id | None` — сначала SID, потом `name_key`. По имени
  учётка с SID склеивается только с пользователем без SID: тот же `домен\\имя` с другим SID —
  пересозданная учётка, другой человек. Несколько кандидатов — None.

Расхождения — `user_discrepancies(user, links, ad_domains) -> list[UserDiscrepancy]`:
- `user: UserCard` — карточка: `enabled` (None — AD не видел), `privileged`, `local`,
  `domain` (DNS-домен, как в `asset_user.domain`), `in_ad` (есть живое наблюдение AD);
- `links: Sequence[UserHostLink]` — связи пользователя с активами-хостами (`asset_user_host`
  плюс имя и ОС актива): `kind` session | owner | local_group, `active` (сеанс KSC в системе
  на момент сбора), `gone` (связь пропала, `gone_at` задан), `users_collected` — собраны ли
  пользователи этого хоста (False — «не собрано», о сеансах на нём судить нельзя);
- `ad_domains` — DNS-домены, чьи выгрузки AD есть: «нет в AD» только для них.
Сеанс — живая связь `session` (в системе или заходил раньше). Порядок — как в `USER_CODES`,
внутри кода — как в `links`. Считаются на лету, находками платформы пока не становятся.
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

USER_CODES = ("disabled_session", "not_in_ad", "privileged_on_workstation", "owner_without_session")


@dataclass(slots=True)
class UserSeen:
    """То, что источник (ad | ksc) сказал об учётке."""

    source: str
    source_key: str
    seen_at: dt.datetime
    sid: str = ""
    #: AD — `user01`; KSC — `CORP\\user01` или `user01`.
    sam: str = ""
    upn: str = ""
    display_name: str = ""
    #: DNS- или NetBIOS-домен, как отдал источник.
    domain: str = ""
    local: bool = False
    #: Запись KSC о группе (`group: true`) — не пользователь.
    group: bool = False
    #: Хост локальной учётки (актив); для доменной — None.
    host_asset_id: int | None = None
    #: Знает только AD; у KSC — None.
    enabled: bool | None = None
    privileged: bool | None = None
    data: dict[str, Any] = field(default_factory=dict)


def _dns_domain(domain: str, domain_map: Mapping[str, str]) -> str:
    text = domain.strip().rstrip(".").lower()
    if not text or "." in text:
        return text
    lowered = {k.lower(): v.lower() for k, v in domain_map.items()}
    return lowered.get(text, text)


def user_key(seen: UserSeen, domain_map: Mapping[str, str]) -> tuple[str, str] | None:
    """(sid, name_key) — пустая строка, если ключа нет; None — запись не пользователь."""
    if seen.group:
        return None
    prefix, _, sam = seen.sam.strip().rpartition("\\")
    sam = sam.lower()
    if seen.local:
        if seen.host_asset_id is None or not sam:
            return None
        return "", f"local:{seen.host_asset_id}\\{sam}"
    sid = seen.sid.strip().upper()
    domain = _dns_domain(prefix or seen.domain, domain_map)
    name_key = f"{domain}\\{sam}" if sam and domain else ""
    if not sid and not name_key:
        return None
    return sid, name_key


def match_user(
    key: tuple[str, str],
    by_sid: Mapping[str, Collection[int]],
    by_name: Mapping[str, Collection[tuple[int, str]]],
) -> int | None:
    """`by_sid` — SID → id пользователей; `by_name` — name_key → (id, SID пользователя или '')."""
    sid, name_key = key
    if sid and (hits := set(by_sid.get(sid, ()))):
        return hits.pop() if len(hits) == 1 else None
    if not name_key:
        return None
    named = {uid for uid, their_sid in by_name.get(name_key, ()) if not sid or not their_sid}
    return named.pop() if len(named) == 1 else None


def is_workstation(os: str) -> bool | None:
    """Рабочая станция — ОС без «server»; ОС неизвестна — None (не судим)."""
    if not os.strip():
        return None
    return "server" not in os.lower()


@dataclass(slots=True)
class UserCard:
    enabled: bool | None
    privileged: bool
    local: bool
    domain: str
    in_ad: bool


@dataclass(slots=True)
class UserHostLink:
    asset_id: int
    name: str
    os: str
    #: session | owner | local_group
    kind: str
    active: bool = False
    gone: bool = False
    users_collected: bool = True


@dataclass(slots=True)
class UserDiscrepancy:
    code: str
    host_asset_id: int | None
    text: str


def _when(link: UserHostLink) -> str:
    return "в системе на момент сбора" if link.active else "заходил раньше"


def _host(link: UserHostLink) -> str:
    return link.name or f"актив #{link.asset_id}"


def user_discrepancies(
    user: UserCard, links: Sequence[UserHostLink], ad_domains: Collection[str],
) -> list[UserDiscrepancy]:
    sessions = [lk for lk in links if lk.kind == "session" and not lk.gone]
    out: list[UserDiscrepancy] = []

    if user.enabled is False:
        for lk in sessions:
            out.append(UserDiscrepancy("disabled_session", lk.asset_id,
                                       f"учётка отключена в AD, сеанс на {_host(lk)}: {_when(lk)}"))

    domain = user.domain.strip().lower()
    known = {d.strip().lower() for d in ad_domains}
    if sessions and not user.local and not user.in_ad and domain and domain in known:
        hosts = ", ".join(dict.fromkeys(_host(lk) for lk in sessions))
        out.append(UserDiscrepancy("not_in_ad", None, f"учётки нет в AD {domain}, сеансы на {hosts}"))

    if user.privileged:
        for lk in sessions:
            if is_workstation(lk.os):
                out.append(UserDiscrepancy("privileged_on_workstation", lk.asset_id,
                                           f"привилегированная учётка на рабочей станции {_host(lk)}: {_when(lk)}"))

    with_session = {lk.asset_id for lk in sessions}
    for lk in links:
        if lk.kind == "owner" and not lk.gone and lk.users_collected and lk.asset_id not in with_session:
            out.append(UserDiscrepancy("owner_without_session", lk.asset_id,
                                       f"владелец {_host(lk)} по KSC, но сеансов на нём нет"))
    return out
