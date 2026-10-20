"""Пользователи как активы: личность учётки (спека §3) и расхождения (§5). Без базы.

Личность:
- `user_key(seen, domain_map) -> (sid, name_key) | None` — ключи учётки. `name_key` —
  `<dns-домен>\\<sam>` в нижнем регистре. Домен — из префикса `ДОМЕН\\` в `sam` или из поля
  `domain`: берётся тот, что в DNS-форме (с точкой); если точки нет ни в одном — NetBIOS → DNS
  по `domain_map` из выгрузок AD, а без записи в карте остаётся как есть в нижнем регистре.
  У локальной — `local:<asset_id хоста>\\<sam>`: локальные учётки между хостами не склеиваются,
  и SID у них ключом не служит (SID машины повторяется на клонах без sysprep). None — не
  пользователь: группа (`group`), внутренняя учётка KSC (`internal`, `ul_InternalUser`),
  учётка компьютера или gMSA (`sam` на `$`), доменная запись с SID не из `S-1-5-21-`
  (NT AUTHORITY, Window Manager, драйверы шрифтов), запись без SID и без имени, локальная
  учётка без хоста (SID не важен).
- `match_user(key, by_sid, by_name) -> MatchResult` — сначала SID, потом `name_key`. По имени
  учётка с SID склеивается только с пользователем без SID: тот же `домен\\имя` с другим SID —
  пересозданная учётка, другой человек. Несколько кандидатов — `ambiguous=True`, это не «нет».
  В `by_sid`/`by_name` не входят строки с `merged_into`. Вызывающий сначала ищет готовое
  наблюдение по (source, source_key) и сопоставляет, только если его нет; при неоднозначности
  запись пропускается и пишется в журнал — новый пользователь не заводится.

Расхождения — `user_discrepancies(user, links, ad_domains) -> list[UserDiscrepancy]`:
- `user: UserCard` — карточка: `enabled` (None — AD не видел), `privileged`, `local`,
  `domain` (DNS-домен, как в `asset_user.domain`), `in_ad` (есть живое наблюдение AD);
- `links: Sequence[UserHostLink]` — связи пользователя с активами-хостами (`asset_user_host`
  плюс имя и ОС актива): `kind` session | owner | local_group, `active` (сеанс KSC в системе
  на момент сбора), `gone` (связь пропала, `gone_at` задан), `users_collected` — собраны ли
  пользователи этого хоста в последнем сборе. False — «не собрано»: сеанс на таком хосте
  считается прошлым («заходил раньше», `active` устарел), владелец без сеанса не судится;
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
    #: Внутренняя учётка KSC (`ul_InternalUser`) — не пользователь.
    internal: bool = False
    #: Запись KSC о группе (`group: true`) — не пользователь.
    group: bool = False
    #: Хост локальной учётки (актив); для доменной — None.
    host_asset_id: int | None = None
    #: Знает только AD; у KSC — None.
    enabled: bool | None = None
    privileged: bool | None = None
    data: dict[str, Any] = field(default_factory=dict)


#: SID доменных и локальных учёток; остальные (S-1-5-18, S-1-5-90-…, S-1-5-96-…) — служебные.
ACCOUNT_SID_PREFIX = "S-1-5-21-"


def _dns_domain(candidates: Sequence[str], domain_map: Mapping[str, str]) -> str:
    """Первый домен в DNS-форме; иначе первый непустой, переведённый из NetBIOS по карте."""
    texts = [t for t in (c.strip().rstrip(".").lower() for c in candidates) if t]
    dotted = next((t for t in texts if "." in t), "")
    if dotted or not texts:
        return dotted
    lowered = {k.lower(): v.lower() for k, v in domain_map.items()}
    return lowered.get(texts[0], texts[0])


def user_key(seen: UserSeen, domain_map: Mapping[str, str]) -> tuple[str, str] | None:
    """(sid, name_key) — пустая строка, если ключа нет; None — запись не пользователь."""
    if seen.group or seen.internal:
        return None
    prefix, _, sam = seen.sam.strip().rpartition("\\")
    sam = sam.lower()
    if sam.endswith("$"):
        return None
    if seen.local:
        if seen.host_asset_id is None or not sam:
            return None
        return "", f"local:{seen.host_asset_id}\\{sam}"
    sid = seen.sid.strip().upper()
    if sid and not sid.startswith(ACCOUNT_SID_PREFIX):
        return None
    domain = _dns_domain((prefix, seen.domain), domain_map)
    name_key = f"{domain}\\{sam}" if sam and domain else ""
    if not sid and not name_key:
        return None
    return sid, name_key


@dataclass(frozen=True, slots=True)
class MatchResult:
    """`user_id` — найденный пользователь; `ambiguous` — кандидатов несколько (`user_id` None)."""

    user_id: int | None
    ambiguous: bool = False


def _one(ids: set[int]) -> MatchResult:
    return MatchResult(ids.pop()) if len(ids) == 1 else MatchResult(None, ambiguous=True)


def match_user(
    key: tuple[str, str],
    by_sid: Mapping[str, Collection[int]],
    by_name: Mapping[str, Collection[tuple[int, str]]],
) -> MatchResult:
    """`by_sid` — SID → id пользователей; `by_name` — name_key → (id, SID пользователя или '');
    строки с `merged_into` в оба не входят."""
    sid, name_key = key
    if sid and (hits := set(by_sid.get(sid, ()))):
        return _one(hits)
    named = {uid for uid, their_sid in by_name.get(name_key, ()) if not sid or not their_sid} if name_key else set()
    return _one(named) if named else MatchResult(None)


def is_workstation(os: str) -> bool | None:
    """По ОС актива-хоста: «server» — сервер (False); Windows и macOS — рабочая станция (True);
    прочее, в том числе Linux и пустая ОС, — None: не судим (по имени дистрибутива не понять)."""
    text = os.lower()
    if "server" in text:
        return False
    if any(mark in text for mark in ("windows", "mac", "os x", "darwin")):
        return True
    return None


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


def _current(link: UserHostLink) -> bool:
    """В системе на момент сбора; у хоста, где пользователи не собраны, `active` устарел."""
    return link.active and link.users_collected


def _when(link: UserHostLink) -> str:
    return "в системе на момент сбора" if _current(link) else "заходил раньше"


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
        current: dict[str, bool] = {}
        for lk in sessions:
            current[_host(lk)] = current.get(_host(lk), False) or _current(lk)
        hosts = ", ".join(
            f"{name} ({'в системе на момент сбора' if cur else 'заходил раньше'})" for name, cur in current.items()
        )
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
