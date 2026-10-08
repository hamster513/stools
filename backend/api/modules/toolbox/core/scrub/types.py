"""Типы движка очистки: категории находок, совпадение, находка, контекст поиска, таблица псевдонимов."""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, IPv6Address
from typing import Protocol

#: Порядок — приоритет при пересечении совпадений (спека §1).
KINDS = ("secret", "word", "user", "host", "domain", "sid", "ip4", "ip6", "mac")
#: Секреты в таблицу соответствий не пишутся никогда: обратного перевода у них нет.
STORED_KINDS = tuple(k for k in KINDS if k != "secret")


@dataclass(slots=True, frozen=True)
class Match:
    start: int
    end: int
    kind: str
    value: str  # как в тексте
    # Составное совпадение раскладывается на части, чтобы у частей были свои псевдонимы:
    # (("host", "msk1"), ("domain", "corp.test")) для FQDN, (("rid", "500"),) для SID.
    parts: tuple[tuple[str, str], ...] = ()
    # Найдено авто-поиском, а не по словарю: в предпросмотре без галочки.
    auto: bool = False


@dataclass(slots=True)
class Finding:
    kind: str
    value: str
    value_key: str
    alias: str
    count: int = 0
    contexts: list[str] = field(default_factory=list)  # ≤ 3 по 80 символов
    first_file: str = ""
    checked: bool = True
    auto: bool = False


@dataclass(slots=True)
class Ctx:
    domains: frozenset[str]  # нижний регистр: dns_root и netbios
    hosts: frozenset[str]  # нижний регистр, короткие имена и fqdn
    users: frozenset[str]  # нижний регистр sAMAccountName; пусто — только regex
    words: dict[str, str]  # слово → псевдоним ("" — назначить word-NNNN)
    subnets: list[tuple[IPv4Network, IPv4Network]]  # «что → во что», по убыванию prefixlen
    json_key: str = ""  # ключ JSON, под которым лежит строка; "" — обычный текст


class Aliases(Protocol):
    def get(self, kind: str, key: str) -> str | None: ...

    def propose(self, kind: str, value: str, key: str) -> str:
        """Кандидат без записи; стабилен внутри одного задания."""
        ...

    def commit(self, pairs: Iterable[tuple[str, str, str, str]]) -> None:
        """Пары (kind, key, real, alias)."""
        ...


def value_key(kind: str, value: str) -> str:
    """Ключ значения в таблице: одно настоящее значение в разных написаниях — один ключ."""
    if kind == "ip4":
        return str(IPv4Address(value))
    if kind == "ip6":
        return IPv6Address(value).compressed
    if kind == "mac":
        return ":".join(re.split(r"[:-]", value)).lower()
    # Регистр SID и секрета значим: Qwerty и qwerty — разные пароли.
    if kind in ("sid", "secret"):
        return value
    return value.lower()
