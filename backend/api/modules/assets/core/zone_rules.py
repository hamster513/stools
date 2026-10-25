"""Правила отнесения сети к группе (зоне), спека §4: чистые функции без базы.

Правила проверяются по `position`, срабатывает первое включённое подошедшее; не подошло ни одно —
публичная сеть получает External (как раньше делал импорт RackTables), остальные остаются без группы.
Ручную группу (`manual`) правила не трогают — это решает сервис, сюда такие сети не попадают.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache

MATCHES = ("name_prefix", "name_contains", "name_glob", "tag", "cidr")
MAX_VALUE = 500
#: Шаблон со звёздочкой короче прочих значений; сравнивается с именем не длиннее `MAX_TITLE`.
MAX_GLOB = 200
MAX_TITLE = 255
#: Регулярные выражения убраны (владелец 25.10): ни одна проверка шаблона не закрывала зависание
#: единственного процесса API.
REGEX_GONE = "тип правила name_regex больше не поддерживается — используйте шаблон со звёздочкой"
#: То же имя, что `models.EXTERNAL_ZONE`; ядро не тянет модели.
EXTERNAL_ZONE = "External"
SOURCE_MANUAL = "manual"
SOURCE_RULE = "rule"
SOURCE_RACKTABLES = "racktables"


@dataclass(slots=True)
class Rule:
    id: int
    position: int
    enabled: bool
    zone: str
    match: str
    value: str


def validate_rule(match: str, value: str) -> None:
    """ValueError с русским текстом: неизвестный вид, пустое или длинное значение, неверный CIDR."""
    if match == "name_regex":
        raise ValueError(REGEX_GONE)
    if match not in MATCHES:
        raise ValueError(f"неизвестный вид правила «{match}»; допустимы: {', '.join(MATCHES)}")
    if not value.strip():
        raise ValueError("значение правила не может быть пустым")
    if len(value) > MAX_VALUE:
        raise ValueError(f"значение правила длиннее {MAX_VALUE} символов")
    if match == "name_glob" and len(value.strip()) > MAX_GLOB:
        raise ValueError(f"шаблон длиннее {MAX_GLOB} символов")
    if match == "cidr":
        try:
            ipaddress.ip_network(value.strip(), strict=False)
        except ValueError:
            raise ValueError(f"«{value}» — не адрес сети CIDR, например 10.10.0.0/16") from None


def normalize_value(match: str, value: str) -> str:
    """Значение для хранения: без пробелов по краям, CIDR — адресом сети (`10.10.0.7/16` → `10.10.0.0/16`),
    в шаблоне несколько `*` подряд — одной."""
    value = value.strip()
    if match == "cidr":
        return str(ipaddress.ip_network(value, strict=False))
    if match == "name_glob":
        while "**" in value:
            value = value.replace("**", "*")
    return value


def glob_match(pattern: str, title: str) -> bool:
    """Шаблон по всему имени (первые `MAX_TITLE` символов) без учёта регистра: `*` — любая
    последовательность, в т. ч. пустая, `?` — ровно один символ, прочие символы буквально.

    Без `re`: два указателя и возврат только к последней `*` — время не хуже длина имени × длина
    шаблона при любом шаблоне. Регистр сравнивается посимвольно, чтобы `?` всегда был одним символом
    имени (`casefold` всей строки превратил бы «ß» в два)."""
    p = [c.casefold() for c in pattern]
    t = [c.casefold() for c in title[:MAX_TITLE]]
    pi = ti = 0
    star, mark = -1, 0
    while ti < len(t):
        if pi < len(p) and p[pi] == "*":
            star, mark = pi, ti
            pi += 1
        elif pi < len(p) and (p[pi] == "?" or p[pi] == t[ti]):
            pi += 1
            ti += 1
        elif star >= 0:
            # Последняя `*` забирает ещё один символ имени; более ранние `*` пересматривать не нужно.
            mark += 1
            pi, ti = star + 1, mark
        else:
            return False
    while pi < len(p) and p[pi] == "*":
        pi += 1
    return pi == len(p)


@lru_cache(maxsize=512)
def _network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(value, strict=False)


def rule_matches(rule: Rule, *, title: str, tags: Iterable[str], cidr: str) -> bool:
    """Без учёта регистра; `tags` — явные и унаследованные вместе; `cidr` — сеть внутри или равна."""
    value = rule.value
    if rule.match == "name_prefix":
        return title.casefold().startswith(value.casefold())
    if rule.match == "name_contains":
        return value.casefold() in title.casefold()
    if rule.match == "name_glob":
        return glob_match(value, title)
    if rule.match == "tag":
        wanted = value.strip().casefold()
        return any(t.strip().casefold() == wanted for t in tags)
    if rule.match == "cidr":
        net, outer = _network(cidr), _network(value)
        return net.version == outer.version and net.subnet_of(outer)  # type: ignore[arg-type]
    return False


def pick_zone(rules: list[Rule], *, title: str, tags: Iterable[str], cidr: str, public: bool) -> tuple[str | None, str, int | None]:
    """(группа, источник `rule` | `racktables` | "", id правила)."""
    tags = list(tags)
    for rule in sorted(rules, key=lambda r: (r.position, r.id)):
        if rule.enabled and rule_matches(rule, title=title, tags=tags, cidr=cidr):
            return rule.zone, SOURCE_RULE, rule.id
    if public:
        return EXTERNAL_ZONE, SOURCE_RACKTABLES, None
    return None, "", None
