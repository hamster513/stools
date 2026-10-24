"""Правила отнесения сети к группе (зоне), спека §4: чистые функции без базы.

Правила проверяются по `position`, срабатывает первое включённое подошедшее; не подошло ни одно —
публичная сеть получает External (как раньше делал импорт RackTables), остальные остаются без группы.
Ручную группу (`manual`) правила не трогают — это решает сервис, сюда такие сети не попадают.
"""
from __future__ import annotations

import ipaddress
import re
import re._parser as sre_parse  # type: ignore[import-untyped]  # разбор шаблона без компиляции; заглушек нет
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache

MATCHES = ("name_prefix", "name_contains", "name_regex", "tag", "cidr")
MAX_VALUE = 500
#: Регулярное выражение короче прочих значений, а сравнивается с именем не длиннее `MAX_TITLE`:
#: так худший случай перебора остаётся ограниченным.
MAX_REGEX = 200
MAX_TITLE = 255
NESTED_REPEAT = "шаблон с вложенными повторами (например, (\\w+)+) не принимается — упростите"
BRANCH_REPEAT = "шаблон с повтором над альтернативой вида (a|b)+ не принимается — упростите: без повтора над альтернативой"
#: Несколько неограниченных повторов подряд (`\\w*\\w*\\w*!`) дают полиномиальный перебор, который на
#: длинном имени не заканчивается; двух хватает для обычных шаблонов вроде `^APP_.*_\\d+`.
MAX_UNBOUNDED = 2
TOO_MANY_UNBOUNDED = f"в шаблоне не больше {MAX_UNBOUNDED} повторов * или + (и {{n,}}) — упростите"
_REPEATS = (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT, sre_parse.POSSESSIVE_REPEAT)
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
    """ValueError с русским текстом: неизвестный вид, пустое или длинное значение, неверный regex или CIDR."""
    if match not in MATCHES:
        raise ValueError(f"неизвестный вид правила «{match}»; допустимы: {', '.join(MATCHES)}")
    if not value.strip():
        raise ValueError("значение правила не может быть пустым")
    if len(value) > MAX_VALUE:
        raise ValueError(f"значение правила длиннее {MAX_VALUE} символов")
    if match == "name_regex":
        if len(value) > MAX_REGEX:
            raise ValueError(f"регулярное выражение длиннее {MAX_REGEX} символов")
        try:
            parsed = sre_parse.parse(value)
        except re.error as exc:
            raise ValueError(f"«{value}» — неверное регулярное выражение: {exc}") from None
        except (OverflowError, RecursionError):
            raise ValueError("слишком большое число повторов или слишком глубокая вложенность скобок — упростите шаблон") from None
        if _nested_repeat(parsed, inside=False):
            raise ValueError(NESTED_REPEAT)
        if _branch_repeat(parsed, inside=False):
            raise ValueError(BRANCH_REPEAT)
        if _unbounded_repeats(parsed) > MAX_UNBOUNDED:
            raise ValueError(TOO_MANY_UNBOUNDED)
    if match == "cidr":
        try:
            ipaddress.ip_network(value.strip(), strict=False)
        except ValueError:
            raise ValueError(f"«{value}» — не адрес сети CIDR, например 10.10.0.0/16") from None


def _children(av: object) -> Iterable[sre_parse.SubPattern]:
    """Вложенные подшаблоны аргумента узла разбора (группы, ветви, проверки)."""
    if isinstance(av, sre_parse.SubPattern):
        yield av
    elif isinstance(av, (tuple, list)):
        for item in av:
            yield from _children(item)


def _nested_repeat(items: sre_parse.SubPattern, *, inside: bool) -> bool:
    """Есть ли повтор (верхняя граница больше 1) внутри другого такого повтора — источник
    катастрофического перебора вроде `(\\w+)+$`. Проверка с запасом: отвергает и безобидные случаи."""
    for op, av in items:
        if op in _REPEATS:
            _low, high, sub = av
            many = high > 1
            if many and inside:
                return True
            if _nested_repeat(sub, inside=inside or many):
                return True
        elif any(_nested_repeat(child, inside=inside) for child in _children(av)):
            return True
    return False


def _branch_repeat(items: sre_parse.SubPattern, *, inside: bool) -> bool:
    """Есть ли альтернатива (`a|aa`) внутри повтора с верхней границей больше 1 — экспоненциальный
    перебор вроде `(a|aa)+$`. Альтернативы из одиночных символов разбор сам сворачивает в набор `[ab]`."""
    for op, av in items:
        if op in _REPEATS:
            _low, high, sub = av
            if _branch_repeat(sub, inside=inside or high > 1):
                return True
        elif (op is sre_parse.BRANCH and inside) or any(_branch_repeat(child, inside=inside) for child in _children(av)):
            return True
    return False


def _unbounded_repeats(items: sre_parse.SubPattern) -> int:
    """Сколько во всём шаблоне повторов без верхней границы (`*`, `+`, `{n,}`)."""
    count = 0
    for op, av in items:
        if op in _REPEATS:
            _low, high, sub = av
            count += (high == sre_parse.MAXREPEAT) + _unbounded_repeats(sub)
        else:
            count += sum(_unbounded_repeats(child) for child in _children(av))
    return count


def broken_regex(rule: Rule) -> bool:
    """Правило name_regex, чей шаблон не компилируется (записан в обход проверки): оно не срабатывает."""
    if rule.match != "name_regex":
        return False
    try:
        _regex(rule.value)
    except (re.error, OverflowError, RecursionError):
        return True
    return False


def normalize_value(match: str, value: str) -> str:
    """Значение для хранения: без пробелов по краям, CIDR — адресом сети (`10.10.0.7/16` → `10.10.0.0/16`)."""
    value = value.strip()
    return str(ipaddress.ip_network(value, strict=False)) if match == "cidr" else value


@lru_cache(maxsize=512)
def _regex(value: str) -> re.Pattern[str]:
    return re.compile(value, re.IGNORECASE)


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
    if rule.match == "name_regex":
        try:
            return _regex(value).search(title[:MAX_TITLE]) is not None
        except (re.error, OverflowError, RecursionError):
            return False
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
