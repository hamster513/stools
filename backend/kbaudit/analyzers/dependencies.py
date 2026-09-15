"""Граф зависимостей правило → правило и наследование требований к телеметрии."""
from __future__ import annotations

from collections import defaultdict

from kbaudit.models import DependencyEdge, Rule


def _casefold_index(rules: list[Rule]) -> dict[str, set[str]]:
    """Индекс «имя без учёта регистра → множество настоящих имён с этим
    написанием».

    Ссылка на correlation_name в теле правила иногда записана в другом
    регистре (например, обёрнута в lower(...) — см. parsers/rule_body.py).
    Само же имя правила в выгрузке одно и записано с исходным регистром,
    поэтому сопоставление со ссылкой должно идти без учёта регистра.

    Значение — множество, а не одно имя: если в выгрузке случайно найдутся
    два правила, различающиеся только регистром (в текущей выгрузке такого
    нет, но заранее полагаться на это нельзя), совпадение с обоими сразу
    неоднозначно. См. _resolve_name — в этом случае ссылка считается
    неразрешённой, а не склеивается наугад с одним из вариантов.
    """
    index: dict[str, set[str]] = defaultdict(set)
    for rule in rules:
        index[rule.name.casefold()].add(rule.name)
    return index


def _resolve_name(
    ref: str, known: set[str], by_casefold: dict[str, set[str]]
) -> str | None:
    """Точное совпадение приоритетнее: если ссылка совпадает с именем
    правила посимвольно, регистр не важен и коллизия исключена по
    построению. Иначе — совпадение без учёта регистра, но только когда оно
    однозначно; при коллизии возвращается None (ссылка не резолвится)."""
    if ref in known:
        return ref
    candidates = by_casefold.get(ref.casefold(), set())
    return next(iter(candidates)) if len(candidates) == 1 else None


def build_edges(rules: list[Rule]) -> list[DependencyEdge]:
    """Ребро parent → child, если child ссылается на parent по correlation_name.

    Сопоставление имени в ссылке с именем правила не учитывает регистр
    (см. _resolve_name), но DependencyEdge.parent всегда содержит настоящее
    имя правила, а не литерал из тела. Ссылки на несуществующие правила
    рёбрами не становятся — см. unresolved_refs.
    """
    known = {r.name for r in rules}
    by_casefold = _casefold_index(rules)
    edges = []
    for rule in rules:
        for ref in rule.corr_refs:
            parent = _resolve_name(ref, known, by_casefold)
            if parent is not None:
                edges.append(DependencyEdge(parent=parent, child=rule.name))
    return sorted(edges, key=lambda e: (e.parent, e.child))


def unresolved_refs(rules: list[Rule]) -> dict[str, list[str]]:
    """Ссылки в никуда. Молча терять их нельзя: это либо опечатка в правиле,
    либо неполная выгрузка. Ссылка приводится в том виде, в каком записана
    в теле правила, — без учёта регистра тоже не разрешилась."""
    known = {r.name for r in rules}
    by_casefold = _casefold_index(rules)
    out = {
        rule.name: sorted(
            ref for ref in rule.corr_refs
            if _resolve_name(ref, known, by_casefold) is None
        )
        for rule in rules
    }
    return {name: refs for name, refs in out.items() if refs}


def inherited_msgids(
    rules: list[Rule], edges: list[DependencyEdge]
) -> dict[str, set[str]]:
    """Собственные msgid правила плюс msgid всех его предков."""
    parents: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        parents[edge.child].append(edge.parent)
    own = {rule.name: set(rule.msgids) for rule in rules}

    resolved: dict[str, set[str]] = {}

    def collect(name: str, seen: frozenset[str]) -> set[str]:
        if name in resolved:
            return resolved[name]
        if name in seen:
            return set(own.get(name, set()))
        total = set(own.get(name, set()))
        for parent in parents.get(name, []):
            total |= collect(parent, seen | {name})
        if name not in seen:
            resolved[name] = total
        return total

    return {rule.name: collect(rule.name, frozenset()) for rule in rules}
