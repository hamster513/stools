"""Сравнение выгруженных списков: содержимое, кратность и порядок, без привязки к профилю."""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict, deque
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any

FIELDS = ('layer', 'name', 'action', 'direction', 'protocol', 'local_ports', 'remote_ports', 'addresses', 'enabled', 'scope')


def values(row: Any) -> tuple[Any, ...]:
    scope = json.dumps(json.loads(row.scope_json), sort_keys=True, ensure_ascii=False) if row.scope_json else None
    return tuple(scope if key == 'scope' else getattr(row, key) for key in FIELDS)


def list_signature(rows: list[Any]) -> str:
    data = [(r.position, values(r)) for r in rows]
    return hashlib.sha256(json.dumps(data, ensure_ascii=False).encode()).hexdigest()


@dataclass
class Delta:
    row: Any
    previous: Any | None
    kind: str
    fields: list[str]
    moved: bool = False


@dataclass
class Comparison:
    summary: dict[str, int]
    deltas: list[Delta]


def compare_rules(base: list[Any], profile: list[Any]) -> Comparison:
    """Сначала точные совпадения с кратностью, затем однозначные пары по имени.

    При нескольких одноимённых остатках не угадываем соответствие. Перемещение —
    изменение относительного порядка совпавших правил, а не сдвиг из-за вставки.
    """
    available: dict[tuple[Any, ...], deque[int]] = defaultdict(deque)
    for i, row in enumerate(base):
        available[values(row)].append(i)
    pairs: dict[int, int] = {}
    for j, row in enumerate(profile):
        candidates = available[values(row)]
        if candidates:
            pairs[j] = candidates.popleft()
    used = set(pairs.values())
    old_names: dict[tuple[str, str], list[int]] = defaultdict(list)
    new_names: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i, row in enumerate(base):
        if i not in used:
            old_names[(row.layer, row.name)].append(i)
    for j, row in enumerate(profile):
        if j not in pairs:
            new_names[(row.layer, row.name)].append(j)
    for name, old in old_names.items():
        new = new_names[name]
        if name[1] and len(old) == len(new) == 1:
            pairs[new[0]] = old[0]
            used.add(old[0])
    ordered = [pairs[j] for j in sorted(pairs)]
    stationary = set()
    for match in SequenceMatcher(a=sorted(ordered), b=ordered, autojunk=False).get_matching_blocks():
        stationary.update(ordered[match.b:match.b + match.size])
    counts = dict(unchanged=0, added=0, removed=0, changed=0, moved=0)
    deltas = []
    for j, row in enumerate(profile):
        if j not in pairs:
            counts['added'] += 1
            deltas.append(Delta(row, None, 'added', []))
            continue
        previous = base[pairs[j]]
        fields = [key for key, a, b in zip(FIELDS, values(previous), values(row)) if a != b]
        moved = pairs[j] not in stationary
        counts['changed'] += bool(fields)
        counts['moved'] += moved
        if fields or moved:
            deltas.append(Delta(row, previous, 'changed' if fields else 'moved', fields, moved))
        else:
            counts['unchanged'] += 1
    for i, row in enumerate(base):
        if i not in used:
            counts['removed'] += 1
            deltas.append(Delta(row, None, 'removed', []))
    return Comparison(counts, deltas)
