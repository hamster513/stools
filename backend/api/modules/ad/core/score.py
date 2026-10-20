"""Оценка домена по категориям проверок (спека §6 «Оценка»): 0 — чисто, 100 — худшее.

Проверка вносит вес своей худшей находки один раз, сколько бы находок ни было:
иначе одна шумная проверка с сотнями Low перевесит единственную Critical.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

WEIGHTS = {"Critical": 40, "High": 20, "Medium": 10, "Low": 3, "Info": 0}
CAP = 100


def score(rows: Iterable[tuple[str, str]], category_of: Mapping[str, str]) -> dict[str, Any]:
    """`rows` — (код проверки, серьёзность) открытых находок; `category_of` — код → категория.
    Проверки без категории не участвуют. В ответе все категории из `category_of`, и пустые."""
    worst: dict[str, tuple[int, str]] = {}
    for check, severity in rows:
        if check not in category_of:
            continue
        points = WEIGHTS.get(severity, 0)
        if points and points > worst.get(check, (0, ""))[0]:
            worst[check] = (points, severity)
    categories: dict[str, dict[str, Any]] = {cat: {"score": 0, "checks": []} for cat in dict.fromkeys(category_of.values())}
    for check, (points, severity) in sorted(worst.items(), key=lambda kv: (-kv[1][0], kv[0])):
        categories[category_of[check]]["checks"].append({"code": check, "severity": severity, "points": points})
    for entry in categories.values():
        entry["score"] = min(CAP, sum(c["points"] for c in entry["checks"]))
    return {"total": max((e["score"] for e in categories.values()), default=0), "categories": categories}
