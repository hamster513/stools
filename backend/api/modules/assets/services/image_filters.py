"""Shared filters for the image catalogue and its exports."""
from __future__ import annotations

import re
from collections import Counter
from typing import Any, cast

from api.modules.assets.services.image_origins import ORIGIN_LABELS

NAME_LABELS = {"present": "С названием", "missing": "Без названия"}
FILTER_KEYS = ("source", "status", "registry_origin", "registry", "name_state", "tag", "platform")
_EMPTY = {"", "none", "<none>", "null", "<null>", "образ не определён", "без названия"}


def _empty(value: Any) -> bool:
    return value is None or str(value).strip().lower() in _EMPTY


def _named(value: Any, image_id: str) -> bool:
    value = str(value or "").strip()
    return not _empty(value) and value != image_id and not re.fullmatch(r"(?:sha256:)?[0-9a-fA-F]{64}", value)


def image_filter_fields(item: dict[str, Any], references: list[dict[str, Any]] | None) -> dict[str, Any]:
    names = [r.get("repo") for r in references] if references else [item["title"]]
    named = any(_named(name, item["image_id"]) for name in names)
    raw_tags = [*item["tags"], *(r.get("tag") for r in references or [])]
    tags = list(dict.fromkeys("-" if _empty(t) else str(t).strip() for t in raw_tags)) or ["-"]
    return {"name_state": "present" if named else "missing", "display_title": item["title"] if named else "Без названия",
            "filter_tags": tags}


def values(item: dict[str, Any], key: str) -> list[str]:
    if key == "registry":
        return item["registries"] or ["-"]
    if key == "tag":
        return cast(list[str], item["filter_tags"])
    if key == "platform":
        return list(dict.fromkeys(p.strip() for p in (item["platform"] or "").split(",") if p.strip())) or ["-"]
    return [item[key]]


def matches(item: dict[str, Any], filters: dict[str, Any], skip: str = "") -> bool:
    return all(key == skip or not filters.get(key) or bool(set(values(item, key)) & filters[key]) for key in FILTER_KEYS)


def filter_catalog(items: list[dict[str, Any]], filters: dict[str, Any], *, with_facets: bool) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    facets = None
    if with_facets:
        facets = {}
        for key in FILTER_KEYS:
            counts: Counter[str] = Counter()
            for item in items:
                if matches(item, filters, skip=key):
                    counts.update(set(values(item, key)))
            fixed = ORIGIN_LABELS if key == "registry_origin" else NAME_LABELS if key == "name_state" else {}
            facets[key] = {**{v: 0 for v in fixed}, **dict(sorted(counts.items()))}
    return [item for item in items if matches(item, filters)], facets
