"""Conservative OSV range matching; unsupported version orders remain unknown.

Range evaluation follows https://ossf.github.io/osv-schema/#evaluation .
Only explicit SEMVER and PyPI ECOSYSTEM orders are supported. An inventory
label is not a package identity: callers must supply an ecosystem/name or purl.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from packaging.version import InvalidVersion, Version

_SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


def _semver(value: str) -> tuple[Any, ...]:
    match = _SEMVER.fullmatch(value)
    if not match:
        raise ValueError("Not a SemVer 2.0 version")
    major, minor, patch, prerelease = match.groups()
    labels: list[tuple[int, int | str]] = []
    for label in prerelease.split(".") if prerelease else []:
        if label.isdigit():
            if len(label) > 1 and label.startswith("0"):
                raise ValueError("Leading zero in numeric prerelease")
            labels.append((0, int(label)))
        else:
            labels.append((1, label))
    return int(major), int(minor), int(patch), not bool(prerelease), tuple(labels)


def _range_affected(version: str, ecosystem: str, item: Mapping[str, Any]) -> bool | None:
    parse: Callable[[str], Any]
    if item.get("type") == "SEMVER":
        parse = _semver
    elif item.get("type") == "ECOSYSTEM" and ecosystem == "PyPI":
        parse = Version
    else:
        return None
    events = item.get("events")
    if not isinstance(events, list) or not events or len(events) > 1024:
        return None
    timeline: list[tuple[Any, str]] = []
    limits: list[Any] = []
    unlimited = False
    kinds: set[str] = set()
    try:
        current = (1, parse(version))
        for event in events:
            if not isinstance(event, dict) or len(event) != 1:
                return None
            kind, value = next(iter(event.items()))
            if kind not in {"introduced", "fixed", "last_affected", "limit"}:
                return None
            if not isinstance(value, str) or not value or len(value) > 256:
                return None
            kinds.add(kind)
            if kind == "limit" and value == "*":
                unlimited = True
                continue
            boundary = (0, None) if kind == "introduced" and value == "0" else (1, parse(value))
            if kind == "limit":
                limits.append(boundary)
            else:
                timeline.append((boundary, kind))
    except (ValueError, InvalidVersion):
        return None
    if "introduced" not in kinds or {"fixed", "last_affected"} <= kinds:
        return None
    if limits and not unlimited and not any(current < limit for limit in limits):
        return False
    affected = False
    # OSV does not require events to arrive in sorted order.
    for boundary, kind in sorted(timeline, key=lambda e: (e[0], e[1] != "introduced")):
        if kind == "introduced" and current >= boundary:
            affected = True
        elif kind == "fixed" and current >= boundary or kind == "last_affected" and current > boundary:
            affected = False
    return affected


def version_affected(
    version: str, ecosystem: str, ranges: Sequence[Mapping[str, Any]], versions: Sequence[str],
) -> bool | None:
    """True: explicit evidence; False: outside known ranges; None: unsupported/absent evidence."""
    if not version or len(version) > 256:
        return None
    if version in versions:
        return True
    unknown = False
    for item in ranges:
        result = _range_affected(version, ecosystem, item)
        if result is True:
            return True
        unknown |= result is None
    return None if unknown or not (ranges or versions) else False


def match_package(
    package: Mapping[str, Any], *, ecosystem: str | None, name: str | None,
    version: str, purl: str | None = None, withdrawn: bool = False,
) -> bool | None:
    """Match an exact supplied identity only; never infer an ecosystem from a display name."""
    if withdrawn:
        return None
    if ecosystem and package.get("ecosystem") != ecosystem:
        return False
    if name and package.get("name") != name:
        return False
    if purl and package.get("purl") and purl != package["purl"]:
        return False
    exact_identity = bool(ecosystem and name) or bool(purl and purl == package.get("purl"))
    if not exact_identity:
        return None
    return version_affected(version, package.get("ecosystem", ""),
                            package.get("ranges", []), package.get("versions", []))
