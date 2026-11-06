"""Classify declared image registries, independently of the inventory source."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.modules.vm.models import VmImage
from api.modules.vm.services.harbor_settings import load_harbor

ORIGIN_LABELS = {
    "corporate": "Корпоративный", "external": "Внешний реестр",
    "mixed": "Есть внешние реестры", "unknown": "Не определён",
}


def registry_identity(value: str | None) -> str | None:
    """Compare authorities, never host substrings, names/tags or image hashes.

    Registry observations often omit the protocol. Standard HTTP(S) ports
    represent the same registry; nonstandard ports remain part of its identity.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if any(c.isspace() for c in value) or "\\" in value:
        return None
    try:
        parts = urlsplit(value if "://" in value else "//" + value)
        if parts.scheme not in ("", "http", "https") or parts.username is not None or parts.password is not None:
            return None
        host = (parts.hostname or "").rstrip(".").lower().encode("idna").decode("ascii")
        if not host or not re.fullmatch(r"[a-z0-9_.:\-]+", host):
            return None
        port = parts.port
    except (ValueError, UnicodeError):
        return None
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{port}" if port is not None and port not in (80, 443) else host


def corporate_registries(db: Session) -> set[str]:
    addresses = [load_harbor(db).url]
    addresses.extend(address for address, _count in db.execute(
        select(VmImage.registry_url, func.count()).where(VmImage.registry_url != "").group_by(VmImage.registry_url),
    ))
    return {identity for address in addresses if (identity := registry_identity(address))}


def harbor_origin(address: str | None) -> dict[str, Any]:
    identity = registry_identity(address)
    return {"registry_origin": "corporate", "registries": [identity] if identity else [], "external_registries": []}


def origin_for_references(references: list[dict[str, Any]] | None, corporate: set[str]) -> dict[str, Any]:
    identities = [registry_identity(r.get("registry")) for r in references or []]
    known = {identity for identity in identities if identity is not None}
    external = known - corporate if corporate else set()
    if external:
        origin = "mixed" if known & corporate else "external"
    elif corporate and identities and None not in identities:
        origin = "corporate"
    else:
        origin = "unknown"
    return {"registry_origin": origin, "registries": sorted(known), "external_registries": sorted(external)}
