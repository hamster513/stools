"""Read-only, field-allowlisted adapters for the IRP service."""
from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime
from ipaddress import ip_address
from typing import Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints, model_validator
from sqlalchemy import ColumnElement, RowMapping, case, cast, func, or_, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.modules.assets.models import Asset, AssetUser
from api.modules.ksc.models import KscHost, KscSnapshot
from api.modules.vm.models import VmHost, VmHostCve, VmRefAttack
from api.timeutil import as_aware_utc, utcnow

Source = Literal["assets", "accounts", "av", "vm", "attack"]
SOURCES: tuple[Source, ...] = ("assets", "accounts", "av", "vm", "attack")
MAX_MATCHES = 20


class Entity(BaseModel):
    kind: Literal["ip", "host", "user", "domain", "hash"]
    value: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]

    @model_validator(mode="after")
    def normalize_ip(self) -> Entity:
        if self.kind == "ip":
            if "%" in self.value:
                raise ValueError("invalid IP address")
            self.value = str(ip_address(self.value))
        return self


class EnrichmentRequest(BaseModel):
    entities: list[Entity] = Field(max_length=20)
    sources: list[Source] = Field(default_factory=lambda: list(SOURCES), max_length=len(SOURCES))


ResultStatus = Literal["ok", "not_found", "not_configured", "ambiguous", "error"]


class EnrichmentResult(BaseModel):
    entity: Entity
    source: Source
    status: ResultStatus
    observed_at: datetime | None = None
    fetched_at: datetime
    data: dict[str, object] = Field(default_factory=dict)
    error: str | None = None


# Observation dates are selected separately so no source metadata or raw records leave the adapter.
AdapterResult = tuple[ResultStatus, dict[str, object], datetime | None]


def _matches(rows: Sequence[RowMapping], *, observed: str | None = None) -> AdapterResult:
    if not rows:
        return "not_found", {}, None
    matches = []
    for row in rows[:MAX_MATCHES]:
        match = dict(row)
        if observed:
            match.pop(observed)
        if "id" in match:
            match["id"] = str(match["id"])
        matches.append(match)
    timestamp = rows[0][observed] if observed and len(rows) == 1 else None
    return (
        "ambiguous" if len(rows) > 1 else "ok",
        {"matches": matches, "truncated": len(rows) > MAX_MATCHES},
        as_aware_utc(timestamp) if timestamp is not None else None,
    )


def _assets(db: Session, entity: Entity) -> AdapterResult:
    value = entity.value.lower()
    if entity.kind == "ip":
        match = func.lower(Asset.ip) == value
    elif entity.kind == "host":
        match = or_(Asset.name_key == value, func.lower(Asset.fqdn) == value)
    elif entity.kind == "domain":
        match = func.lower(Asset.fqdn) == value
    else:
        return "not_found", {}, None
    rows = db.execute(
        select(Asset.id, Asset.name, Asset.fqdn, Asset.ip, Asset.os, Asset.criticality, Asset.last_seen)
        .where(Asset.merged_into.is_(None), match).order_by(Asset.id).limit(MAX_MATCHES + 1)
    ).mappings().all()
    return _matches(rows, observed="last_seen")


def _accounts(db: Session, entity: Entity) -> AdapterResult:
    if entity.kind != "user":
        return "not_found", {}, None
    value = entity.value.lower()
    rows = db.execute(
        select(AssetUser.id, AssetUser.sam, AssetUser.domain, AssetUser.enabled, AssetUser.last_seen)
        .where(AssetUser.merged_into.is_(None), or_(
            AssetUser.name_key == value, func.lower(AssetUser.sam) == value, func.lower(AssetUser.upn) == value,
        ))
        .order_by(AssetUser.id).limit(MAX_MATCHES + 1)
    ).mappings().all()
    return _matches(rows, observed="last_seen")


def _av(db: Session, entity: Entity) -> AdapterResult:
    value = entity.value.lower()
    if entity.kind == "ip":
        match = func.lower(KscHost.ip) == value
    elif entity.kind == "host":
        match = or_(func.lower(KscHost.name) == value, func.lower(KscHost.fqdn) == value)
    elif entity.kind == "domain":
        match = func.lower(KscHost.fqdn) == value
    else:
        return "not_found", {}, None
    latest = select(
        KscSnapshot.id, KscSnapshot.collected_at,
        func.row_number().over(
            partition_by=KscSnapshot.server_id, order_by=(KscSnapshot.collected_at.desc(), KscSnapshot.id.desc()),
        ).label("position"),
    ).subquery()
    rows = db.execute(
        select(KscHost.id, KscHost.name, KscHost.fqdn, KscHost.ip, KscHost.protection, KscHost.status,
               KscHost.agent_alive, KscHost.product, latest.c.collected_at)
        .join(latest, KscHost.snapshot_id == latest.c.id)
        .where(latest.c.position == 1, match).order_by(KscHost.id).limit(MAX_MATCHES + 1)
    ).mappings().all()
    return _matches(rows, observed="collected_at")


def _vm_hosts(db: Session, entity: Entity) -> Sequence[RowMapping]:
    if entity.kind == "ip":
        if ":" in entity.value:
            # Imports preserve the original spelling and can contain invalid addresses.
            # CASE keeps the cast away from invalid rows, regardless of predicate ordering.
            address = case((func.pg_input_is_valid(VmHost.ip, "inet"), cast(VmHost.ip, INET)))
            match = address == cast(entity.value, INET)
        else:
            match = VmHost.ip == entity.value
    elif entity.kind in ("host", "domain"):
        match = func.lower(VmHost.hostname) == entity.value.lower()
    else:
        return []
    return db.execute(
        select(VmHost.id, VmHost.hostname, VmHost.ip).where(match).order_by(VmHost.id).limit(MAX_MATCHES + 1)
    ).mappings().all()


def _vm(db: Session, entity: Entity) -> AdapterResult:
    hosts = _vm_hosts(db, entity)
    status, data, _ = _matches(hosts)
    if status == "ok":
        vulnerabilities = db.execute(
            select(VmHostCve.cve_id, VmHostCve.risk).where(VmHostCve.host_id == hosts[0]["id"])
            .order_by(VmHostCve.risk.desc(), VmHostCve.cve_id).limit(MAX_MATCHES + 1)
        ).mappings().all()
        data["vulnerabilities"] = [dict(row) for row in vulnerabilities[:MAX_MATCHES]]
        data["truncated"] = len(vulnerabilities) > MAX_MATCHES
    return status, data, None


def _attack(db: Session, entity: Entity) -> AdapterResult:
    hosts = _vm_hosts(db, entity)
    if len(hosts) != 1:
        # The ATT&CK scope does not include the VM host records themselves.
        return ("ambiguous" if hosts else "not_found"), {}, None
    rows = db.execute(
        select(VmRefAttack.technique_id, VmRefAttack.cve_id, VmRefAttack.mapping_type)
        .join(VmHostCve, VmHostCve.cve_id == VmRefAttack.cve_id)
        .where(VmHostCve.host_id == hosts[0]["id"])
        .order_by(VmRefAttack.technique_id, VmRefAttack.cve_id).limit(MAX_MATCHES + 1)
    ).mappings().all()
    if not rows:
        return "not_found", {}, None
    return "ok", {
        "matches": [dict(row) for row in rows[:MAX_MATCHES]],
        "truncated": len(rows) > MAX_MATCHES,
    }, None


ADAPTERS: dict[Source, tuple[ColumnElement[bool], Callable[[Session, Entity], AdapterResult]]] = {
    "assets": (select(Asset.id).where(Asset.merged_into.is_(None)).exists(), _assets),
    "accounts": (select(AssetUser.id).where(AssetUser.merged_into.is_(None)).exists(), _accounts),
    "av": (select(KscSnapshot.id).exists(), _av),
    "vm": (select(VmHost.id).exists(), _vm),
    "attack": (select(VmRefAttack.cve_id).exists() & select(VmHost.id).exists(), _attack),
}


def enrich(db: Session, payload: EnrichmentRequest, scopes: frozenset[str]) -> list[EnrichmentResult]:
    results = []
    available: dict[Source, bool] = {}
    for entity in payload.entities:
        for source in dict.fromkeys(payload.sources):
            result = EnrichmentResult(entity=entity, source=source, status="not_configured", fetched_at=utcnow())
            if source in scopes:
                exists, adapter = ADAPTERS[source]
                try:
                    if source not in available:
                        available[source] = bool(db.scalar(select(exists)))
                    if available[source]:
                        result.status, result.data, result.observed_at = adapter(db, entity)
                except SQLAlchemyError:
                    db.rollback()
                    result.status = "error"
                    result.error = "source query failed"
            results.append(result)
    return results
