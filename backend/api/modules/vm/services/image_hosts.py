"""Join verified Harbor hashes to MP VM running containers, without name/tag guesses."""
from __future__ import annotations

from typing import Any

from sqlalchemy import and_, cast, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session
from sqlalchemy.sql import ColumnElement

from api.modules.assets.models import AssetObservation
from api.modules.vm.docker_models import VmDockerImage, VmDockerSnapshot
from api.modules.vm.models import VmImage


def running_condition() -> ColumnElement[bool]:
    """Confirmed running matches, before pagination and without multiplying image rows.

    Inventory status is derived from the same host/container records used below.
    A failed latest poll keeps the previous completed snapshot, as host_views does.
    """
    snapshot_ready = select(VmDockerSnapshot.id).where(
        VmDockerSnapshot.id == 1, VmDockerSnapshot.collected_at.is_not(None),
    ).exists()
    matched = select(VmDockerImage.id).where(
        VmDockerImage.status == "running",
        VmDockerImage.image_id != "",
        cast(VmImage.runtime_ids, JSONB).has_key(VmDockerImage.image_id),
    ).correlate(VmImage).exists()
    return and_(snapshot_ready, matched, VmImage.artifact_kind.not_in(["helm", "other"]))


def host_views(db: Session, images: list[VmImage]) -> dict[int, dict[str, Any]]:
    snapshot = db.get(VmDockerSnapshot, 1)
    ids = {ref for image in images for ref in image.runtime_ids}
    observations = list(db.scalars(select(VmDockerImage).where(VmDockerImage.image_id.in_(ids)))) if ids and snapshot and snapshot.collected_at else []
    host_keys = {f"{h['hostname']}|{h['ip']}" for row in observations for h in row.details["hosts"]}
    asset_ids = dict(db.execute(select(AssetObservation.source_key, AssetObservation.asset_id).where(
        AssetObservation.source == "vm", AssetObservation.source_key.in_(host_keys), AssetObservation.gone_at.is_(None),
    )).tuples().all()) if host_keys else {}
    by_digest = {row.image_id: row for row in observations}
    result = {}
    for image in images:
        state = "mapping_missing" if not image.runtime_ids else "snapshot_missing" if not snapshot or not snapshot.collected_at else "ready"
        if image.artifact_kind in {"helm", "other"}:
            state = "not_applicable"
        hosts: dict[str, dict[str, Any]] = {}
        if state == "ready":
            for ref in image.runtime_ids:
                observation = by_digest.get(ref)
                if observation is None:
                    continue
                for host in observation.details["hosts"]:
                    containers = [c for c in host["containers"] if c["status"] == "running"]
                    if not containers:
                        continue
                    source_key = f"{host['hostname']}|{host['ip']}"
                    asset_id = asset_ids.get(source_key)
                    key = f"asset:{asset_id}" if asset_id is not None else f"vm:{source_key}"
                    target = hosts.setdefault(key, {
                        "hostname": host["hostname"], "ip": host["ip"], "asset_id": asset_id,
                        "host_updated_at": host["host_updated_at"], "containers": {},
                    })
                    for container in containers:
                        target["containers"].setdefault(container["id"], container)
        items = []
        for host in hosts.values():
            host["containers"] = list(host["containers"].values())
            items.append(host)
        items.sort(key=lambda h: (h["hostname"].lower(), h["ip"]))
        result[image.id] = {
            "state": state, "count": len(items) if state == "ready" else None, "items": items,
            "collected_at": snapshot.collected_at if snapshot else None,
            "warning": snapshot.error if snapshot else "", "mapping_error": image.runtime_error,
        }
    return result


def summaries(db: Session, images: list[VmImage]) -> dict[int, dict[str, Any]]:
    return {key: {"running_host_count": value["count"], "runtime_state": value["state"]}
            for key, value in host_views(db, images).items()}
