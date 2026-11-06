"""Atomic Docker snapshot; a failed or limited export leaves previous data intact."""
from __future__ import annotations

import datetime as dt
import logging
import tempfile
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.vm.core.docker_inventory import (
    DockerFormatError,
    build_docker_pdql,
    parse_inventory,
)
from api.modules.vm.core.mpvm import MpVmClient
from api.modules.vm.docker_models import VmDockerImage, VmDockerSnapshot
from api.modules.vm.services.settings import Connection

log = logging.getLogger(__name__)


def collect_inventory(db: Session, client: MpVmClient, conn: Connection, data_dir: Path) -> bool:
    now = dt.datetime.now(dt.UTC)
    try:
        if conn.limit:
            raise DockerFormatError("Снимок Docker не обновлён: снимите лимит строк в подключении MaxPatrol VM")
        folder = data_dir / "vm"
        folder.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="docker-", dir=folder) as directory:
            images, containers = (Path(directory) / name for name in ("images.csv", "containers.csv"))
            client.export_csv(build_docker_pdql("images"), images)
            client.export_csv(build_docker_pdql("containers"), containers)
            records = parse_inventory(images, containers)
        previous = {r.image_key: r for r in db.scalars(select(VmDockerImage))}
        keep = set()
        for record in records:
            key = record["key"]
            keep.add(key)
            row = previous.get(key)
            if row is None:
                row = VmDockerImage(image_key=key)
                db.add(row)
            refs = record["references"]
            row.image_id = record["image_id"]
            row.title = ", ".join(dict.fromkeys("/".join(filter(None, (r['registry'], r['repo']))) for r in refs)) or "Образ не определён"
            row.tags = sorted({r["tag"] for r in refs if r["tag"]})
            row.platform = ", ".join(sorted(record["platforms"]))
            row.status = record["status"]
            row.host_count = len(record["hosts"])
            row.container_count = sum(len(h["containers"]) for h in record["hosts"])
            row.details = record
            row.search_text = " ".join([
                row.title, row.image_id, row.platform, *row.tags,
                *(h["hostname"] + " " + h["ip"] for h in record["hosts"]),
                *(c["name"] + " " + c["id"] for h in record["hosts"] for c in h["containers"]),
            ])
            row.collected_at = now
        for key, old in previous.items():
            if key not in keep:
                db.delete(old)
        snapshot = db.get(VmDockerSnapshot, 1)
        if snapshot is None:
            snapshot = VmDockerSnapshot(id=1)
            db.add(snapshot)
        snapshot.source_address = conn.host
        snapshot.attempted_at = snapshot.collected_at = now
        snapshot.error = ""
        db.commit()
        return True
    except Exception as exc:  # noqa: BLE001 — isolate optional inventory; report failure and retain last snapshot
        db.rollback()
        snapshot = db.get(VmDockerSnapshot, 1)
        if snapshot is None:
            snapshot = VmDockerSnapshot(id=1, source_address="")
            db.add(snapshot)
        snapshot.attempted_at = now
        # Never include raw vendor responses or connection credentials.
        snapshot.error = str(exc) if isinstance(exc, DockerFormatError) else f"Сбор Docker не выполнен: {type(exc).__name__}"
        db.commit()
        log.warning("%s", snapshot.error)
        return False
