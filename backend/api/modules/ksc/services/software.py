"""Persist immutable KSC inventory, including collection completeness."""
from __future__ import annotations

import datetime as dt
import json

from sqlalchemy import delete
from sqlalchemy.orm import Session

from api.modules.ksc.core.software import normalize_inventory
from api.modules.ksc.software_models import KscSoftware, KscSoftwareInventory
from api.modules.vm.core.software_match import product_key
from api.modules.vm.services.software import inventory_lock, rebuild_ksc


def store_inventory(db: Session, snapshot, idx) -> None:
    inventory_lock(db)
    db.execute(delete(KscSoftwareInventory).where(KscSoftwareInventory.snapshot_id == snapshot.id))
    for host in idx.hosts:
        entry = idx.export.host_inventory.get(host.host_id)
        status, rows = normalize_inventory(entry)
        inv = KscSoftwareInventory(snapshot_id=snapshot.id, host_id=host.host_id, host_name=host.name,
            os=host.os, status=status, error=str(entry.get("error") or "Не удалось получить полный список ПО")[:2000]
            if status == "error" and isinstance(entry, dict) else None)
        db.add(inv); db.flush()
        seen = set()
        for row in rows:
            identity = (row["product_id"], row["name"], row["version"], row["publisher"], row["install_dir"])
            if identity in seen:
                continue
            seen.add(identity)
            vendor, product = product_key(row["publisher"], row["name"], row["version"])
            db.add(KscSoftware(inventory_id=inv.id, product_id=row["product_id"], name=row["name"],
                version=row["version"], publisher=row["publisher"], vendor_key=vendor, product_key=product,
                installed_on=dt.date.fromisoformat(row["installed_on"]) if row["installed_on"] else None,
                install_dir=row["install_dir"], raw_json=json.dumps(row["raw"], ensure_ascii=False, default=str)))
    db.flush()
    rebuild_ksc(db, snapshot_id=snapshot.id)
