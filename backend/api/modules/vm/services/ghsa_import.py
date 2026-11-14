"""Atomic full GHSA snapshot replacement, isolated from job progress commits."""
from __future__ import annotations

import datetime as dt
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from sqlalchemy import delete, insert, text
from sqlalchemy.orm import Session

from api.modules.vm.core.ghsa import iter_advisories
from api.modules.vm.ghsa_models import VmRefGhsa, VmRefGhsaAlias, VmRefGhsaPackage
from api.modules.vm.models import VmRefState
from api.modules.vm.services.jobs import JobHandle

BATCH_SIZE = 1000
MAX_BATCH_BYTES = 8 * 1024 * 1024


def load_ghsa(db: Session, path: Path, handle: JobHandle, source: str, detail: str = "") -> int:
    """A bad/empty/cancelled archive rolls back rows, child tables and state.

    JobHandle.tick commits its own session. Never share that transaction with
    the replacement; readers keep seeing the old snapshot until this commits.
    """
    count = 0
    pending_bytes = 0
    parents: list[dict[str, Any]] = []
    aliases: list[dict[str, Any]] = []
    packages: list[dict[str, Any]] = []
    with Session(db.get_bind()) as catalog, catalog.begin():
        catalog.execute(delete(VmRefGhsaPackage))
        catalog.execute(delete(VmRefGhsaAlias))
        catalog.execute(delete(VmRefGhsa))

        def flush() -> None:
            if parents:
                catalog.execute(insert(VmRefGhsa), parents)
            if aliases:
                catalog.execute(insert(VmRefGhsaAlias), aliases)
            if packages:
                catalog.execute(insert(VmRefGhsaPackage), packages)
            parents.clear()
            aliases.clear()
            packages.clear()
            handle.tick(count, message=f"GHSA: {count} advisories")

        for record in iter_advisories(path):
            row = asdict(record)
            # Limit memory as well as row count: a single valid OSV record can
            # contain megabytes of package ranges or description text.
            pending_bytes += len(json.dumps(row, default=str))
            aliases.extend({"ghsa_id": record.ghsa_id, "alias": alias} for alias in row.pop("aliases"))
            packages.extend({"ghsa_id": record.ghsa_id, **package} for package in row.pop("packages"))
            parents.append(row)
            count += 1
            if len(parents) >= BATCH_SIZE or pending_bytes >= MAX_BATCH_BYTES:
                flush()
                pending_bytes = 0
        flush()  # Final cancellation check must precede the atomic commit.
        state = catalog.get(VmRefState, "ghsa")
        if state is None:
            state = VmRefState(name="ghsa")
            catalog.add(state)
        state.loaded_at = dt.datetime.now(dt.UTC)
        state.source, state.records, state.detail = source, count, detail
        from api.modules.vm.services.ref_updates import record_full_checkpoint
        record_full_checkpoint(catalog, "ghsa", path)
    # Full replacement invalidates cardinality estimates. Refresh them after
    # publication, before alias-aware scoring/search plans are constructed.
    with Session(db.get_bind()) as statistics, statistics.begin():
        statistics.execute(text("ANALYZE vm_ref_ghsa, vm_ref_ghsa_alias, vm_ref_ghsa_package"))
    db.expire_all()
    return count
