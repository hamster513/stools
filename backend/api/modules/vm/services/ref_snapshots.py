"""Merge native source files from an update ZIP into the existing catalogue."""
from pathlib import Path

from sqlalchemy import MetaData, Table, delete, select, text, tuple_
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from api.modules.vm.services import refs
from api.modules.vm.services.jobs import JobHandle


def _stage(db: Session, table: Table) -> Table:
    # Names come from the mapped tables. Each update owns its temp tables until commit.
    staged = table.to_metadata(MetaData(), name=f"incoming_{table.name}")
    db.execute(text(f'CREATE TEMP TABLE "{staged.name}" (LIKE "{table.name}") ON COMMIT DROP'))
    return staged


def _merge(db: Session, table: Table, staged: Table) -> int:
    columns = list(table.c.keys())
    stmt = insert(table).from_select(columns, select(*(staged.c[name] for name in columns)))
    keys = list(table.primary_key.columns.keys())
    values = {name: stmt.excluded[name] for name in columns if name not in keys}
    if values:
        changed = tuple_(*(table.c[name] for name in values)).is_distinct_from(tuple_(*values.values()))
        stmt = stmt.on_conflict_do_update(index_elements=keys, set_=values, where=changed)
    else:
        stmt = stmt.on_conflict_do_nothing(index_elements=keys)
    return db.connection().execute(stmt, execution_options={"preserve_rowcount": True}).rowcount


def merge_snapshot(db: Session, handle: JobHandle, name: str, files: list[Path], table: Table) -> dict[str, int]:
    staged = _stage(db, table)
    link_changes = 0
    if name in {"exploitdb", "msf"}:
        links, load = ((refs.EXDB_CVE_T, refs._load_exploitdb) if name == "exploitdb"
                       else (refs.MSF_CVE_T, refs._load_msf))
        staged_links = _stage(db, links)
        received = load(db, files[0], handle, staged, staged_links)
        # A supplied record contains its full CVE list. Other records keep their links.
        parent_key = next(iter(table.primary_key.columns)).name
        supplied_parent = links.c[parent_key].in_(select(staged.c[parent_key]))
        supplied_pair = select(1).select_from(staged_links).where(*(
            staged_links.c[key.name] == links.c[key.name] for key in links.primary_key.columns
        )).exists()
        removed = db.connection().execute(delete(links).where(supplied_parent, ~supplied_pair)).rowcount
        link_changes = removed + _merge(db, links, staged_links)
    elif name == "attack":
        # The KEV JSON takes precedence over the historical CSV for the same pair.
        ordered = sorted(files, key=lambda f: f.suffix.lower() != ".json")
        received = sum(refs._load_attack(db, f, handle, replace=i == 0, table=staged)
                       for i, f in enumerate(ordered))
    else:
        received = {"epss": refs._load_epss, "kev": refs._load_kev}[name](db, files[0], handle, staged)
    if not received:
        if name == "attack":
            raise ValueError("ATT&CK: в снимке нет поддерживаемых связей; исходные данные сохранены")
        raise ValueError(f"{name}: в снимке нет записей; исходные данные сохранены")
    return {"received": received, "upserted": _merge(db, table, staged), "deleted": 0,
            "links_changed": link_changes}
