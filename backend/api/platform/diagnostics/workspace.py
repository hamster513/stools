"""Materialize validated rows in a private SQLite database, never the live engine."""

import datetime as dt
import gzip
import json
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Date, DateTime, MetaData, create_engine, event
from sqlalchemy.orm import Session

from api.modules.ad.models import AdDomain, AdSnapshot
from api.modules.assets.models import (
    Asset,
    AssetGroup,
    AssetGroupGpo,
    AssetGroupMember,
    AssetObservation,
    AssetUser,
    AssetUserGroup,
    AssetUserHost,
    AssetUserObservation,
)
from api.modules.ksc.models import KscHost, KscPolicy, KscPolicyScope, KscServer, KscSnapshot
from api.modules.toolbox.services.lookup_types import configure_sqlite_lookup

ACCESS = {"assets": "read", "ad": "read", "ksc": "read"}
READ_MODELS = (
    Asset,
    AssetGroup,
    AssetGroupGpo,
    AssetGroupMember,
    AssetObservation,
    AssetUser,
    AssetUserGroup,
    AssetUserHost,
    AssetUserObservation,
    AdDomain,
    AdSnapshot,
    KscHost,
    KscPolicy,
    KscPolicyScope,
    KscServer,
    KscSnapshot,
)


def materialize(bundle: dict, directory: Path) -> None:
    from .exporter import TABLE_MODELS

    tables = {model.__table__ for model in (*TABLE_MODELS.values(), *READ_MODELS)}
    pending = list(tables)
    while pending:
        for foreign_key in pending.pop().foreign_keys:
            target = foreign_key.column.table
            if target not in tables:
                tables.add(target)
                pending.append(target)
    metadata = MetaData()
    for table in tables:
        copied = table.to_metadata(metadata)
        for index in copied.indexes:
            predicate = index.dialect_options["postgresql"].get("where")
            if predicate is not None:
                index.dialect_options["sqlite"]["where"] = predicate
    engine = create_engine("sqlite:///" + str(directory / "dataset.sqlite"))
    configure_sqlite_lookup(engine)
    try:
        # Schema comes only from application models; uploads cannot supply SQL/schema.
        metadata.create_all(engine)
        with engine.begin() as connection:
            for table in metadata.sorted_tables:
                if table.name not in bundle["tables"]:
                    continue
                for raw in bundle["tables"][table.name]:
                    row = dict(raw)
                    for column in table.columns:
                        value = row.get(column.name)
                        if isinstance(value, str) and isinstance(column.type, DateTime):
                            row[column.name] = dt.datetime.fromisoformat(value)
                        elif isinstance(value, str) and isinstance(column.type, Date):
                            row[column.name] = dt.date.fromisoformat(value)
                    connection.execute(table.insert().values(**row))
            # Enforce references after insertion, including self-referential rows.
            if connection.exec_driver_sql("PRAGMA foreign_key_check").first():
                raise ValueError("Некорректные связи диагностического пакета.")
        ad_dir = directory / "ad"
        ad_dir.mkdir(mode=0o700)
        for item in bundle["ad_exports"]:
            with gzip.open(
                ad_dir / f"{item['snapshot_id']}.json.gz", "wt", encoding="utf-8"
            ) as output:
                json.dump(item["export"], output, ensure_ascii=False)
    finally:
        engine.dispose()


@contextmanager
def open_dataset(directory: Path):
    database = directory / "dataset.sqlite"
    if not database.is_file() or database.is_symlink():
        raise FileNotFoundError
    engine = create_engine(
        database.resolve().as_uri().replace("file:", "sqlite:///file:", 1)
        + "?mode=ro&immutable=1&uri=true"
    )
    configure_sqlite_lookup(engine)

    @event.listens_for(engine, "connect")
    def readonly(connection, _):
        connection.execute("PRAGMA query_only = ON")

    try:
        with Session(engine, autoflush=False) as session:
            yield session
    finally:
        engine.dispose()


def without_live_links(value):
    """Keep scoped IDs, remove live URLs and mark omitted totals as unknown."""
    if isinstance(value, dict):
        result = {
            key: "" if key == "href" else without_live_links(item) for key, item in value.items()
        }
        if value.get("id") == "ad_policies":
            # The wire schema excludes GPO host rosters/totals. Model defaults must
            # not turn absent evidence into a claim that there are zero hosts.
            for row in result.get("items", []):
                for fact in row.get("facts", []):
                    if fact.get("label") == "Хостов":
                        fact["value"] = "Не включено в пакет"
        return result
    if isinstance(value, list):
        return [without_live_links(item) for item in value]
    return value
