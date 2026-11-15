"""Keep imported diagnostic evidence outside ordinary Assets reconciliation.

The filter belongs to one sync Session, including its commits. Ordinary module
readers and other Sessions still see the imported rows. The caller must hold the
Assets sync lock so an additive import cannot appear halfway through this view.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from functools import wraps

from sqlalchemy import Integer, all_, bindparam, event, select
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import with_loader_criteria

from .models import DiagnosticImport
from .schema import TABLE_MODELS

PROTECTED = {name: model for name, model in TABLE_MODELS.items()
             if name.startswith("asset") or name in {"ad_domain", "ksc_server"}}
_ACTIVE = "diagnostic_sync_guard"


def _owned_ids(db):
    ids = {name: set() for name in PROTECTED}
    after = ""
    while True:
        page = list(db.execute(select(DiagnosticImport.id, DiagnosticImport.records_json)
                    .where(DiagnosticImport.id > after).order_by(DiagnosticImport.id).limit(200)).tuples())
        if not page:
            break
        for package_id, raw in page:
            manifest = json.loads(raw)
            for name, rows in manifest["tables"].items():
                if name in ids:
                    ids[name].update(row["id"] for row in rows)
            after = package_id
    return {name: sorted(values) for name, values in ids.items() if values}


@contextmanager
def diagnostic_sync_guard(db):
    if db.info.get(_ACTIVE):
        yield
        return
    owned = _owned_ids(db)
    if not owned:
        yield
        return
    predicates = {}
    for name, ids in owned.items():
        model = PROTECTED[name]
        # One PostgreSQL array parameter avoids its bind-parameter limit when
        # several imported slices contain many membership rows.
        predicates[name] = (model.id != all_(bindparam(f"diagnostic_{name}", ids, type_=ARRAY(Integer)))) if db.get_bind().dialect.name == "postgresql" else model.id.not_in(ids)
    options = [with_loader_criteria(PROTECTED[name], predicate, include_aliases=True)
               for name, predicate in predicates.items()]

    def exclude(execution):
        if not (execution.is_select or execution.is_update or execution.is_delete):
            return
        statement = execution.statement.options(*options)
        if execution.is_update or execution.is_delete:
            table = statement.table
            predicate = predicates.get(table.name)
            if predicate is not None:
                # Explicit WHERE also covers Core updates/deletes; loader
                # criteria alone only affect mapped ORM statements.
                statement = statement.where(predicate)
            # Bulk update-by-PK cannot synchronize extra WHERE criteria. Sync
            # stages commit/expire before reading their affected rows again.
            statement = statement.execution_options(synchronize_session=False)
        execution.statement = statement

    db.info[_ACTIVE] = True
    event.listen(db, "do_orm_execute", exclude)
    try:
        yield
    finally:
        event.remove(db, "do_orm_execute", exclude)
        db.info.pop(_ACTIVE, None)


def exclude_diagnostic_imports(function):
    @wraps(function)
    def guarded(db, *args, **kwargs):
        with diagnostic_sync_guard(db):
            return function(db, *args, **kwargs)

    return guarded
