# ruff: noqa: F811
"""Job counters retain their values when widened and never truncate on rollback."""
import pytest
from alembic import command
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import DataError
from sqlalchemy.orm import Session

from api.jobs import JobHandle
from api.modules.ad.models import AdJob
from api.modules.assets.models import AssetJob
from api.modules.attack.models import AttackJob
from api.modules.ksc.models import KscJob
from api.modules.siem.hunting.models import ThJob
from api.modules.siem.logons.models import SiemLogonJob
from api.modules.toolbox.models import ToolboxJob
from api.modules.vm.models import VmJob
from api.platform.sync_queue.models import SyncJob
from tests.api.test_access_migration import scratch  # noqa: F401

BEFORE = "4ea8db3261fa"
AFTER = "5fb9ec43720a"
MODELS = (AdJob, AssetJob, AttackJob, KscJob, SyncJob, SiemLogonJob, ThJob, ToolboxJob, VmJob)
INT_MAX = 2**31 - 1
EXPORT_BYTES = 2_976_578_498


def _rows(engine):
    with engine.connect() as conn:
        return {
            model.__tablename__: conn.execute(
                select(model.__table__).order_by(model.id).limit(10),
            ).mappings().all()
            for model in MODELS
        }


def _assert_types(engine, expected):
    for model in MODELS:
        columns = {column["name"]: column for column in inspect(engine).get_columns(model.__tablename__)}
        assert str(columns["processed"]["type"]) == expected
        assert str(columns["total"]["type"]) == expected
        assert not columns["processed"]["nullable"]
        assert columns["total"]["nullable"]
        assert str(columns["progress"]["type"]) == "INTEGER"


def test_job_progress_migration_preserves_history_and_large_values(scratch):
    engine, cfg = scratch
    command.upgrade(cfg, BEFORE)
    with Session(engine) as db:
        for model in MODELS:
            for job_id, total in ((1, INT_MAX), (2, None)):
                db.add(model(id=job_id, kind="import_file", stage="docker", status="done",
                             progress=100, processed=INT_MAX, total=total, message="keep history"))
        db.commit()
    before = _rows(engine)
    _assert_types(engine, "INTEGER")

    command.upgrade(cfg, AFTER)
    _assert_types(engine, "BIGINT")
    assert _rows(engine) == before
    with Session(engine) as db:
        for model in MODELS:
            job = db.get(model, 1)
            handle = JobHandle(db, job)
            handle.stage("parsing", total=EXPORT_BYTES)
            handle.tick(EXPORT_BYTES)
            db.refresh(job)
            assert (job.processed, job.total, job.progress) == (EXPORT_BYTES, EXPORT_BYTES, 100)
            job.processed = job.total = INT_MAX
        # ad_job is narrowed last, so a failure must also roll back earlier ALTERs.
        db.get(AdJob, 1).total = EXPORT_BYTES
        db.commit()
    large = _rows(engine)

    with pytest.raises(DataError, match="integer out of range"):
        command.downgrade(cfg, BEFORE)
    _assert_types(engine, "BIGINT")
    assert _rows(engine) == large
    with engine.connect() as conn:
        assert conn.execute(text("SELECT version_num FROM alembic_version LIMIT 1")).scalar_one() == AFTER

    with Session(engine) as db:
        db.get(AdJob, 1).total = INT_MAX
        db.commit()
    small = _rows(engine)
    command.downgrade(cfg, BEFORE)
    _assert_types(engine, "INTEGER")
    assert _rows(engine) == small
