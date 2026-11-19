"""The derived index is expendable; source writes and analyst decisions remain authoritative."""
import datetime as dt

import pytest
from sqlalchemy import text

from api.modules.assets.models import Asset, AssetObservation
from api.modules.assets.services.read_model import ready_generation, refresh, refresh_small
from api.platform.data_revision import bump_revision, read_revision

NOW = dt.datetime(2026, 11, 18, 12, tzinfo=dt.UTC)


def seed(db):
    a = Asset(name="Серверİ_100%", name_key="серверi̇_100%", ip="10.2.3.4")
    db.add(a)
    db.flush()
    db.add(AssetObservation(asset_id=a.id, source="ad", source_key="sid-1", name=a.name,
        ip=a.ip, seen_at=NOW, extra={"enabled": True, "last_logon": NOW.isoformat(), "laps": True}))
    db.commit()
    return a


def test_revision_is_transactional_and_raw_writes_invalidate(db_session):
    db = db_session
    a = seed(db)
    before = read_revision(db, "assets")
    assert before > 0
    assert bump_revision(db, "assets") > before
    db.rollback()
    assert read_revision(db, "assets") == before
    refresh(db, now=NOW)
    db.commit()
    assert ready_generation(db, NOW)
    db.execute(text("UPDATE asset SET name='changed' WHERE id=:id"), {"id": a.id})
    assert ready_generation(db, NOW) is None
    db.rollback()
    assert ready_generation(db, NOW)


def test_small_change_and_cancel_preserve_atomicity(db_session):
    db = db_session
    a = seed(db)
    refresh(db, now=NOW)
    db.commit()
    generation = ready_generation(db, NOW)
    a.name = "renamed"
    db.flush()
    assert refresh_small(db, now=NOW)
    assert ready_generation(db, NOW) == generation
    db.rollback()
    assert db.get(Asset, a.id).name != "renamed"
    def cancelled():
        raise RuntimeError("cancelled")
    with pytest.raises(RuntimeError, match="cancelled"):
        refresh(db, now=NOW, check=cancelled)
    db.rollback()
    assert ready_generation(db, NOW) == generation


def test_expiry_is_exact_for_inactive_boundary(db_session):
    db = db_session
    seed(db)
    refresh(db, now=NOW)
    db.commit()
    assert ready_generation(db, NOW)
    assert ready_generation(db, NOW + dt.timedelta(days=31)) is None


def test_time_transition_and_settings_invalidate(db_session, monkeypatch):
    from sqlalchemy import select

    from api.modules.assets.models import AssetSettings
    db = db_session
    a = seed(db)
    obs = db.scalar(select(AssetObservation).where(AssetObservation.asset_id == a.id).limit(1))
    obs.extra = {"enabled": True, "last_logon": (NOW - dt.timedelta(days=30)).isoformat()}
    db.commit()
    refresh(db, now=NOW)
    db.commit()
    assert ready_generation(db, NOW)
    after = NOW + dt.timedelta(microseconds=1)
    assert ready_generation(db, after) is None
    refresh(db, now=after)
    db.commit()
    assert ready_generation(db, after)
    db.add(AssetSettings(data={"inactive_days": 60}))
    db.flush()
    assert ready_generation(db, after) is None
    db.rollback()
    assert ready_generation(db, after)


def test_build_rejects_a_concurrent_source_change(db_session):
    from sqlalchemy.orm import Session

    from api.modules.assets.services.read_model import SourceChanged
    db = db_session
    a = seed(db)
    refresh(db, now=NOW)
    db.commit()
    checks = 0
    def change_after_batch():
        nonlocal checks
        checks += 1
        if checks == 2:
            with Session(db.get_bind()) as writer:
                writer.execute(text("UPDATE asset SET note='new' WHERE id=:id"), {"id": a.id})
                writer.commit()
    with pytest.raises(SourceChanged):
        refresh(db, now=NOW, check=change_after_batch)
    db.rollback()
    assert ready_generation(db, NOW) is None
    refresh(db, now=NOW)
    db.commit()
    assert ready_generation(db, NOW)


def test_first_publication_cannot_erase_concurrent_dirty_id(db_session):
    import threading

    from sqlalchemy import delete, event, select
    from sqlalchemy.orm import Session

    from api.modules.assets.models import AssetReadDirty
    from api.platform.data_revision import DataRevision
    db = db_session
    a = seed(db)
    id_ = a.id
    db.execute(delete(DataRevision))  # Existing business data at the first migration.
    db.commit()
    done, started = threading.Event(), threading.Event()
    errors = []
    def writer():
        try:
            with Session(db.get_bind()) as side:
                side.execute(text("UPDATE asset SET name='concurrent' WHERE id=:id"), {"id": id_})
                side.commit()
        except Exception as exc:  # noqa: BLE001 — propagate the writer thread failure to the assertion
            errors.append(exc)
        finally:
            done.set()
    thread = threading.Thread(target=writer)
    def at_publication(conn, cursor, statement, parameters, context, many):
        if "platform_data_revision" in statement and "FOR UPDATE" in statement and not started.is_set():
            started.set()
            thread.start()
            done.wait(.2)  # Old path has no row lock; the correct path blocks the writer until commit.
    event.listen(db.get_bind(), "after_cursor_execute", at_publication)
    try:
        refresh(db, now=NOW)
        db.commit()
    finally:
        event.remove(db.get_bind(), "after_cursor_execute", at_publication)
        db.rollback()
        if started.is_set():
            thread.join(timeout=10)
    assert done.is_set() and not errors
    assert id_ in set(db.scalars(select(AssetReadDirty.asset_id)))
    assert ready_generation(db, NOW) is None


def test_bulk_revision_once_per_transaction_but_every_write_invalidates(db_session):
    from sqlalchemy import insert
    db = db_session
    a = seed(db)
    before = read_revision(db, "assets")
    db.execute(insert(Asset), [{"name": f"bulk-{i}"} for i in range(50)])
    assert read_revision(db, "assets") == before + 1
    db.commit()
    refresh(db, now=NOW)
    db.commit()
    db.execute(text("UPDATE asset SET name='first' WHERE id=:id"), {"id": a.id})
    assert refresh_small(db, now=NOW)
    assert ready_generation(db, NOW)
    revision = read_revision(db, "assets")
    db.execute(text("UPDATE asset SET name='second' WHERE id=:id"), {"id": a.id})
    assert read_revision(db, "assets") == revision
    assert ready_generation(db, NOW) is None
    db.rollback()
