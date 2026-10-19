"""Таблицы Threat Hunting: миграция совпадает с моделями, каскады и «мягкие» связи работают."""
from __future__ import annotations

import datetime as dt

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import select

from api.db.models import Base
from api.modules.siem.hunting.models import (
    ThDeepHunt,
    ThEvent,
    ThFinding,
    ThHunt,
    ThQuery,
    ThRun,
    ThRunQuery,
)

NOW = dt.datetime(2026, 10, 19, tzinfo=dt.UTC)


def test_migration_matches_models(db_session):
    """Автосравнение схемы базы (из миграций) с моделями: расхождение по th_* — ошибка одной из сторон."""
    ctx = MigrationContext.configure(
        db_session.connection(),
        opts={"compare_type": True, "compare_server_default": False},
    )
    diff = [
        d for d in compare_metadata(ctx, Base.metadata)
        if "th_" in repr(d)
    ]
    assert diff == []


def test_cascades(db_session):
    hunt = ThHunt(code="H1", name="x")
    db_session.add(hunt)
    db_session.flush()
    db_session.add(ThQuery(hunt_id=hunt.id, query_id="Q1", query="select 1"))
    run = ThRun(target_date=NOW.date(), period_from=NOW, period_to=NOW)
    deep = ThDeepHunt(title="t", hunt_id=hunt.id, query="q", period_from=NOW, period_to=NOW)
    db_session.add_all([run, deep])
    db_session.flush()
    db_session.add(ThRunQuery(run_id=run.id, query_pk=1, hunt_code="H1", query_id="Q1", status="ok"))
    nightly = ThFinding(kind="nightly", hunt_id=hunt.id, hunt_code="H1", query_id="Q1", run_id=run.id,
                        period_from=NOW, period_to=NOW)
    big = ThFinding(kind="deep", hunt_id=hunt.id, hunt_code="H1", query_id="Q1", deep_id=deep.id,
                    period_from=NOW, period_to=NOW)
    db_session.add_all([nightly, big])
    db_session.flush()
    db_session.add_all([ThEvent(finding_id=nightly.id, position=0, data_json="{}"),
                        ThEvent(finding_id=big.id, position=0, data_json="{}")])
    db_session.commit()
    nightly_id, big_id = nightly.id, big.id

    # Большой хант уносит свои находки и события; удаление ханта лишь отвязывает находку и сам большой хант.
    db_session.delete(deep)
    db_session.commit()
    db_session.expire_all()
    assert db_session.get(ThFinding, big_id) is None
    db_session.delete(hunt)
    db_session.commit()
    db_session.expire_all()
    kept = db_session.get(ThFinding, nightly_id)
    assert kept is not None and kept.hunt_id is None and kept.hunt_code == "H1"
    assert db_session.execute(select(ThQuery)).scalars().all() == []
    assert len(db_session.execute(select(ThEvent)).scalars().all()) == 1

    # Вытеснение прогона не убирает находку, удаление — убирает его запросы.
    db_session.delete(run)
    db_session.commit()
    db_session.expire_all()
    assert db_session.get(ThFinding, nightly_id).run_id is None
    assert db_session.execute(select(ThRunQuery)).scalars().all() == []
