# ruff: noqa: F811
"""Аддитивная миграция метаданных запросов не меняет существующие условия."""
from alembic import command
from sqlalchemy import inspect, text

from tests.api.test_access_migration import scratch  # noqa: F401


def test_query_metadata_migration(scratch):
    engine, cfg = scratch
    command.upgrade(cfg, "c83f0e4a921d")
    with engine.begin() as conn:
        conn.execute(text("""INSERT INTO th_hunt
            (id,code,name,description,enabled,position,created_at,updated_at,updated_by)
            VALUES (1,'OLD','Old hunt','',true,0,now(),now(),'test')"""))
        conn.execute(text("""INSERT INTO th_query
            (hunt_id,query_id,position,query,fields_json,labels_json,enabled)
            VALUES (1,'Q1',0,'normalized = true','["time"]','["Time"]',true)"""))
    command.upgrade(cfg, "d74f2a8c1e90")
    with engine.connect() as conn:
        row = conn.execute(text("SELECT name, description, is_full_pdql, query FROM th_query LIMIT 1")).one()
        assert tuple(row) == ("Q1", "", False, "normalized = true")
    assert "is_full_pdql" in {column["name"] for column in inspect(engine).get_columns("th_deep_hunt")}
