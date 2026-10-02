"""Миграция вердиктов AD и KSC в статусы находок (спека §7): настоящий прогон
alembic на отдельной базе того же сервера — upgrade, сверка чисел, downgrade."""
from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.engine import make_url

from tests.conftest import BACKEND_DIR

BEFORE = "a4b5c6d7e8f9"
AFTER = "b5c6d7e8f9a0"


@pytest.fixture
def scratch(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Engine, Config]]:
    """Пустая база рядом с тестовой; alembic смотрит в неё через STOOLS_DATABASE_URL."""
    name = f"stools_mig_{uuid.uuid4().hex[:8]}"
    admin = create_engine(postgres_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    url = make_url(postgres_url).set(database=name).render_as_string(hide_password=False)
    monkeypatch.setenv("STOOLS_DATABASE_URL", url)
    engine = create_engine(url)
    try:
        yield engine, Config(str(BACKEND_DIR / "alembic.ini"))
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _count(engine: Engine, sql: str) -> int:
    with engine.connect() as conn:
        return int(conn.execute(text(sql)).scalar() or 0)


def test_verdicts_move_to_states_and_back(scratch: tuple[Engine, Config]) -> None:
    engine, cfg = scratch
    command.upgrade(cfg, BEFORE)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO ad_domain (id, sid, dns_root, netbios, dn, created_at) VALUES (1, 'S-1-5-21-1', 'corp.local', 'CORP', 'DC=corp,DC=local', now())"))
        conn.execute(text("INSERT INTO ksc_server (id, name, version, created_at) VALUES (2, 'ksc01', '15', now())"))
        conn.execute(text(
            "INSERT INTO ad_verdict (domain_id, key, status, reason, decided_by, decided_at) VALUES "
            "(1, 'ad-k1', 'accepted', 'сервисная учётка', 'analyst1', '2026-09-01T10:00:00Z'),"
            "(1, 'ad-k2', 'accepted', '', 'analyst2', '2026-09-02T10:00:00Z')"
        ))
        conn.execute(text(
            "INSERT INTO ksc_verdict (server_id, key, status, reason, decided_by, decided_at) VALUES "
            "(2, 'ksc-k1', 'accepted', 'стенд разработки', 'admin1', '2026-09-03T10:00:00Z')"
        ))

    command.upgrade(cfg, AFTER)
    tables = set(inspect(engine).get_table_names())
    assert {"ad_verdict_archive_20261002", "ksc_verdict_archive_20261002"} <= tables
    assert not {"ad_verdict", "ksc_verdict"} & tables
    assert _count(engine, "SELECT count(*) FROM platform_finding_state WHERE module = 'ad'") == 2
    assert _count(engine, "SELECT count(*) FROM platform_finding_state WHERE module = 'ksc'") == 1
    assert _count(engine, "SELECT count(*) FROM ad_verdict_archive_20261002") == 2
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT scope_id, status, reason, updated_by, present, updated_at FROM platform_finding_state WHERE key = 'ad-k1'"
        )).one()
        assert tuple(row[:5]) == (1, "risk_accepted", "сервисная учётка", "analyst1", True)
        assert row.updated_at.isoformat().startswith("2026-09-01T10:00")
        events = conn.execute(text(
            "SELECT s.key, e.kind, e.actor, e.to_status, e.comment FROM platform_finding_event e "
            "JOIN platform_finding_state s ON s.id = e.state_id ORDER BY s.key"
        )).all()
        assert [tuple(e) for e in events] == [
            ("ad-k1", "migrated", "analyst1", "risk_accepted", "сервисная учётка"),
            ("ad-k2", "migrated", "analyst2", "risk_accepted", ""),
            ("ksc-k1", "migrated", "admin1", "risk_accepted", "стенд разработки"),
        ]

    command.downgrade(cfg, BEFORE)
    tables = set(inspect(engine).get_table_names())
    assert {"ad_verdict", "ksc_verdict"} <= tables and not {"ad_verdict_archive_20261002", "ksc_verdict_archive_20261002"} & tables
    assert _count(engine, "SELECT count(*) FROM platform_finding_state") == 0
    assert _count(engine, "SELECT count(*) FROM platform_finding_event") == 0
    assert _count(engine, "SELECT count(*) FROM ad_verdict") == 2
    assert _count(engine, "SELECT count(*) FROM ksc_verdict") == 1
