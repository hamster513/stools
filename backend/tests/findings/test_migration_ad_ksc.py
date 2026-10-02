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
        # Снапшотов у домена нет — ключа нет и в последнем снапшоте.
        assert tuple(row[:5]) == (1, "risk_accepted", "сервисная учётка", "analyst1", False)
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


def test_present_title_severity_follow_snapshots(scratch: tuple[Engine, Config]) -> None:
    """`present` — ключ в последнем снапшоте области; подпись и severity — из самого
    позднего снапшота, где ключ был; вердикт без находки ни в одном снапшоте — пустые."""
    engine, cfg = scratch
    command.upgrade(cfg, BEFORE)
    snap_cols = "collected_at, imported_at, source, collector, filename, sha256, findings, stats_json, analyzer_version"
    snap_vals = "now(), 'file', '', '', '', 0, '{}', '1'"
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO ad_domain (id, sid, dns_root, netbios, dn, created_at) VALUES (1, 'S-1-5-21-1', 'corp.local', 'CORP', 'DC=corp,DC=local', now())"))
        conn.execute(text(f"INSERT INTO ad_snapshot (id, domain_id, objects, {snap_cols}) VALUES "
                          f"(10, 1, 0, '2026-09-01T00:00:00Z', {snap_vals}), (11, 1, 0, '2026-09-08T00:00:00Z', {snap_vals})"))
        ad_cols = '(snapshot_id, key, "check", severity, severity_original, identity, identity_sid, target, "right", allowlisted, details_json)'
        conn.execute(text(
            f"INSERT INTO ad_finding {ad_cols} VALUES "
            "(10, 'ad-old', 'Kerberoast', 'Medium', 'Medium', 'CORP\\old_name', '', '', '', false, '{}'),"
            "(10, 'ad-live', 'Kerberoast', 'Low', 'Low', 'CORP\\svc_was', '', '', '', false, '{}'),"
            "(11, 'ad-live', 'Kerberoast', 'High', 'High', 'CORP\\svc_now', '', '', '', false, '{}')"
        ))
        conn.execute(text(
            "INSERT INTO ad_verdict (domain_id, key, status, reason, decided_by, decided_at) VALUES "
            "(1, 'ad-live', 'accepted', 'норма', 'analyst1', now()), (1, 'ad-old', 'accepted', 'норма', 'analyst1', now()),"
            "(1, 'ad-orphan', 'accepted', 'норма', 'analyst1', now())"
        ))
        conn.execute(text("INSERT INTO ksc_server (id, name, version, created_at) VALUES (2, 'ksc01', '15', now())"))
        conn.execute(text(f"INSERT INTO ksc_snapshot (id, server_id, hosts, {snap_cols}) VALUES (20, 2, 0, '2026-09-01T00:00:00Z', {snap_vals})"))
        conn.execute(text(
            'INSERT INTO ksc_finding (snapshot_id, key, "check", severity, severity_original, host, host_key, target, allowlisted, details_json) '
            "VALUES (20, 'ksc-live', 'RTP_OFF', 'Critical', 'Critical', 'WS02', 'ws02.corp.local', '', false, '{}')"
        ))
        conn.execute(text("INSERT INTO ksc_verdict (server_id, key, status, reason, decided_by, decided_at) VALUES (2, 'ksc-live', 'accepted', 'стенд', 'admin1', now())"))

    command.upgrade(cfg, AFTER)
    with engine.connect() as conn:
        rows = {r.key: (r.present, r.title, r.severity) for r in conn.execute(text(
            "SELECT key, present, title, severity FROM platform_finding_state"))}
    assert rows == {
        "ad-live": (True, "Kerberoast: CORP\\svc_now", "High"),
        "ad-old": (False, "Kerberoast: CORP\\old_name", "Medium"),
        "ad-orphan": (False, "", ""),
        "ksc-live": (True, "RTP_OFF: WS02", "Critical"),
    }
    command.downgrade(cfg, BEFORE)
    assert _count(engine, "SELECT count(*) FROM platform_finding_state") == 0
    assert _count(engine, "SELECT count(*) FROM ad_verdict") == 3


def test_existing_row_is_kept_and_authorless_verdict_is_system(scratch: tuple[Engine, Config]) -> None:
    """Строка состояния, которая уже есть, не роняет перенос и не получает события `migrated`;
    у вердикта без автора и строка, и событие — от `system`."""
    engine, cfg = scratch
    command.upgrade(cfg, BEFORE)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO ad_domain (id, sid, dns_root, netbios, dn, created_at) VALUES (1, 'S-1-5-21-1', 'corp.local', 'CORP', 'DC=corp,DC=local', now())"))
        conn.execute(text(
            "INSERT INTO ad_verdict (domain_id, key, status, reason, decided_by, decided_at) VALUES "
            "(1, 'ad-k1', 'accepted', 'норма', 'analyst1', now()), (1, 'ad-k2', 'accepted', 'норма', '', now())"
        ))
        conn.execute(text(
            "INSERT INTO platform_finding_state (module, scope_id, key, status, reason, present, title, severity, updated_by, updated_at) "
            "VALUES ('ad', 1, 'ad-k1', 'in_work', '', true, 'уже есть', '', 'tester', now())"))

    command.upgrade(cfg, AFTER)
    with engine.connect() as conn:
        rows = {r.key: (r.status, r.title, r.updated_by) for r in conn.execute(text(
            "SELECT key, status, title, updated_by FROM platform_finding_state"))}
        events = [tuple(e) for e in conn.execute(text(
            "SELECT s.key, e.actor FROM platform_finding_event e JOIN platform_finding_state s ON s.id = e.state_id"))]
    assert rows == {"ad-k1": ("in_work", "уже есть", "tester"), "ad-k2": ("risk_accepted", "", "system")}
    assert events == [("ad-k2", "system")]
