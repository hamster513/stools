"""Миграция вердиктов SIEM в статусы находок (спека §7): настоящий прогон
alembic на отдельной базе того же сервера — upgrade, сверка чисел, downgrade."""
from __future__ import annotations

import json
import uuid
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.engine import make_url

from api.modules.siem.findings_adapter import SALT_SETTING, finding_key
from tests.conftest import BACKEND_DIR

BEFORE = "b5c6d7e8f9a0"
AFTER = "c6d7e8f9a0b1"
STAMPS = "d7e8f9a0b1c2"
UA = "000ffb49-bb9e-4ee4-9262-6754b7ee28d2"
UB = "111ffb49-bb9e-4ee4-9262-6754b7ee28d3"
H1, H2, H3 = "a1" * 32, "b2" * 32, "c3" * 32


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


_SNAPSHOT = (
    "INSERT INTO snapshot (id, created_at, sha256, filename, archive_path, parsed_cache_path, source_type, rule_count,"
    " group_count, rules_without_code, unsupported_count, edge_count, scoped_count, finding_count, findings_by_kind_json,"
    " findings_by_polarity_json, findings_by_object_type_json, objects_with_findings, in_table_count, divergence_count,"
    " clone_count, rules_without_msgid, table_ranking_json, authors_json, unresolved_json) VALUES"
    " (:id, :at, :sha, 'kb.zip', '/x', '/x', 'upload', 0, 0, 0, 0, 0, 0, 0, '{}', '{}', '{}', 0, 0, 0, 0, 0, '[]', '{}', '{}')"
)
_FINDING = (
    "INSERT INTO finding (snapshot_id, object_type, object_uuid, object_name, kind, severity, field, value, value_hash,"
    " polarity, in_table) VALUES (:snap, 'correlation', :uuid, :name, :kind, :sev, :field, 'x', :hash, 'assertion', false)"
)


def test_verdicts_move_to_states_and_back(scratch: tuple[Engine, Config]) -> None:
    engine, cfg = scratch
    command.upgrade(cfg, BEFORE)
    with engine.begin() as conn:
        # Снапшоты 1 и 2 — разобраны, активный — 2; снапшот 3 — загрузка ещё идёт.
        # Находка UB была только в снапшоте 1: подпись её строки — оттуда.
        conn.execute(text(_SNAPSHOT), {"id": 1, "at": "2026-08-01T10:00:00Z", "sha": "0" * 64})
        conn.execute(text(_SNAPSHOT), {"id": 2, "at": "2026-09-01T10:00:00Z", "sha": "1" * 64})
        conn.execute(text(_SNAPSHOT), {"id": 3, "at": "2026-09-05T10:00:00Z", "sha": "2" * 64})
        conn.execute(text("INSERT INTO job (snapshot_id, stage, status, progress, started_at) VALUES "
                          "(1, 'done', 'done', 100, now()), (2, 'done', 'done', 100, now()), "
                          "(3, 'parsing', 'running', 20, now())"))
        conn.execute(text(_FINDING), {"snap": 2, "uuid": UA, "name": "DEMO_Rule_A", "kind": 1, "sev": "high",
                                      "field": "subject.account.name", "hash": H1})
        conn.execute(text(_FINDING), {"snap": 1, "uuid": UB, "name": "DEMO_Rule_B", "kind": 2, "sev": "medium",
                                      "field": "dst.ip", "hash": H2})
        conn.execute(text(
            "INSERT INTO finding_verdict (object_key, key_kind, kind, field, value_hash, status, reason, decided_by, decided_at) VALUES "
            f"('{UA}', 'uuid', 1, 'subject.account.name', '{H1}', 'accepted', 'сервисная учётка', 'analyst1', '2026-09-02T10:00:00Z'),"
            f"('{UB}', 'uuid', 2, 'dst.ip', '{H2}', 'in_progress', NULL, 'analyst2', '2026-09-03T10:00:00Z'),"
            f"('DEMO_Rule_A', 'name', 1, 'subject.account.name', '{H1}', 'accepted', 'по имени', 'admin1', '2026-09-04T10:00:00Z'),"
            f"('{UB}', 'uuid', 3, 'dst.ip', '{H3}', 'open', NULL, 'admin1', '2026-09-04T11:00:00Z')"
        ))

    command.upgrade(cfg, AFTER)
    tables = set(inspect(engine).get_table_names())
    assert "finding_verdict_archive_20261002" in tables and "finding_verdict" not in tables
    # Переносятся решения по uuid: «принята» и «в работе». По имени вердикты не писались
    # и не читались никогда, «открыта» строкой — то же, что её отсутствие.
    assert _count(engine, "SELECT count(*) FROM platform_finding_state WHERE module = 'siem'") == 2
    assert _count(engine, "SELECT count(*) FROM finding_verdict_archive_20261002") == 4
    with engine.connect() as conn:
        salt = bytes.fromhex(json.loads(conn.execute(text("SELECT value_json FROM app_setting WHERE key = :k"),
                                                     {"k": SALT_SETTING}).scalar_one())["salt"])
        rows = {r.key: r for r in conn.execute(text(
            "SELECT key, scope_id, status, reason, updated_by, updated_at, present, title, severity, assignee "
            "FROM platform_finding_state WHERE module = 'siem'"
        ))}
        ka = finding_key(salt, UA, 1, "subject.account.name", H1)
        kb = finding_key(salt, UB, 2, "dst.ip", H2)
        assert set(rows) == {ka, kb}
        a, b = rows[ka], rows[kb]
        assert (a.scope_id, a.status, a.reason, a.updated_by, a.present, a.severity) == (0, "risk_accepted", "сервисная учётка", "analyst1", True, "high")
        assert "DEMO_Rule_A" in a.title and a.updated_at.isoformat().startswith("2026-09-02T10:00")
        assert (b.status, b.reason, b.updated_by, b.present, b.severity, b.assignee) == ("in_work", "", "analyst2", False, "medium", None)
        assert "DEMO_Rule_B" in b.title
        events = conn.execute(text(
            "SELECT s.key, e.kind, e.actor, e.from_status, e.to_status, e.comment FROM platform_finding_event e "
            "JOIN platform_finding_state s ON s.id = e.state_id ORDER BY e.to_status"
        )).all()
        assert [tuple(e) for e in events] == [
            (kb, "migrated", "analyst2", None, "in_work", ""),
            (ka, "migrated", "analyst1", None, "risk_accepted", "сервисная учётка"),
        ]

    command.downgrade(cfg, BEFORE)
    tables = set(inspect(engine).get_table_names())
    assert "finding_verdict" in tables and "finding_verdict_archive_20261002" not in tables
    assert _count(engine, "SELECT count(*) FROM platform_finding_state WHERE module = 'siem'") == 0
    assert _count(engine, "SELECT count(*) FROM platform_finding_event") == 0
    assert _count(engine, "SELECT count(*) FROM finding_verdict") == 4

    # Строка, заведённая уже после миграции, при откате остаётся; повторный upgrade
    # её не трогает и не падает на ней.
    with engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO platform_finding_state (module, scope_id, key, status, reason, present, title, severity, updated_by, updated_at) "
            "VALUES ('siem', 0, :k, 'new', '', true, 'после миграции', '', 'tester', now())"), {"k": kb})

    # Повторный upgrade даёт те же ключи: соль та же.
    command.upgrade(cfg, AFTER)
    with engine.connect() as conn:
        rows = {r.key: r for r in conn.execute(text("SELECT key, status, title FROM platform_finding_state WHERE module = 'siem'"))}
        migrated = set(conn.execute(text(
            "SELECT s.key FROM platform_finding_event e JOIN platform_finding_state s ON s.id = e.state_id")).scalars())
    assert set(rows) == {ka, kb} and migrated == {ka}
    assert (rows[kb].status, rows[kb].title) == ("new", "после миграции")


def test_snapshot_stamps_and_index_name(scratch: tuple[Engine, Config]) -> None:
    """Снапшот хранит версию разбора и отпечаток профиля; индекс ключа находки назван по делу."""
    engine, cfg = scratch
    command.upgrade(cfg, STAMPS)
    columns = {c["name"]: c for c in inspect(engine).get_columns("snapshot")}
    assert columns["parser_version"]["nullable"] and columns["profile_hash"]["nullable"]
    indexes = {i["name"] for i in inspect(engine).get_indexes("finding")}
    assert "ix_finding_identity" in indexes and "ix_finding_verdict_key" not in indexes

    command.downgrade(cfg, AFTER)
    assert not {"parser_version", "profile_hash"} & {c["name"] for c in inspect(engine).get_columns("snapshot")}
    indexes = {i["name"] for i in inspect(engine).get_indexes("finding")}
    assert "ix_finding_verdict_key" in indexes and "ix_finding_identity" not in indexes
