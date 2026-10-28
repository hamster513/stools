"""Миграция 4e7a9c1b3d5f: `scope_json` у сетевых правил, таблица `ksc_policy_firewall`, версия таблиц политик снапшота.
Настоящий прогон alembic по кругу upgrade → downgrade → upgrade."""
from __future__ import annotations

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, inspect, text

from tests.findings.test_migration_siem import scratch  # noqa: F401 — фикстура

BEFORE = "7e31b0364015"
AFTER = "4e7a9c1b3d5f"

#: Колонки `ksc_policy_firewall` после миграции.
FIREWALL = {"id", "snapshot_id", "policy_id", "profile", "enabled", "notify_only", "hips_enabled", "hips_notify_only", "component_enabled",
            "hips_component_enabled", "default_app_group", "zones_json", "app_groups_json", "locks_json"}


def _columns(engine: Engine, table: str) -> set[str]:
    return {c["name"] for c in inspect(engine).get_columns(table)}


def _assert_upgraded(engine: Engine) -> None:
    assert "policy_store_version" in _columns(engine, "ksc_snapshot")
    assert "scope_json" in _columns(engine, "ksc_net_rule")
    assert _columns(engine, "ksc_policy_firewall") == FIREWALL


def test_policy_store_migration_round_trip(scratch: tuple[Engine, Config]) -> None:  # noqa: F811
    engine, cfg = scratch
    command.upgrade(cfg, BEFORE)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO ksc_server (id, name, version, created_at) VALUES (2, 'ksc01', '15', now())"))
        conn.execute(text("INSERT INTO ksc_snapshot (id, server_id, hosts, collected_at, imported_at, source, collector, filename, sha256, "
                          "findings, stats_json, analyzer_version) VALUES (20, 2, 0, '2026-09-01T00:00:00Z', now(), 'file', '', '', '', 0, '{}', '1')"))

    command.upgrade(cfg, AFTER)
    _assert_upgraded(engine)
    with engine.connect() as conn:
        # Снапшот до миграции — версия 0: его таблицы дозаполнятся при первом чтении.
        assert conn.execute(text("SELECT policy_store_version FROM ksc_snapshot WHERE id = 20")).scalar_one() == 0

    command.downgrade(cfg, BEFORE)
    assert "ksc_policy_firewall" not in inspect(engine).get_table_names()
    assert "policy_store_version" not in _columns(engine, "ksc_snapshot")
    assert "scope_json" not in _columns(engine, "ksc_net_rule")

    command.upgrade(cfg, AFTER)
    _assert_upgraded(engine)
