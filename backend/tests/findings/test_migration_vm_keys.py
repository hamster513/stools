"""Миграция e8f9a0b1c2d3: ключ находки до 400 символов, подсказки статусов пар VM
(`vm_finding_state_ref`) для строк, заведённых до неё. Настоящий прогон alembic."""
from __future__ import annotations

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, inspect, text

from tests.findings.test_migration_siem import scratch  # noqa: F401 — фикстура

BEFORE = "d7e8f9a0b1c2"
AFTER = "e8f9a0b1c2d3"

_STATE = ("INSERT INTO platform_finding_state (module, scope_id, key, status, reason, present, title, severity, "
          "updated_by, updated_at) VALUES (:module, 0, :key, 'in_work', '', true, '', '', 'tester', now())")


def _key_length(engine: Engine) -> int:
    return next(c["type"].length for c in inspect(engine).get_columns("platform_finding_state") if c["name"] == "key")


def test_key_widened_and_vm_refs_backfilled(scratch: tuple[Engine, Config]) -> None:  # noqa: F811
    engine, cfg = scratch
    command.upgrade(cfg, BEFORE)
    keys = {
        "vm": ["srv01.corp.local|10.0.0.1|CVE-2021-44228", "web|01.corp|10.0.0.9|CVE-2019-0708",
               "noip.corp||CVE-2023-1234", "без-разделителей"],
        "ad": ["a|b|c"],
    }
    with engine.begin() as conn:
        for module, ks in keys.items():
            for key in ks:
                conn.execute(text(_STATE), {"module": module, "key": key})

    command.upgrade(cfg, AFTER)
    assert _key_length(engine) == 400
    with engine.connect() as conn:
        refs = {tuple(r) for r in conn.execute(text(
            "SELECT s.key, r.hostname, r.ip, r.cve_id FROM vm_finding_state_ref r "
            "JOIN platform_finding_state s ON s.id = r.state_id"))}
    # Разбор справа: «|» в имени хоста остаётся в имени; ключ не пары и чужой модуль — без подсказки.
    assert refs == {
        ("srv01.corp.local|10.0.0.1|CVE-2021-44228", "srv01.corp.local", "10.0.0.1", "CVE-2021-44228"),
        ("web|01.corp|10.0.0.9|CVE-2019-0708", "web|01.corp", "10.0.0.9", "CVE-2019-0708"),
        ("noip.corp||CVE-2023-1234", "noip.corp", "", "CVE-2023-1234"),
    }
    indexes = {i["name"] for i in inspect(engine).get_indexes("vm_host")}
    assert "ix_vm_host_key" in indexes

    command.downgrade(cfg, BEFORE)
    assert "vm_finding_state_ref" not in inspect(engine).get_table_names()
    assert _key_length(engine) == 128
