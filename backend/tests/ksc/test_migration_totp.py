"""Existing connections survive TOTP schema upgrade and downgrade."""
from alembic import command
from sqlalchemy import inspect, text

from tests.findings.test_migration_siem import scratch  # noqa: F401


def test_totp_migration_round_trip(scratch):
    engine, cfg = scratch
    command.upgrade(cfg, "6ac0fd54831b")
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO ksc_connection (id,title,host,port,username,password,verify_tls,internal,domain,skip_policy_contents) "
                          "VALUES (101,'existing','ksc.test',13299,'test','encrypted-old-password',true,true,'',false)"))
    command.upgrade(cfg, "7bd1ae65942c")
    with engine.connect() as conn:
        assert conn.execute(text("SELECT password,totp_secret FROM ksc_connection WHERE id=101 LIMIT 1")).one() == ("encrypted-old-password", "")
    col = next(c for c in inspect(engine).get_columns("ksc_connection") if c["name"] == "totp_secret")
    assert not col["nullable"]
    command.downgrade(cfg, "6ac0fd54831b")
    assert "totp_secret" not in {c["name"] for c in inspect(engine).get_columns("ksc_connection")}
    with engine.connect() as conn:
        assert conn.scalar(text("SELECT password FROM ksc_connection WHERE id=101 LIMIT 1")) == "encrypted-old-password"
    command.upgrade(cfg, "7bd1ae65942c")
    with engine.connect() as conn:
        assert conn.scalar(text("SELECT totp_secret FROM ksc_connection WHERE id=101 LIMIT 1")) == ""
