from __future__ import annotations

from sqlalchemy import inspect

from api.modules.ksc.models import KscHost, KscSnapshot


def test_ksc_tables_exist(db_session) -> None:
    names = set(inspect(db_session.get_bind()).get_table_names())
    assert {"ksc_server", "ksc_connection", "ksc_snapshot", "ksc_host", "ksc_finding", "ksc_job"} <= names
    # Вердикты перенесены в статусы находок; таблица осталась архивом.
    assert "ksc_verdict_archive_20261002" in names and "ksc_verdict" not in names
    cols = {c.name for c in KscHost.__table__.columns}
    assert {"snapshot_id", "host_id", "fqdn", "agent_alive", "rtp_state", "bases_at", "in_ad", "components_json"} <= cols
    assert "stats_json" in {c.name for c in KscSnapshot.__table__.columns}
