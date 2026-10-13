"""Сбор правил из базы знаний по API: инвентарь, экспорт, конвейер разбора."""
from __future__ import annotations

from typing import Any


def test_inventory_tables_round_trip(db_session: Any, snapshot_id: int) -> None:
    from api.db.models import SiemDeploymentSet, SiemRuleDeployment, Snapshot

    db_session.add(SiemDeploymentSet(snapshot_id=snapshot_id, kb_id="set-1", name="install", system_name="install",
                                     general_status="Ok", compilation_status="Success", deployment_statuses_json='{"p1": "Installed"}', rule_count=2))
    db_session.add(SiemRuleDeployment(snapshot_id=snapshot_id, rule_uuid="u-1", installed=True, folder_path="PT/Windows", set_ids_json='["set-1"]'))
    snapshot = db_session.get(Snapshot, snapshot_id)
    snapshot.kb_host, snapshot.kb_database = "mp.corp.local", "Default"
    db_session.commit()
    db_session.expire_all()
    assert db_session.query(SiemDeploymentSet).filter_by(snapshot_id=snapshot_id).one().rule_count == 2
    assert db_session.query(SiemRuleDeployment).filter_by(snapshot_id=snapshot_id).one().installed is True
    assert db_session.get(Snapshot, snapshot_id).kb_database == "Default"
