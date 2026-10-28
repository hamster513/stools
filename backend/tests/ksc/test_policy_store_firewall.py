"""Хранение структуры адресов сетевых правил (`scope_json`) и настроек сетевого экрана (`ksc_policy_firewall`),
дозаполнение снапшотов, записанных до миграции."""
from __future__ import annotations

import json
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from api.modules.ksc.core.policy_model import Scope, scope_from_json
from api.modules.ksc.models import KscNetRule, KscPolicyFirewall
from api.modules.ksc.services.snapshots import snapshot_path
from tests.ksc.kes11 import kes11_export
from tests.ksc.test_api import upload


def _upload(client: TestClient) -> int:
    assert upload(client, kes11_export())["status"] == "done"
    return int(client.get("/api/ksc/snapshots").json()[0]["id"])


def _scopes(db: Session, sid: int) -> list[str | None]:
    return list(db.execute(select(KscNetRule.scope_json).where(KscNetRule.snapshot_id == sid).order_by(KscNetRule.id)).scalars())


def _firewall(db: Session, sid: int) -> list[tuple[Any, ...]]:
    return [tuple(r) for r in db.execute(
        select(KscPolicyFirewall.policy_id, KscPolicyFirewall.profile, KscPolicyFirewall.locks_json)
        .where(KscPolicyFirewall.snapshot_id == sid).order_by(KscPolicyFirewall.id)
    )]


def _forget(db: Session, sid: int) -> None:
    """Состояние снапшота, записанного до миграции: `scope_json` NULL, строк firewall нет."""
    db.execute(update(KscNetRule).where(KscNetRule.snapshot_id == sid).values(scope_json=None))
    db.execute(delete(KscPolicyFirewall).where(KscPolicyFirewall.snapshot_id == sid))
    db.commit()


def test_upload_writes_scope_and_firewall(auth_client: TestClient, db_session: Session) -> None:
    sid = _upload(auth_client)
    scopes = _scopes(db_session, sid)
    assert scopes and all(scopes)
    assert scope_from_json(scopes[0]) == Scope(networks=2)
    fw = _firewall(db_session, sid)
    # Секция HIPS есть только у самой политики 1: у профилей «Ноутбуки» и «Выключенный» её нет, у политики 3 — тоже.
    assert [(policy_id, profile) for policy_id, profile, _ in fw] == [(1, "")]
    assert json.loads(fw[0][2]) == {"packet": True, "networks": True, "app": True}


def test_scope_backfill_on_first_read(auth_client: TestClient, db_session: Session) -> None:
    sid = _upload(auth_client)
    _forget(db_session, sid)
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/net-rules").status_code == 200
    scopes = _scopes(db_session, sid)
    assert scopes and all(scopes)
    assert [(policy_id, profile) for policy_id, profile, _ in _firewall(db_session, sid)] == [(1, "")]


def test_scope_backfill_without_file_is_noop(auth_client: TestClient, db_session: Session, app_settings: Any) -> None:
    sid = _upload(auth_client)
    _forget(db_session, sid)
    snapshot_path(app_settings.data_dir, sid).unlink()
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/net-rules").status_code == 200
    scopes = _scopes(db_session, sid)
    assert scopes and all(s is None for s in scopes)
    assert _firewall(db_session, sid) == []
