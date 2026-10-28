"""Хранение структуры адресов сетевых правил (`scope_json`) и настроек сетевого экрана (`ksc_policy_firewall`),
дозаполнение снапшотов, записанных до миграции (версия таблиц политик ниже текущей)."""
from __future__ import annotations

import json
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from api.modules.ksc.core.policy_index import extract
from api.modules.ksc.core.policy_model import Scope, firewall_to_json, scope_from_json
from api.modules.ksc.models import KscNetRule, KscPolicyFirewall, KscSnapshot
from api.modules.ksc.services.policy_store import POLICY_STORE_VERSION
from api.modules.ksc.services.snapshots import snapshot_path
from tests.ksc.kes11 import _APP_GROUPS, kes11_export, kes11_sections
from tests.ksc.test_api import upload

#: Выгрузка, где у политики 1 нет ни одного сетевого правила: пакетных нет, у групп доверия нет программ; секция HIPS есть.
NO_RULES = {"cf9370d5/firewall.networkPacketRules": [], "cf9370d5/hips.appGroups": [{**g, "applications": []} for g in _APP_GROUPS]}


def _upload(client: TestClient, raw: dict[str, Any] | None = None) -> int:
    assert upload(client, raw or kes11_export())["status"] == "done"
    return int(client.get("/api/ksc/snapshots").json()[0]["id"])


def _scopes(db: Session, sid: int) -> list[str | None]:
    return list(db.execute(select(KscNetRule.scope_json).where(KscNetRule.snapshot_id == sid).order_by(KscNetRule.id)).scalars())


def _firewall(db: Session, sid: int) -> list[KscPolicyFirewall]:
    db.expire_all()
    return list(db.execute(select(KscPolicyFirewall).where(KscPolicyFirewall.snapshot_id == sid).order_by(KscPolicyFirewall.id)).scalars())


def _pairs(db: Session, sid: int) -> list[tuple[int, str]]:
    return [(f.policy_id, f.profile) for f in _firewall(db, sid)]


def _version(db: Session, sid: int) -> int:
    return int(db.execute(select(KscSnapshot.policy_store_version).where(KscSnapshot.id == sid)).scalar_one())


def _forget(db: Session, sid: int) -> None:
    """Состояние снапшота, записанного до миграции: `scope_json` NULL, строк firewall нет, версия таблиц 0."""
    db.execute(update(KscNetRule).where(KscNetRule.snapshot_id == sid).values(scope_json=None))
    db.execute(delete(KscPolicyFirewall).where(KscPolicyFirewall.snapshot_id == sid))
    db.execute(update(KscSnapshot).where(KscSnapshot.id == sid).values(policy_store_version=0))
    db.commit()


def test_upload_writes_scope_and_firewall(auth_client: TestClient, db_session: Session) -> None:
    sid = _upload(auth_client)
    scopes = _scopes(db_session, sid)
    assert scopes and all(scopes)
    assert scope_from_json(scopes[0]) == Scope(networks=2)
    assert _version(db_session, sid) == POLICY_STORE_VERSION
    fw = _firewall(db_session, sid)
    # Секция HIPS есть только у самой политики 1: у профилей «Ноутбуки» и «Выключенный» её нет, у политики 3 — тоже.
    assert [(f.policy_id, f.profile) for f in fw] == [(1, "")]
    objs = extract("KES", kes11_sections())
    assert objs is not None and objs.firewall is not None
    expected = json.loads(json.dumps(firewall_to_json(objs.firewall)))
    row = fw[0]
    assert (row.enabled, row.notify_only, row.hips_enabled, row.hips_notify_only) == (
        expected["enabled"], expected["notify_only"], expected["hips_enabled"], expected["hips_notify_only"])
    assert json.loads(row.zones_json) == expected["zones"] and expected["zones"]
    assert json.loads(row.app_groups_json) == expected["app_groups"] and expected["app_groups"]
    assert json.loads(row.locks_json) == expected["locks"] == {"packet": True, "networks": True, "app": True}


def test_scope_backfill_on_first_read(auth_client: TestClient, db_session: Session) -> None:
    sid = _upload(auth_client)
    _forget(db_session, sid)
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/net-rules").status_code == 200
    scopes = _scopes(db_session, sid)
    assert scopes and all(scopes)
    assert _pairs(db_session, sid) == [(1, "")]
    assert _version(db_session, sid) == POLICY_STORE_VERSION


def test_backfill_without_net_rules_writes_firewall(auth_client: TestClient, db_session: Session) -> None:
    sid = _upload(auth_client, kes11_export(**NO_RULES))
    assert _scopes(db_session, sid) == []
    _forget(db_session, sid)
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/net-rules").status_code == 200
    assert _pairs(db_session, sid) == [(1, "")]
    assert _version(db_session, sid) == POLICY_STORE_VERSION


def test_backfill_is_not_repeated(auth_client: TestClient, db_session: Session) -> None:
    sid = _upload(auth_client)
    first = [f.id for f in _firewall(db_session, sid)]
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/net-rules").status_code == 200
    assert [f.id for f in _firewall(db_session, sid)] == first


def test_scope_backfill_without_file_is_noop(auth_client: TestClient, db_session: Session, app_settings: Any) -> None:
    sid = _upload(auth_client)
    _forget(db_session, sid)
    snapshot_path(app_settings.data_dir, sid).unlink()
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/net-rules").status_code == 200
    scopes = _scopes(db_session, sid)
    assert scopes and all(s is None for s in scopes)
    assert _pairs(db_session, sid) == []
    assert _version(db_session, sid) == 0
