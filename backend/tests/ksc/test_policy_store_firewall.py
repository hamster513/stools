"""Хранение структуры адресов сетевых правил (`scope_json`) и настроек сетевого экрана (`ksc_policy_firewall`),
дозаполнение снапшотов, записанных до миграции (версия таблиц политик ниже текущей)."""
from __future__ import annotations

import json
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from api.modules.ksc.core.export import load_export
from api.modules.ksc.core.policy_index import extract, policy_objects
from api.modules.ksc.core.policy_model import Scope, firewall_to_json, scope_from_json
from api.modules.ksc.models import KscNetRule, KscPolicyFirewall, KscSnapshot
from api.modules.ksc.services.policy_store import POLICY_STORE_VERSION
from api.modules.ksc.services.snapshots import snapshot_path
from tests.ksc.kes11 import _APP_GROUPS, kes11_export, kes11_sections
from tests.ksc.test_api import upload
from tests.ksc.test_firewall_settings import _APP, _NETWORKS, _PACKET, _set_lock

#: Выгрузка, где у политики 1 нет ни одного сетевого правила: пакетных нет, у групп доверия нет программ; секция HIPS есть.
#: Строки firewall выгрузки `kes11_export()`: секция HIPS — у политики 1; у профиля «Ноутбуки» и политики 3 (синтетика) — только флаг
#: компонента Firewall в `KLPRSS_Components`; у профиля «Выключенный» — ничего.
PAIRS = [(1, ""), (1, "Ноутбуки"), (3, "")]
NO_RULES = {"cf9370d5/firewall.networkPacketRules": [], "cf9370d5/hips.appGroups": [{**g, "applications": []} for g in _APP_GROUPS]}


def _profile_export() -> dict[str, Any]:
    """`kes11_export()`, где у профиля «Ноутбуки» политики 1 секции — `kes11_sections()` без замков у трёх листов HIPS
    (как в профиле, где замок не задан). Элемент списка профилей заменяется, общий `P_NOTEBOOKS` синтетики не меняется."""
    raw = kes11_export()
    sections = kes11_sections()
    for path in (_PACKET, _NETWORKS, _APP):
        _set_lock(sections, path, None)
    profiles = raw["policy_profiles"]["1"]["profiles"]
    assert profiles[0]["name"] == "Ноутбуки"
    profiles[0] = {**profiles[0], "sections": sections}
    return raw


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
    assert [(f.policy_id, f.profile) for f in fw] == PAIRS
    objs = extract("KES", kes11_sections())
    assert objs is not None and objs.firewall is not None
    expected = json.loads(json.dumps(firewall_to_json(objs.firewall)))
    row = fw[0]
    assert (row.enabled, row.notify_only, row.hips_enabled, row.hips_notify_only) == (
        expected["enabled"], expected["notify_only"], expected["hips_enabled"], expected["hips_notify_only"])
    assert (row.component_enabled, row.hips_component_enabled, row.default_app_group) == (None, None, 1) == (
        expected["component_enabled"], expected["hips_component_enabled"], expected["default_app_group"])
    assert json.loads(row.zones_json) == expected["zones"] and expected["zones"]
    assert json.loads(row.app_groups_json) == expected["app_groups"] and expected["app_groups"]
    assert json.loads(row.locks_json) == expected["locks"] == {"packet": True, "networks": True, "app": True, "component": None,
                                                              "hips_component": None}
    # Только флаг компонента: «Ноутбуки» выключает Firewall под замком, политика 3 включает без замка; секции HIPS нет.
    for f, enabled, locked in ((fw[1], False, True), (fw[2], True, False)):
        assert (f.component_enabled, f.hips_component_enabled, f.default_app_group, f.enabled, f.hips_enabled) == (enabled, None, None, None, None)
        assert (f.zones_json, f.app_groups_json) == ("[]", "[]")
        assert json.loads(f.locks_json) == {"packet": None, "networks": None, "app": None, "component": locked, "hips_component": None}


def test_upload_writes_profile_firewall(auth_client: TestClient, db_session: Session) -> None:
    """У профиля с секцией HIPS — своя строка: сначала политика, затем профили в порядке `policy_objects`; замки профиля
    без признака — None, у политики — True."""
    raw = _profile_export()
    sid = _upload(auth_client, raw)
    objs, _ = policy_objects(load_export(json.dumps(raw).encode()), "1")
    assert list(objs.firewall_by_profile) == ["", "Ноутбуки"]
    fw = _firewall(db_session, sid)
    assert [(f.policy_id, f.profile) for f in fw] == PAIRS
    policy, profile = (json.loads(f.locks_json) for f in fw[:2])
    assert policy == {"packet": True, "networks": True, "app": True, "component": None, "hips_component": None}
    assert profile == {"packet": None, "networks": None, "app": None, "component": None, "hips_component": None}
    assert (fw[1].zones_json, fw[1].app_groups_json) == (fw[0].zones_json, fw[0].app_groups_json)


def test_policy_objects_firewall_by_profile_keys() -> None:
    """Ключи `firewall_by_profile`: "" — сама политика, имя — профиль с секцией HIPS; профиль без неё («Выключенный») — без ключа,
    `firewall` у результата — None."""
    objs, described = policy_objects(load_export(json.dumps(_profile_export()).encode()), "1")
    assert described is True and objs.firewall is None
    assert set(objs.firewall_by_profile) == {"", "Ноутбуки"}
    assert objs.firewall_by_profile["Ноутбуки"].locks.packet is None and objs.firewall_by_profile[""].locks.packet is True


def test_scope_backfill_on_first_read(auth_client: TestClient, db_session: Session) -> None:
    sid = _upload(auth_client)
    _forget(db_session, sid)
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/net-rules").status_code == 200
    scopes = _scopes(db_session, sid)
    assert scopes and all(scopes)
    assert _pairs(db_session, sid) == PAIRS
    assert _version(db_session, sid) == POLICY_STORE_VERSION


def test_backfill_without_net_rules_writes_firewall(auth_client: TestClient, db_session: Session) -> None:
    sid = _upload(auth_client, kes11_export(**NO_RULES))
    assert _scopes(db_session, sid) == []
    _forget(db_session, sid)
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/net-rules").status_code == 200
    assert _pairs(db_session, sid) == PAIRS
    assert _version(db_session, sid) == POLICY_STORE_VERSION


def test_backfill_is_not_repeated(auth_client: TestClient, db_session: Session) -> None:
    sid = _upload(auth_client)
    first = [f.id for f in _firewall(db_session, sid)]
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/net-rules").status_code == 200
    assert [f.id for f in _firewall(db_session, sid)] == first
    # Снапшот до миграции: первое чтение дозаполняет (id строк новые), второе — уже нет (id те же).
    _forget(db_session, sid)
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/net-rules").status_code == 200
    backfilled = [f.id for f in _firewall(db_session, sid)]
    assert backfilled and backfilled != first
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/net-rules").status_code == 200
    assert [f.id for f in _firewall(db_session, sid)] == backfilled


def test_scope_backfill_without_file_is_noop(auth_client: TestClient, db_session: Session, app_settings: Any) -> None:
    sid = _upload(auth_client)
    _forget(db_session, sid)
    snapshot_path(app_settings.data_dir, sid).unlink()
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/net-rules").status_code == 200
    scopes = _scopes(db_session, sid)
    assert scopes and all(s is None for s in scopes)
    assert _pairs(db_session, sid) == []
    assert _version(db_session, sid) == 0
