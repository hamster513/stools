"""Вкладка «Настройки» политики: группы по компонентам словаря, «Прочее», «не описан», счётчик распознанных при импорте."""
from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.ksc.core.dictionary import DICTIONARIES
from api.modules.ksc.models import KscPolicy
from tests.ksc.kes11 import SECRETS, kes11_export
from tests.ksc.synthetic import SECRET_VALUES
from tests.ksc.test_api import upload


@pytest.fixture
def sid(auth_client: TestClient) -> int:
    assert upload(auth_client, kes11_export())["status"] == "done"
    return int(auth_client.get("/api/ksc/snapshots").json()[0]["id"])


def _settings(client: TestClient, sid: int, pid: int) -> dict[str, Any]:
    r = client.get(f"/api/ksc/snapshots/{sid}/policies/{pid}/settings")
    assert r.status_code == 200, r.text
    return dict(r.json())


def test_kes_policy_grouped_by_components(auth_client: TestClient, sid: int) -> None:
    body = _settings(auth_client, sid, 1)
    assert body["described"] is True
    order = list(DICTIONARIES["KES"].components)
    components = [g["component"] for g in body["groups"]]
    assert components == [c for c in order if c in components] and components[:4] == ["general", "trusted_zone", "hips", "firewall"]
    assert all(g["settings"] for g in body["groups"])
    assert body["known"] == sum(len(g["settings"]) for g in body["groups"])
    assert body["total"] == body["known"] + len(body["other"])
    card = auth_client.get(f"/api/ksc/snapshots/{sid}/policies/1").json()
    assert (card["settings_known"], card["settings_total"]) == (body["known"], body["total"])
    groups = {g["component"]: g for g in body["groups"]}
    assert groups["general"]["title"] == "Общие настройки" and groups["general"]["enabled"] is None
    assert groups["firewall"]["enabled"] is True and groups["file_threat"]["enabled"] is True and groups["ksn"]["enabled"] is None
    self_defence = next(s for s in groups["general"]["settings"] if s["path"] == "selfDefense.enableSelfDefence")
    assert self_defence == {"section": "1d3e35bd", "path": "selfDefense.enableSelfDefence", "title": "Самозащита", "value": "включено",
                            "raw": "true", "locked": True, "verified": True}
    action = next(s for s in groups["file_threat"]["settings"] if s["path"] == "scanAction")
    assert (action["value"], action["verified"]) == ("код 0", False)
    other = {(o["section"], o["path"]): o for o in body["other"]}
    assert other[("f8e8efda", "mode")] == {"section": "f8e8efda", "path": "mode", "value": "0", "locked": False}


def test_secrets_hidden(auth_client: TestClient, sid: int) -> None:
    body = _settings(auth_client, sid, 1)
    text = json.dumps(body, ensure_ascii=False)
    assert not [s for s in SECRETS if s in text]
    general = next(g for g in body["groups"] if g["component"] == "general")["settings"]
    shown = {s["path"]: s["value"] for s in general}
    assert shown["passwordProtection.passwordHash"] == "<скрыто>" and shown["passwordProtection.login"] == "<скрыто>"
    assert shown["proxy.userPassword"] == "<скрыто>"
    assert not [s for s in SECRET_VALUES if s in json.dumps(_settings(auth_client, sid, 3), ensure_ascii=False)]


def test_kes_policy_without_known_sections(auth_client: TestClient, sid: int) -> None:
    """Политика 3 — продукт KES, но секции выдуманные (`KLPRSS_*`): словарь есть, распознанного нет."""
    body = _settings(auth_client, sid, 3)
    assert body["described"] is True and body["known"] == 0 and body["groups"] == []
    assert body["total"] == len(body["other"]) > 0
    assert {o["section"] for o in body["other"]} >= {"KLPRSS_Basic", "KLPRSS_Components"}


def test_policy_without_dictionary(auth_client: TestClient, sid: int) -> None:
    """Политика 2 — агент: словаря нет, содержимое не собирается."""
    assert _settings(auth_client, sid, 2) == {"described": False, "known": 0, "total": 0, "groups": [], "other": []}


def test_not_found(auth_client: TestClient, sid: int) -> None:
    assert auth_client.get(f"/api/ksc/snapshots/{sid + 100}/policies/1/settings").status_code == 404
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/policies/99/settings").status_code == 404


def test_settings_known_stored(auth_client: TestClient, db_session: Session, sid: int) -> None:
    rows = {p.policy_id: p for p in db_session.execute(select(KscPolicy).where(KscPolicy.snapshot_id == sid)).scalars()}
    assert rows[1].settings_known > 0 and rows[1].settings_known < rows[1].settings_total
    assert rows[3].settings_known == 0 and rows[2].settings_known == 0


def test_settings_same_for_top_level_containers(auth_client: TestClient, sid: int) -> None:
    """Контейнеры `KLPRSS_Val` на ключах верхнего уровня (скелет такую форму не отличает): ответ тот же, что при
    контейнерах на листьях, и тот же счётчик распознанных в карточке."""
    leaf = _settings(auth_client, sid, 1)
    assert upload(auth_client, kes11_export("top"))["status"] == "done"
    top_sid = max(int(s["id"]) for s in auth_client.get("/api/ksc/snapshots").json())
    assert top_sid != sid
    assert _settings(auth_client, top_sid, 1) == leaf
    card = auth_client.get(f"/api/ksc/snapshots/{top_sid}/policies/1").json()
    assert (card["settings_known"], card["settings_total"]) == (leaf["known"], leaf["total"])

