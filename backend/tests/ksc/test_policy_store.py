from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from api.modules.ksc.core.policy_model import (
    EXTRACTORS,
    Exclusion,
    NetRule,
    PolicyObjects,
    exclusion_key,
    net_rule_key,
)
from api.modules.ksc.models import (
    KscExclusion,
    KscHost,
    KscNetRule,
    KscPolicy,
    KscPolicyScope,
    KscProfile,
)
from api.modules.ksc.services.snapshots import snapshot_path
from tests.ksc.synthetic import build_export, without_new_sections
from tests.ksc.test_api import upload

TABLES = (KscPolicy, KscPolicyScope, KscProfile, KscExclusion, KscNetRule)


def _snapshot_id(client: TestClient) -> int:
    return int(client.get("/api/ksc/snapshots").json()[0]["id"])


def _counts(db: Session, snapshot_id: int) -> dict[str, int]:
    return {m.__tablename__: db.execute(select(func.count()).select_from(m).where(m.snapshot_id == snapshot_id)).scalar_one() for m in TABLES}


def _policies(db: Session, snapshot_id: int) -> dict[int, KscPolicy]:
    db.expire_all()
    return {p.policy_id: p for p in db.execute(select(KscPolicy).where(KscPolicy.snapshot_id == snapshot_id)).scalars()}


def test_policies_scope_profiles_stored(auth_client: TestClient, db_session: Session) -> None:
    raw = build_export()
    assert upload(auth_client, raw)["status"] == "done"
    sid = _snapshot_id(auth_client)
    pols = _policies(db_session, sid)
    assert set(pols) == {1, 2, 3}
    p1 = pols[1]
    assert p1.name == "KES workstations" and p1.product == "KES" and p1.group_id == 0 and p1.group_path == "Managed devices"
    assert p1.has_contents and p1.profiles == 2 and p1.settings_total > 0 and p1.settings_known == 0 and p1.described is False
    assert p1.active and p1.accept_parent and p1.modified_at is not None
    assert p1.exclusions == 0 and p1.net_rules == 0
    assert not pols[2].has_contents and pols[2].settings_total == 0 and pols[3].profiles == 0
    # groups/hosts — по effective_policies синтетики и хостам в каждой группе.
    hosts_in = {g["id"]: sum(1 for h in raw["hosts"] if h["KLHST_WKS_GROUPID"] == g["id"]) for g in raw["groups"]}
    for pid, p in pols.items():
        scope = [int(gid) for gid, items in raw["effective_policies"].items() if any(i["KLPOL_ID"] == pid for i in items)]
        assert p.groups == len(scope) and p.hosts == sum(hosts_in[g] for g in scope), pid

    rows = {(s.policy_id, s.group_id): s for s in db_session.execute(select(KscPolicyScope).where(KscPolicyScope.snapshot_id == sid)).scalars()}
    assert rows[(1, 0)].own and rows[(1, 0)].group_path == "Managed devices" and rows[(1, 0)].hosts == hosts_in[0]
    assert not rows[(1, 2)].own and rows[(1, 2)].group_path == "Managed devices/Workstations" and rows[(1, 2)].hosts == hosts_in[2]
    assert rows[(3, 4)].own and (3, 2) not in rows

    profiles = {p.name: p for p in db_session.execute(select(KscProfile).where(KscProfile.snapshot_id == sid)).scalars()}
    assert set(profiles) == {"Ноутбуки", "Выключенный"} and all(p.policy_id == 1 for p in profiles.values())
    nb, off = profiles["Ноутбуки"], profiles["Выключенный"]
    assert nb.enabled and nb.priority == 0 and nb.settings == 2 and '"KLSSPOL_TAG": "Notebook"' in nb.condition_json
    assert not off.enabled and off.priority == 1 and off.settings == 0 and off.errors_json == "[]"

    hosts = {h.name: h.group_id for h in db_session.execute(select(KscHost).where(KscHost.snapshot_id == sid)).scalars()}
    assert hosts["WS01"] == 2 and hosts["SRV01"] == 3 and hosts["LAB01"] == 4 and hosts["WS08"] == 1


def test_profiles_not_collected(auth_client: TestClient, db_session: Session) -> None:
    assert upload(auth_client, without_new_sections(build_export()))["status"] == "done"
    sid = _snapshot_id(auth_client)
    assert _counts(db_session, sid)["ksc_profile"] == 0
    assert all(p.profiles is None for p in _policies(db_session, sid).values())


def _fake_extractor(sections: dict[str, Any]) -> PolicyObjects:
    """Секции политики (в них есть `KLPRSS_Deep`) — два исключения и правило; профиль «Ноутбуки» — одно исключение."""
    if "KLPRSS_Deep" in sections:
        return PolicyObjects(
            exclusions=[Exclusion("path", "C:\\Tools\\a.exe"), Exclusion("hash", "ABC", enabled=False)],
            net_rules=[NetRule("packet", 0, "DNS", "allow", "out", "UDP", "", "53", "10.0.0.1")],
        )
    if sections:
        return PolicyObjects(exclusions=[Exclusion("path", "C:\\Tools", components=("FileAV",), comment="профиль")])
    return PolicyObjects()


def test_extracted_objects_stored_and_reanalyze_and_delete(auth_client: TestClient, db_session: Session, monkeypatch: Any) -> None:
    monkeypatch.setitem(EXTRACTORS, "KES", _fake_extractor)
    raw = build_export()
    raw["policy_contents"].pop("3")  # у «KES lab» нет содержимого: только политика 1 даёт записи
    assert upload(auth_client, raw)["status"] == "done"
    sid = _snapshot_id(auth_client)
    pols = _policies(db_session, sid)
    p1 = pols[1]
    assert p1.described and p1.exclusions == 3 and p1.net_rules == 1
    assert pols[3].described and pols[3].exclusions == 0 and not pols[3].has_contents
    assert pols[2].described is False

    excl = {(e.profile, e.value): e for e in db_session.execute(select(KscExclusion).where(KscExclusion.snapshot_id == sid)).scalars()}
    assert set(excl) == {("", "C:\\Tools\\a.exe"), ("", "ABC"), ("Ноутбуки", "C:\\Tools")}
    prof = excl[("Ноутбуки", "C:\\Tools")]
    assert prof.policy_id == 1 and prof.kind == "path" and prof.components_json == '["FileAV"]' and prof.comment == "профиль"
    assert prof.key == exclusion_key(Exclusion("path", "C:\\Tools")) and prof.risks_json == "[]"
    assert excl[("", "ABC")].enabled is False and excl[("", "ABC")].kind == "hash"
    rule = db_session.execute(select(KscNetRule).where(KscNetRule.snapshot_id == sid)).scalars().one()
    assert (rule.policy_id, rule.profile, rule.layer, rule.name, rule.action, rule.direction, rule.remote_ports) == (1, "", "packet", "DNS", "allow", "out", "53")
    assert rule.key == net_rule_key(NetRule("packet", 0, "DNS", "allow", "out", "UDP", "", "53", "10.0.0.1"))

    before = _counts(db_session, sid)
    assert before == {"ksc_policy": 3, "ksc_policy_scope": 7, "ksc_profile": 2, "ksc_exclusion": 3, "ksc_net_rule": 1}
    r = auth_client.post(f"/api/ksc/snapshots/{sid}/reanalyze")
    assert r.status_code == 202 and auth_client.get(f"/api/ksc/jobs/{r.json()['job_id']}").json()["status"] == "done"
    db_session.expire_all()
    assert _counts(db_session, sid) == before

    assert auth_client.delete(f"/api/ksc/snapshots/{sid}").status_code == 204
    db_session.expire_all()
    assert _counts(db_session, sid) == dict.fromkeys(before, 0)


def _drop_policy_tables(db: Session, snapshot_id: int) -> None:
    """Как у снапшота, импортированного до таблиц политик: строк нет, у хостов нет группы."""
    for m in TABLES:
        db.execute(delete(m).where(m.snapshot_id == snapshot_id))
    db.execute(update(KscHost).where(KscHost.snapshot_id == snapshot_id).values(group_id=None))
    db.commit()


def test_old_snapshot_backfilled_on_first_read(auth_client: TestClient, db_session: Session) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    sid = _snapshot_id(auth_client)
    before = _counts(db_session, sid)
    full = auth_client.get(f"/api/ksc/snapshots/{sid}/policy-list").json()
    _drop_policy_tables(db_session, sid)
    assert _counts(db_session, sid) == dict.fromkeys(before, 0)

    assert auth_client.get(f"/api/ksc/snapshots/{sid}/policy-list").json() == full
    db_session.expire_all()
    assert _counts(db_session, sid) == before
    host = auth_client.get(f"/api/ksc/snapshots/{sid}/hosts/h-ws01").json()
    assert [p["id"] for p in host["policies"]] == [2, 1]
    # Второе чтение не дублирует строк.
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/policy-list").json() == full
    db_session.expire_all()
    assert _counts(db_session, sid) == before


@pytest.mark.parametrize("path", ["policies/1", "exclusions", "net-rules", "hosts/h-ws01", "hosts?policy=1"])
def test_each_route_backfills(auth_client: TestClient, db_session: Session, path: str) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    sid = _snapshot_id(auth_client)
    before = _counts(db_session, sid)
    _drop_policy_tables(db_session, sid)
    r = auth_client.get(f"/api/ksc/snapshots/{sid}/{path}")
    assert r.status_code == 200, r.text
    db_session.expire_all()
    assert _counts(db_session, sid) == before
    if path == "hosts?policy=1":
        assert r.json()["total"] == 11


def test_old_snapshot_without_file_stays_empty(auth_client: TestClient, db_session: Session, app_settings: Any) -> None:
    assert upload(auth_client, build_export())["status"] == "done"
    sid = _snapshot_id(auth_client)
    _drop_policy_tables(db_session, sid)
    snapshot_path(app_settings.data_dir, sid).unlink()
    body = auth_client.get(f"/api/ksc/snapshots/{sid}/policy-list").json()
    assert body == {"items": [], "facets": {"product": {}, "active": {"true": 0, "false": 0}}, "profiles_collected": False}
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/hosts/h-ws01").json()["policies"] == []
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/exclusions").json()["total"] == 0
    db_session.expire_all()
    assert _counts(db_session, sid)["ksc_policy"] == 0


def test_old_snapshot_with_broken_file_stays_empty(auth_client: TestClient, db_session: Session, app_settings: Any) -> None:
    """Файл снапшота не разбирается: дозаполнение не роняет чтение, экраны пусты, как до него."""
    assert upload(auth_client, build_export())["status"] == "done"
    sid = _snapshot_id(auth_client)
    _drop_policy_tables(db_session, sid)
    snapshot_path(app_settings.data_dir, sid).write_bytes(b"\x00not a gzip export\xff")
    r = auth_client.get(f"/api/ksc/snapshots/{sid}/policy-list")
    assert r.status_code == 200, r.text
    assert r.json()["items"] == []
    assert auth_client.get(f"/api/ksc/snapshots/{sid}/hosts/h-ws01").json()["policies"] == []
    db_session.expire_all()
    assert _counts(db_session, sid)["ksc_policy"] == 0
