"""Журнал изменений: разница двух выгрузок и её запись при импорте, пересчёте и удалении снапшотов."""
from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.modules.ksc.core import changes as core_changes
from api.modules.ksc.core.changes import KINDS, Change, Diff, diff_exports
from api.modules.ksc.core.export import KscExport, load_export
from api.modules.ksc.core.policy_contents import walk_settings
from api.modules.ksc.core.policy_model import EXTRACTORS, Exclusion, PolicyObjects, exclusion_key
from api.modules.ksc.models import KscChange, KscSnapshot
from api.modules.ksc.services.changes import changes_summary
from api.modules.ksc.services.snapshots import snapshot_path
from tests.ksc.kes11 import _PACKET_RULES, TCP, exclusion, kes11_export, packet_rule
from tests.ksc.synthetic import (
    NOTEBOOKS_EXPRESSION,
    _lock,
    activation,
    build_export,
    condition_group,
    tag_condition,
    without_new_sections,
)
from tests.ksc.test_api import upload


def _copy(raw: dict[str, Any]) -> dict[str, Any]:
    return dict(json.loads(json.dumps(raw)))


def _load(raw: dict[str, Any]) -> KscExport:
    """Как при импорте: обёртки сняты, секреты скрыты."""
    return load_export(json.dumps(raw).encode())


def _diff(prev: dict[str, Any], cur: dict[str, Any]) -> Diff:
    return diff_exports(_load(prev), _load(cur))


def _of(diff: Diff, kind: str) -> list[Change]:
    return [c for c in diff.changes if c.kind == kind]


def _policy(raw: dict[str, Any], pid: int) -> dict[str, Any]:
    return next(p for p in raw["policies"] if p["KLPOL_ID"] == pid)


# --- чистое сравнение ---------------------------------------------------------------------------


#: Сравнение без извлекателя: исключения и сетевые правила не сравнивались — продукт не описан.
UNDESCRIBED = {**dict.fromkeys(KINDS, True), "net_rule": False, "exclusion": False}


def test_no_edits_no_changes_all_compared(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = build_export()
    # Политики синтетики — продукт KES: извлекатель есть, записи сравнивались (в выдуманных секциях их просто нет).
    diff = _diff(raw, _copy(raw))
    assert diff.changes == [] and not diff.truncated
    assert diff.compared == dict.fromkeys(KINDS, True)
    monkeypatch.delitem(EXTRACTORS, "KES")
    assert _diff(raw, _copy(raw)).compared == UNDESCRIBED


def test_policy_renamed_deactivated_added_removed() -> None:
    prev = build_export()
    cur = _copy(prev)
    _policy(cur, 1)["KLPOL_DN"] = "KES workstations 2"
    _policy(cur, 3)["KLPOL_ACTIVE"] = False
    cur["policies"] = [p for p in cur["policies"] if p["KLPOL_ID"] != 2]
    cur["policies"].append(dict(_policy(cur, 1), KLPOL_ID=7, KLPOL_DN="KES new", KLPOL_GROUP_ID=3))
    pol = {(c.policy_id, c.action, c.path): c for c in _of(_diff(prev, cur), "policy")}
    assert set(pol) == {(1, "changed", "name"), (3, "changed", "active"), (2, "removed", ""), (7, "added", "")}
    renamed = pol[(1, "changed", "name")]
    assert (renamed.before, renamed.after, renamed.policy_name) == ("KES workstations", "KES workstations 2", "KES workstations 2")
    assert (pol[(3, "changed", "active")].before, pol[(3, "changed", "active")].after) == (True, False)
    assert pol[(7, "added", "")].after == {"name": "KES new", "product": "KES", "group": "Managed devices/Servers"}
    assert pol[(2, "removed", "")].before == {"name": "Agent", "product": "1103", "group": "Managed devices"}
    assert pol[(2, "removed", "")].policy_name == "Agent"


def test_policy_group_and_accept_parent() -> None:
    prev = build_export()
    cur = _copy(prev)
    _policy(cur, 3)["KLPOL_GROUP_ID"] = 2
    _policy(cur, 3)["KLPOL_ACCEPT_PARENT"] = True
    pol = {c.path: c for c in _of(_diff(prev, cur), "policy")}
    assert set(pol) == {"group", "accept_parent"}
    assert (pol["group"].before, pol["group"].after) == ("Managed devices/Workstations/Lab", "Managed devices/Workstations")
    assert (pol["accept_parent"].before, pol["accept_parent"].after) == (False, True)


def test_scope_policy_starts_acting_on_group() -> None:
    prev = build_export()
    cur = _copy(prev)
    cur["effective_policies"]["3"].append(dict(_policy(cur, 1), KLPOL_INHERITED=True))
    cur["effective_policies"]["4"] = [p for p in cur["effective_policies"]["4"] if p["KLPOL_ID"] != 3]
    diff = _diff(prev, cur)
    scope = {(c.policy_id, c.action): c for c in _of(diff, "scope")}
    assert set(scope) == {(1, "added"), (3, "removed")}
    assert scope[(1, "added")].path == "Managed devices/Servers" and scope[(1, "added")].policy_name == "KES workstations"
    assert scope[(3, "removed")].path == "Managed devices/Workstations/Lab"
    assert len(diff.changes) == 2


def test_profiles_added_disabled_priority_condition() -> None:
    prev = build_export()
    cur = _copy(prev)
    entry = cur["policy_profiles"]["1"]
    notebooks = entry["profiles"][0]
    notebooks["attrs"]["KLSSPOL_PRF_ENABLED"] = False
    notebooks["attrs"]["EXPRESSION"]["value"] = activation(condition_group(tag_condition("Laptop")))
    entry["profiles"].append({"name": "Серверы", "attrs": {"KLSSPOL_PRF_ENABLED": True}, "sections": {}, "errors": []})
    entry["priorities"] = ["Серверы", "Ноутбуки", "Выключенный"]
    prof = {(c.profile, c.action, c.path): c for c in _of(_diff(prev, cur), "profile")}
    assert set(prof) == {
        ("Серверы", "added", ""), ("Ноутбуки", "changed", "enabled"), ("Ноутбуки", "changed", "priority"),
        ("Ноутбуки", "changed", "condition"), ("Выключенный", "changed", "priority"),
    }
    assert all(c.policy_id == 1 and c.policy_name == "KES workstations" for c in prof.values())
    assert prof[("Серверы", "added", "")].after["priority"] == 0
    assert (prof[("Ноутбуки", "changed", "enabled")].before, prof[("Ноутбуки", "changed", "enabled")].after) == (True, False)
    assert (prof[("Выключенный", "changed", "priority")].before, prof[("Выключенный", "changed", "priority")].after) == (1, 2)
    cond = prof[("Ноутбуки", "changed", "condition")]
    assert cond.before["EXPRESSION"] == NOTEBOOKS_EXPRESSION and cond.after["EXPRESSION"] == activation(condition_group(tag_condition("Laptop")))


def test_profile_only_disabled() -> None:
    """Включённость лежит и в атрибутах профиля: условие из-за неё изменённым не считается."""
    prev = build_export()
    cur = _copy(prev)
    cur["policy_profiles"]["1"]["profiles"][0]["attrs"]["KLSSPOL_PRF_ENABLED"] = False
    assert [(c.kind, c.profile, c.action, c.path) for c in _diff(prev, cur).changes] == [("profile", "Ноутбуки", "changed", "enabled")]


def test_profile_removed() -> None:
    prev = build_export()
    cur = _copy(prev)
    cur["policy_profiles"]["1"]["profiles"].pop()  # «Выключенный»
    cur["policy_profiles"]["1"]["priorities"] = ["Ноутбуки"]
    prof = _of(_diff(prev, cur), "profile")
    assert [(c.profile, c.action) for c in prof] == [("Выключенный", "removed")]
    assert prof[0].before["enabled"] is False


def test_setting_value_changed() -> None:
    prev = build_export()
    cur = _copy(prev)
    cur["policy_contents"]["1"]["sections"]["KLPRSS_Basic"]["ReportsMaxSize"] = _lock(2048, locked=False)
    diff = _diff(prev, cur)
    assert len(diff.changes) == 1
    c = diff.changes[0]
    assert (c.kind, c.action, c.policy_id, c.profile, c.section, c.path) == ("setting", "changed", 1, "", "KLPRSS_Basic", "ReportsMaxSize")
    assert (c.before, c.after) == ({"value": 1024}, {"value": 2048})


def test_setting_only_lock_changed() -> None:
    prev = build_export()
    cur = _copy(prev)
    cur["policy_contents"]["1"]["sections"]["KLPRSS_Basic"]["ReportsMaxSize"] = _lock(1024, locked=True)
    [c] = _diff(prev, cur).changes
    assert (c.kind, c.path) == ("setting", "ReportsMaxSize")
    assert (c.before, c.after) == ({"value": 1024, "locked": False}, {"value": 1024, "locked": True})


def test_list_setting_items_added_and_removed() -> None:
    prev = build_export()
    cur = _copy(prev)
    cur["policy_contents"]["1"]["sections"]["KLPRSS_Basic"]["Exclusions"] = _lock(["C:\\Tools\\b.exe", {"Path": "D:\\x"}], locked=False)
    [c] = _diff(prev, cur).changes
    assert (c.kind, c.action, c.path) == ("setting", "changed", "Exclusions")
    assert c.before == {"removed": ["C:\\Tools\\a.exe"]} and c.after == {"added": ["C:\\Tools\\b.exe", {"Path": "D:\\x"}]}


@pytest.mark.parametrize("container", ["top", "section", "mixed"])
def test_setting_change_does_not_depend_on_container_level(container: str) -> None:
    """Одна и та же правка видна одинаково — тем же путём листа — при контейнерах `KLPRSS_Val` на листьях, на ключах
    верхнего уровня, на всю секцию и вперемешку."""
    # `officeArchivesScanMode` в форме «вперемешку» — обычное значение рядом с вложенными контейнерами.
    edits = {"4b741d57/heuristicLevel": 3, "4b741d57/compoundFilesSettings.officeArchivesScanMode": 0,
             "1d3e35bd/passwordProtection.areas.exportSettings": True,
             "852d0287/scanExclusionsAndTrustedZone.scanExclusions": [exclusion("C:\\Tools\\b.exe")]}

    def changes(shape: str) -> list[tuple[Any, ...]]:
        diff = _diff(kes11_export(shape), kes11_export(shape, **edits))
        return [(c.kind, c.action, c.policy_id, c.profile, c.section, c.path, c.before, c.after) for c in diff.changes]

    leaf = changes("leaf")
    # Список исключений разбирает извлекатель KES: вместо настройки-списка — записи исключений (3 убраны, 1 добавлена).
    assert [c[5] for c in leaf if c[0] == "setting"] == ["passwordProtection.areas.exportSettings", "compoundFilesSettings.officeArchivesScanMode",
                                                         "heuristicLevel"]
    assert sorted((c[0], c[1]) for c in leaf if c[0] != "setting") == [("exclusion", "added")] + [("exclusion", "removed")] * 3
    assert leaf[2][6:] == ({"value": 2}, {"value": 3})
    assert changes(container) == leaf


def test_list_setting_reordered_is_not_a_change() -> None:
    prev = build_export()
    prev["policy_contents"]["1"]["sections"]["KLPRSS_Basic"]["Exclusions"] = _lock(["C:\\a.exe", "C:\\b.exe"], locked=False)
    cur = _copy(prev)
    cur["policy_contents"]["1"]["sections"]["KLPRSS_Basic"]["Exclusions"] = _lock(["C:\\b.exe", "C:\\a.exe"], locked=False)
    assert _diff(prev, cur).changes == []


def test_new_setting_in_profile() -> None:
    prev = build_export()
    cur = _copy(prev)
    cur["policy_profiles"]["1"]["profiles"][0]["sections"]["KLPRSS_Basic"]["ReportsMaxSize"] = _lock(10, locked=True)
    [c] = _diff(prev, cur).changes
    assert (c.kind, c.action, c.profile, c.section, c.path) == ("setting", "added", "Ноутбуки", "KLPRSS_Basic", "ReportsMaxSize")
    assert c.after == {"value": 10, "locked": True} and c.before is None


def test_setting_of_new_policy_not_listed() -> None:
    prev = build_export()
    cur = _copy(prev)
    cur["policies"].append(dict(_policy(cur, 3), KLPOL_ID=8, KLPOL_DN="KES copy"))
    cur["policy_contents"]["8"] = _copy(cur["policy_contents"]["3"])
    assert [(c.kind, c.action, c.policy_id) for c in _diff(prev, cur).changes] == [("policy", "added", 8)]


def test_profiles_not_collected_in_prev() -> None:
    prev = build_export()
    cur = _copy(prev)
    cur["policy_profiles"]["1"]["profiles"][0]["sections"]["KLPRSS_Basic"]["ReportsMaxSize"] = _lock(10, locked=True)
    cur["policy_profiles"]["1"]["profiles"][1]["attrs"]["KLSSPOL_PRF_ENABLED"] = True
    diff = _diff(without_new_sections(prev), cur)
    assert diff.compared["profile"] is False and diff.compared["setting"] is True
    assert _of(diff, "profile") == [] and not [c for c in _of(diff, "setting") if c.profile]
    assert diff.changes == []


def test_contents_not_collected_in_prev() -> None:
    prev = build_export()
    prev.pop("policy_contents")
    cur = _copy(build_export())
    cur["policy_contents"]["1"]["sections"]["KLPRSS_Basic"]["ReportsMaxSize"] = _lock(2048, locked=False)
    diff = _diff(prev, cur)
    assert diff.compared["setting"] is False and diff.compared["exclusion"] is False and diff.compared["net_rule"] is False
    assert diff.compared["policy"] is True and diff.compared["scope"] is True
    assert _of(diff, "setting") == []


def test_section_not_read_in_current_is_not_removed() -> None:
    """Секция политики ушла в ошибки (больше лимита): её настройки не «удалены», остальные секции сравниваются."""
    prev = build_export()
    cur = _copy(prev)
    content = cur["policy_contents"]["1"]
    content["sections"].pop("KLPRSS_Basic")
    content["errors"] = ["KLPRSS_Basic: секция больше лимита"]
    content["sections"]["KLPRSS_Components"]["KLPRSS_Val"]["Firewall"]["KLPRSS_Val"]["Enabled"] = _lock(False, locked=False)
    diff = _diff(prev, cur)
    assert [(c.kind, c.action, c.profile, c.section) for c in diff.changes] == [("setting", "changed", "", "KLPRSS_Components")]
    assert diff.compared["setting"] is True


def test_policy_over_limit_not_compared() -> None:
    prev = build_export()
    cur = _copy(prev)
    cur["policy_contents"]["1"] = {"product": "KES", "version": "12.0.0.0", "sections": {}, "errors": ["лимит политик"]}
    cur["policy_profiles"]["1"] = {"profiles": [], "priorities": [], "errors": ["лимит политик"]}
    assert _diff(prev, cur).changes == []


def _profile_unread(raw: dict[str, Any], name: str) -> None:
    """Профиль, у которого не прочитаны ни атрибуты, ни настройки."""
    pr = next(p for p in raw["policy_profiles"]["1"]["profiles"] if p["name"] == name)
    pr.update(attrs={}, sections={}, errors=["GetProfileSettings: boom"])


def test_profile_unread_in_current_is_not_changed_or_removed() -> None:
    prev = build_export()
    cur = _copy(prev)
    _profile_unread(cur, "Ноутбуки")
    assert _diff(prev, cur).changes == []


def test_profile_unread_in_previous_is_not_added() -> None:
    prev = _copy(build_export())  # профили синтетики — общие словари модуля: правится только копия
    _profile_unread(prev, "Ноутбуки")
    assert _diff(prev, build_export()).changes == []


def test_profile_section_not_read_is_not_removed() -> None:
    prev = build_export()
    cur = _copy(prev)
    pr = cur["policy_profiles"]["1"]["profiles"][0]
    pr["sections"].pop("KLPRSS_Components")
    pr["errors"] = ["KLPRSS_Components: секция больше лимита"]
    assert _diff(prev, cur).changes == []


def test_priorities_not_read_is_not_a_priority_change() -> None:
    """`GetPriorities` отказал: профили в порядке по имени — это не смена приоритетов."""
    prev = build_export()
    cur = _copy(prev)
    cur["policy_profiles"]["1"].update(priorities=[], errors=["GetPriorities: boom"])
    assert _diff(prev, cur).changes == []


def test_records_of_unread_section_not_compared(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(EXTRACTORS, "KES", _exclusions_extractor)
    prev = build_export()
    cur = _copy(prev)
    cur["policy_contents"]["1"]["sections"].pop("KLPRSS_Basic")
    cur["policy_contents"]["1"]["errors"] = ["KLPRSS_Basic: секция больше лимита"]
    diff = _diff(prev, cur)
    assert diff.changes == [] and diff.compared["exclusion"] is True


def test_hidden_values_not_compared() -> None:
    prev = build_export()
    cur = _copy(prev)
    cur["policy_contents"]["1"]["sections"]["KLPRSS_Basic"]["AdminPassword"] = _lock("another-secret", locked=True)
    cur["policy_profiles"]["1"]["profiles"][0]["sections"]["KLPRSS_Basic"]["ProxyPassword"] = _lock("other-profile-secret", locked=True)
    assert _diff(prev, cur).changes == []


def _exclusions_extractor(sections: dict[str, Any]) -> PolicyObjects:
    """Исключения — элементы списка `KLPRSS_Basic.Exclusions`; исходная настройка уходит в `consumed`."""
    out = PolicyObjects()
    for s in walk_settings(sections):
        if (s.section, s.path) == ("KLPRSS_Basic", "Exclusions"):
            out.exclusions.extend(Exclusion("path", str(v)) for v in s.value)
            out.consumed.add((s.section, s.path))
    return out


def test_extracted_exclusion_added_and_source_setting_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(EXTRACTORS, "KES", _exclusions_extractor)
    prev = build_export()
    cur = _copy(prev)
    cur["policy_contents"]["1"]["sections"]["KLPRSS_Basic"]["Exclusions"] = _lock(["C:\\Tools\\a.exe", "C:\\Tools\\b.exe"], locked=False)
    diff = _diff(prev, cur)
    assert [(c.kind, c.action, c.policy_id, c.profile) for c in diff.changes] == [("exclusion", "added", 1, "")]
    c = diff.changes[0]
    assert c.path == exclusion_key(Exclusion("path", "C:\\Tools\\b.exe")) and c.after["value"] == "C:\\Tools\\b.exe" and c.before is None
    assert _of(diff, "setting") == []
    assert diff.compared == dict.fromkeys(KINDS, True)


def test_extracted_exclusion_changed(monkeypatch: pytest.MonkeyPatch) -> None:
    def extractor(sections: dict[str, Any]) -> PolicyObjects:
        enabled = any(s.path == "ReportsMaxSize" and s.value == 1024 for s in walk_settings(sections))
        return PolicyObjects(exclusions=[Exclusion("path", "C:\\Tools", enabled=enabled)]) if "KLPRSS_Deep" in sections else PolicyObjects()

    monkeypatch.setitem(EXTRACTORS, "KES", extractor)
    prev = build_export()
    cur = _copy(prev)
    cur["policy_contents"]["1"]["sections"]["KLPRSS_Basic"]["ReportsMaxSize"] = _lock(2048, locked=False)
    diff = _diff(prev, cur)
    excl = _of(diff, "exclusion")
    assert [(c.action, c.policy_id, c.before["enabled"], c.after["enabled"]) for c in excl] == [("changed", 1, True, False)]
    assert diff.compared["exclusion"] is True and diff.compared["net_rule"] is True


def test_packet_rule_inserted_on_top_is_one_added() -> None:
    """Номер правила (`position`) сдвигается у всех правил ниже вставленного — это не их изменение."""
    prev = kes11_export()
    cur = kes11_export(**{"cf9370d5/firewall.networkPacketRules": [packet_rule("Тестовое правило: новое", action=1, direction=3, protocol=TCP),
                                                                    *_PACKET_RULES]})
    rules = _of(_diff(prev, cur), "net_rule")
    assert [(c.action, c.after["name"], c.after["position"]) for c in rules] == [("added", "Тестовое правило: новое", 0)]
    assert _of(_diff(cur, prev), "net_rule")[0].action == "removed" and len(_of(_diff(cur, prev), "net_rule")) == 1


def test_net_rule_changed_keeps_position_for_display() -> None:
    edited = [dict(r) for r in _PACKET_RULES]
    edited[1] = {**edited[1], "enabled": False}
    rules = _of(_diff(kes11_export(), kes11_export(**{"cf9370d5/firewall.networkPacketRules": edited})), "net_rule")
    assert [(c.action, c.before["enabled"], c.after["enabled"], c.before["position"], c.after["position"]) for c in rules] == [
        ("changed", True, False, 1, 1)]


def test_truncated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(core_changes, "MAX_CHANGES", 3)
    prev = build_export()
    cur = _copy(prev)
    for p in cur["policies"]:
        p["KLPOL_DN"] += " v2"
        p["KLPOL_ACTIVE"] = False
    diff = _diff(prev, cur)
    assert len(diff.changes) == 3 and diff.truncated


# --- запись в базу ------------------------------------------------------------------------------


def _raw(collected_at: str, name: str = "KES workstations") -> dict[str, Any]:
    raw = build_export()
    raw["server"]["collected_at"] = collected_at
    _policy(raw, 1)["KLPOL_DN"] = name
    return raw


def _snapshot_ids(client: TestClient) -> dict[str, int]:
    """Время сбора (дата) → id снапшота."""
    return {s["collected_at"][:10]: int(s["id"]) for s in client.get("/api/ksc/snapshots").json()}


def _summary(db: Session, snapshot_id: int) -> dict[str, Any]:
    db.expire_all()
    return changes_summary(db.get(KscSnapshot, snapshot_id))  # type: ignore[arg-type]


def _rows(db: Session, snapshot_id: int) -> list[KscChange]:
    return list(db.execute(select(KscChange).where(KscChange.snapshot_id == snapshot_id).order_by(KscChange.id)).scalars())


def test_import_middle_delete_reanalyze(auth_client: TestClient, db_session: Session) -> None:
    assert upload(auth_client, _raw("2026-09-14T12:00:00Z", "A"))["status"] == "done"
    assert upload(auth_client, _raw("2026-09-16T12:00:00Z", "B"))["status"] == "done"
    ids = _snapshot_ids(auth_client)
    first, last = ids["2026-09-14"], ids["2026-09-16"]
    assert _summary(db_session, first) == {"prev": None, "total": 0, "compared": {}, "truncated": False}
    s = _summary(db_session, last)
    assert s["prev"] == first and s["total"] == 1 and s["compared"] == dict.fromkeys(KINDS, True) and not s["truncated"]
    [row] = _rows(db_session, last)
    assert (row.kind, row.action, row.policy_id, row.path, row.prev_snapshot_id) == ("policy", "changed", 1, "name", first)
    assert (json.loads(row.before_json), json.loads(row.after_json), row.policy_name) == ("A", "B", "B")
    assert "checks" in json.loads(db_session.get(KscSnapshot, last).stats_json)  # type: ignore[union-attr]

    # Снапшот в середину истории: последний сравнивается уже с ним.
    assert upload(auth_client, _raw("2026-09-15T12:00:00Z", "B"))["status"] == "done"
    middle = _snapshot_ids(auth_client)["2026-09-15"]
    assert _summary(db_session, middle)["prev"] == first and _summary(db_session, middle)["total"] == 1
    assert _summary(db_session, last)["prev"] == middle and _summary(db_session, last)["total"] == 0 and _rows(db_session, last) == []

    # Пересчёт не удваивает записи.
    r = auth_client.post(f"/api/ksc/snapshots/{middle}/reanalyze")
    assert r.status_code == 202 and auth_client.get(f"/api/ksc/jobs/{r.json()['job_id']}").json()["status"] == "done"
    assert len(_rows(db_session, middle)) == 1 and _summary(db_session, middle)["total"] == 1

    # Удаление среднего: последний снова сравнивается с первым.
    assert auth_client.delete(f"/api/ksc/snapshots/{middle}").status_code == 204
    assert _summary(db_session, last)["prev"] == first and _summary(db_session, last)["total"] == 1
    assert [r.prev_snapshot_id for r in _rows(db_session, last)] == [first]
    assert db_session.execute(select(func.count()).select_from(KscChange).where(KscChange.snapshot_id == middle)).scalar_one() == 0


def test_previous_file_missing(auth_client: TestClient, db_session: Session, app_settings: Any) -> None:
    assert upload(auth_client, _raw("2026-09-14T12:00:00Z", "A"))["status"] == "done"
    first = _snapshot_ids(auth_client)["2026-09-14"]
    snapshot_path(app_settings.data_dir, first).unlink()
    assert upload(auth_client, _raw("2026-09-15T12:00:00Z", "B"))["status"] == "done"
    second = _snapshot_ids(auth_client)["2026-09-15"]
    assert _summary(db_session, second) == {
        "prev": first, "total": 0, "compared": dict.fromkeys(KINDS, False), "truncated": False, "reason": "файл предыдущего снапшота не найден",
    }
    assert _rows(db_session, second) == []


def test_failure_does_not_break_import(auth_client: TestClient, db_session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    from api.modules.ksc.services import changes as service

    def boom(prev: KscExport, cur: KscExport) -> Diff:
        raise RuntimeError("сбой сравнения")

    assert upload(auth_client, _raw("2026-09-14T12:00:00Z", "A"))["status"] == "done"
    monkeypatch.setattr(service, "diff_exports", boom)
    assert upload(auth_client, _raw("2026-09-15T12:00:00Z", "B"))["status"] == "done"
    ids = _snapshot_ids(auth_client)
    s = _summary(db_session, ids["2026-09-15"])
    assert s["reason"] == "изменения не посчитаны: сбой сравнения" and s["total"] == 0 and s["prev"] == ids["2026-09-14"]
    assert "checks" in json.loads(db_session.get(KscSnapshot, ids["2026-09-15"]).stats_json)  # type: ignore[union-attr]


def test_successor_lookup_failure_does_not_break_import(auth_client: TestClient, db_session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    from api.modules.ksc.services import changes as service

    def boom(db: Session, snapshot: KscSnapshot) -> KscSnapshot | None:
        raise RuntimeError("сбой поиска следующего")

    monkeypatch.setattr(service, "next_snapshot", boom)
    assert upload(auth_client, _raw("2026-09-14T12:00:00Z", "A"))["status"] == "done"
    assert _summary(db_session, _snapshot_ids(auth_client)["2026-09-14"])["prev"] is None


def test_import_does_not_reread_own_file(auth_client: TestClient, db_session: Session, app_settings: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Импорт сравнивает с предыдущим уже разобранную выгрузку: свой файл журнал изменений не перечитывает."""
    from api.modules.ksc.services import changes as service

    read: list[str] = []
    real = service.load_snapshot_export

    def spy(path: Any) -> KscExport:
        read.append(str(path))
        return real(path)

    monkeypatch.setattr(service, "load_snapshot_export", spy)
    assert upload(auth_client, _raw("2026-09-14T12:00:00Z", "A"))["status"] == "done"
    assert upload(auth_client, _raw("2026-09-15T12:00:00Z", "B"))["status"] == "done"
    ids = _snapshot_ids(auth_client)
    assert read == [str(snapshot_path(app_settings.data_dir, ids["2026-09-14"]))]
    assert _summary(db_session, ids["2026-09-15"])["total"] == 1
