"""Обход дерева настроек политики (замки) и три проверки по нему."""
from __future__ import annotations

import json
from typing import Any

from api.modules.ksc.core.checks import CHECK_BY_CODE
from api.modules.ksc.core.checks.policy_contents import (
    check_policy_content_missing,
    check_policy_no_locks,
    check_policy_weak_locks,
)
from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.export import ExportIndex, load_export
from api.modules.ksc.core.findings import Finding
from api.modules.ksc.core.policy_contents import (
    flat_settings,
    lock_summary,
    truncate_value,
    walk_settings,
)
from tests.ksc.synthetic import build_export, expected_policy_contents


def _idx(raw: dict[str, Any] | None = None) -> ExportIndex:
    data = build_export() if raw is None else raw
    return ExportIndex(load_export(json.dumps(data, ensure_ascii=False).encode()))


def _run(check: Any, raw: dict[str, Any] | None = None, cfg: KscConfig | None = None) -> list[Finding]:
    return check(_idx(raw), cfg or KscConfig())


# --- walk_settings: обход дерева ---


def _lock(value: Any, *, locked: bool | None = False, inherited: bool = False, lock_policy: str = "", lock_group: str = "") -> dict[str, Any]:
    node: dict[str, Any] = {"KLPRSS_Val": value, "KLPRSS_ValLck": inherited, "KLPRSS_ValLckPolicy": lock_policy, "KLPRSS_ValLckGroup": lock_group}
    if locked is not None:
        node["KLPRSS_Mnd"] = locked
    return node


def test_walk_settings_flat_container_locked_and_unlocked() -> None:
    sections = {"Sec": {"A": _lock(True, locked=True), "B": _lock(1024, locked=False)}}
    out = {s.path: s for s in walk_settings(sections)}
    assert out["A"].section == "Sec" and out["A"].value is True and out["A"].locked is True and out["A"].inherited_lock is False and out["A"].lock_from == ""
    assert out["B"].value == 1024 and out["B"].locked is False


def test_walk_settings_nested_container_accumulates_path() -> None:
    """`KLPRSS_Val`, сам будучи словарём дальнейших контейнеров, не лист — спуск с накоплением path."""
    sections = {"Sec": {"Group": {"KLPRSS_Val": {"Inner": {"KLPRSS_Val": {"Enabled": _lock(True, locked=True)}}}}}}
    out = walk_settings(sections)
    assert len(out) == 1
    assert out[0].section == "Sec" and out[0].path == "Group.Inner.Enabled" and out[0].value is True and out[0].locked is True


def test_walk_settings_inherited_lock_with_group() -> None:
    sections = {"Sec": {"A": _lock(True, locked=True, inherited=True, lock_policy="KES root", lock_group="Managed devices")}}
    s = walk_settings(sections)[0]
    assert s.inherited_lock is True and s.lock_from == "KES root (Managed devices)"


def test_walk_settings_lock_from_without_group_is_bare_policy_name() -> None:
    sections = {"Sec": {"A": _lock(True, locked=True, inherited=True, lock_policy="KES root")}}
    assert walk_settings(sections)[0].lock_from == "KES root"


def test_walk_settings_locked_none_when_mnd_absent() -> None:
    sections = {"Sec": {"A": _lock(True, locked=None)}}
    assert walk_settings(sections)[0].locked is None


def test_walk_settings_plain_container_without_val_is_descended() -> None:
    sections = {"Sec": {"Wrapper": {"A": _lock(True, locked=True), "B": _lock(False, locked=False)}}}
    out = {s.path: s for s in walk_settings(sections)}
    assert set(out) == {"Wrapper.A", "Wrapper.B"}


def test_walk_settings_locked_container_with_plain_children_is_one_setting() -> None:
    """`KLPRSS_Val` — словарь, но среди детей нет контейнеров `KLPRSS_Val`: это значение, а не
    вложенность. Одна замкнутая настройка со всем словарём в значении — не «ни одного замка»."""
    sections = {"Sec": {"Scan": {"KLPRSS_Val": {"Enabled": True, "Level": 2}, "KLPRSS_Mnd": True}}}
    out = walk_settings(sections)
    assert len(out) == 1
    assert out[0].path == "Scan" and out[0].value == {"Enabled": True, "Level": 2} and out[0].locked is True
    summary = lock_summary(out)
    assert summary.total == 1 and summary.locked == 1 and summary.with_lock_flag == 1 and summary.share == 1.0


def test_walk_settings_descends_when_any_child_is_container() -> None:
    """Хотя бы один ребёнок — контейнер `KLPRSS_Val`: спуск; простые значения рядом не настройки."""
    sections = {"Sec": {"Group": {"KLPRSS_Val": {"A": _lock(True, locked=True), "Note": "x"}, "KLPRSS_Mnd": False}}}
    assert [(s.path, s.locked) for s in walk_settings(sections)] == [("Group.A", True)]


def test_walk_settings_ignores_bare_scalars_and_lists() -> None:
    """Значения без контейнера `KLPRSS_Val` (голая строка, список) — не настройки, не спускаются."""
    sections = {"Sec": {"PlainString": "hunter2", "PlainList": ["a", "b"], "A": _lock(True, locked=True)}}
    out = walk_settings(sections)
    assert [s.path for s in out] == ["A"]


def test_walk_settings_list_inside_val_is_a_leaf_value_not_descended() -> None:
    sections = {"Sec": {"Exclusions": _lock(["a.exe", "b.exe"], locked=True)}}
    s = walk_settings(sections)[0]
    assert s.value == ["a.exe", "b.exe"] and s.locked is True


def test_walk_settings_unwraps_typed_scalar_inside_val() -> None:
    sections = {"Sec": {"A": {"KLPRSS_Val": {"type": "long", "value": 42}, "KLPRSS_Mnd": True, "KLPRSS_ValLck": False, "KLPRSS_ValLckPolicy": "", "KLPRSS_ValLckGroup": ""}}}
    s = walk_settings(sections)[0]
    assert s.value == 42 and s.locked is True


def test_walk_settings_binary_section_wrapper_yields_no_settings() -> None:
    """Секция целиком — типизированная двоичная обёртка (как `KLPRSS_Secret` в синтетике):
    после `unwrap` это просто строка, не контейнер — настроек в ней нет."""
    sections = {"KLPRSS_Secret": {"type": "binary", "value": "c2VjcmV0"}}
    assert walk_settings(sections) == []


def test_walk_settings_on_synthetic_policy_contents() -> None:
    """Синтетика: `KLPRSS_Basic` — 8 контейнеров-настроек (среди них `TrustedApps` без признака
    замка и `PasswordProtection` со словарём без контейнеров в значении — лист), `KLPRSS_Components`
    (вложенный `KLPRSS_Val`, 2 листа), `KLPRSS_Passwords` (2 контейнера), `KLPRSS_Firewall`
    (1 контейнер со списком правил); `KLPRSS_Password`, `KLPRSS_Secret` и `KLPRSS_Deep` без настроек."""
    contents = expected_policy_contents()
    locked_settings = walk_settings(contents["1"]["sections"])
    # section несёт имя секции (KLPRSS_Components) отдельно — в path оно не дублируется.
    assert {(s.section, s.path) for s in locked_settings} == {
        ("KLPRSS_Basic", "EnableSelfProtection"), ("KLPRSS_Basic", "EnablePasswordProtection"), ("KLPRSS_Basic", "ReportsMaxSize"),
        ("KLPRSS_Basic", "AdminPassword"), ("KLPRSS_Basic", "ProxyPassword"), ("KLPRSS_Basic", "PasswordProtection"),
        ("KLPRSS_Basic", "Exclusions"), ("KLPRSS_Basic", "TrustedApps"),
        ("KLPRSS_Components", "FileThreatProtection.Enabled"), ("KLPRSS_Components", "Firewall.Enabled"),
        ("KLPRSS_Passwords", "Uninstall"), ("KLPRSS_Passwords", "Exit"), ("KLPRSS_Firewall", "rules"),
    }
    summary = lock_summary(locked_settings)
    assert summary.total == 13 and summary.locked == 7 and summary.with_lock_flag == 12 and summary.share == 7 / 12
    unlocked_settings = walk_settings(contents["3"]["sections"])
    unlocked_summary = lock_summary(unlocked_settings)
    assert unlocked_summary.total == 13 and unlocked_summary.locked == 0 and unlocked_summary.with_lock_flag == 12 and unlocked_summary.share == 0.0


# --- lock_summary ---


def test_lock_summary_empty_is_zero_share_no_division_error() -> None:
    s = lock_summary([])
    assert s.total == 0 and s.locked == 0 and s.share == 0.0 and s.with_lock_flag == 0


def test_lock_summary_share_counts_only_settings_with_lock_flag() -> None:
    sections = {"Sec": {"A": _lock(True, locked=True), "B": _lock(True, locked=False), "C": _lock(True, locked=None), "D": _lock(True, locked=None)}}
    s = lock_summary(walk_settings(sections))
    assert s.total == 4 and s.locked == 1 and s.with_lock_flag == 2 and s.share == 0.5


# --- truncate_value ---


def test_truncate_value_short_value_unchanged() -> None:
    assert truncate_value(True) == "true"
    assert truncate_value(1024) == "1024"
    assert truncate_value("ok") == '"ok"'


def test_truncate_value_long_value_is_cut_with_marker() -> None:
    text = truncate_value("x" * 500, limit=200)
    assert len(text) == 200 + len("… (обрезано)") and text.endswith("… (обрезано)")
    assert truncate_value("x" * 198, limit=200) == json.dumps("x" * 198)  # 200 символов ровно — граница не режется


# --- проверки: позитив, негатив, пороги ---


def test_check_policy_no_locks_fires_on_policy_without_any_lock() -> None:
    f = _run(check_policy_no_locks)
    assert {x.target for x in f} == {"KES lab"}
    finding = f[0]
    assert finding.severity == "High" and finding.key_extra == "3"
    assert finding.details["total"] == 13 and finding.details["locked"] == 0 and finding.details["with_lock_flag"] == 12 and finding.details["share"] == 0.0
    assert finding.details["product"] == "KES" and finding.details["group"] == "Managed devices/Workstations/Lab"


def test_check_policy_no_locks_silent_on_policy_with_some_locks() -> None:
    assert not [x for x in _run(check_policy_no_locks) if x.target == "KES workstations"]


def test_check_policy_weak_locks_fires_below_threshold() -> None:
    cfg = KscConfig(policy_lock_share=0.7)
    f = _run(check_policy_weak_locks, cfg=cfg)
    assert {x.target for x in f} == {"KES workstations"}
    assert f[0].severity == "Medium" and f[0].key_extra == "1"
    assert f[0].details["share"] == 7 / 12 and f[0].details["with_lock_flag"] == 12


def test_check_policy_weak_locks_silent_at_default_threshold() -> None:
    assert not _run(check_policy_weak_locks)


def test_check_policy_weak_locks_does_not_fire_on_policy_with_zero_locks() -> None:
    """Нулевая доля — это `POLICY_NO_LOCKS`, не `POLICY_WEAK_LOCKS`."""
    f = _run(check_policy_weak_locks, cfg=KscConfig(policy_lock_share=1.0))
    assert "KES lab" not in {x.target for x in f}


def _no_lock_flags(raw: dict[str, Any]) -> dict[str, Any]:
    """Убирает `KLPRSS_Mnd` из всех контейнеров — формат замков, который обход не распознаёт."""
    if isinstance(raw, dict):
        return {k: _no_lock_flags(v) for k, v in raw.items() if k != "KLPRSS_Mnd"}
    if isinstance(raw, list):
        return [_no_lock_flags(v) for v in raw]
    return raw


def test_lock_checks_silent_when_no_setting_has_lock_flag() -> None:
    """Ни одной настройки с `KLPRSS_Mnd` — замки не распознаны: ни High «нет замков», ни Medium,
    хотя настроек много и ни одна не замкнута."""
    raw = build_export()
    for content in raw["policy_contents"].values():
        content["sections"] = _no_lock_flags(content["sections"])
    idx = _idx(raw)
    cfg = KscConfig(policy_lock_share=1.0)
    summary = lock_summary(walk_settings(idx.export.policy_contents["3"]["sections"]))
    assert summary.total == 13 and summary.with_lock_flag == 0 and summary.share == 0.0
    assert not check_policy_no_locks(idx, cfg)
    assert not check_policy_weak_locks(idx, cfg)


def test_check_policy_no_locks_not_fired_by_locked_container_with_plain_children() -> None:
    """Сценарий ревью: единственная настройка — замкнутый контейнер со словарём простых значений.
    Раньше обход спускался в словарь, терял замок и давал ложную High."""
    raw = build_export()
    raw["policy_contents"]["3"]["sections"] = {"Sec": {"Scan": {"KLPRSS_Val": {"Enabled": True, "Level": 2}, "KLPRSS_Mnd": True}, "Other": _lock(True, locked=False)}}
    assert not [x for x in _run(check_policy_no_locks, raw) if x.target == "KES lab"]
    weak = _run(check_policy_weak_locks, raw, KscConfig(policy_lock_share=0.9))
    assert [(x.target, x.details["locked"], x.details["with_lock_flag"]) for x in weak if x.target == "KES lab"] == [("KES lab", 1, 2)]


def test_check_policy_content_missing_shows_policy_limit_reason() -> None:
    """Политика, пропущенная сборщиком по лимиту, приходит с `errors == ["лимит политик"]`."""
    raw = build_export()
    raw["policy_contents"]["3"] = {"product": "KES", "version": "12.0.0.0", "sections": {}, "errors": ["лимит политик"]}
    f = _run(check_policy_content_missing, raw)
    assert [(x.target, x.details["case"], x.details["reason"]) for x in f] == [("KES lab", "empty", "лимит политик")]


def test_check_policy_content_missing_fires_when_section_present_but_policy_absent() -> None:
    raw = build_export()
    del raw["policy_contents"]["3"]
    f = _run(check_policy_content_missing, raw)
    assert {x.target for x in f} == {"KES lab"}
    assert f[0].severity == "Info" and f[0].key_extra == "3" and f[0].details["group"] == "Managed devices/Workstations/Lab"
    # с содержимым по-прежнему не сообщается
    assert "KES workstations" not in {x.target for x in f}


def test_check_policy_content_missing_silent_when_present_for_all_active() -> None:
    assert not _run(check_policy_content_missing)


def test_policy_content_checks_silent_on_old_file_without_section() -> None:
    """Файл без секции `policy_contents` вовсе (старый сборщик) — все три проверки молчат,
    включая `POLICY_CONTENT_MISSING` (её нельзя отличить от «секция есть, но пуста»)."""
    raw = build_export()
    del raw["policy_contents"]
    idx = _idx(raw)
    cfg = KscConfig()
    assert not check_policy_no_locks(idx, cfg)
    assert not check_policy_weak_locks(idx, cfg)
    assert not check_policy_content_missing(idx, cfg)


def test_check_policy_content_missing_fires_when_all_sections_failed() -> None:
    """Политика присутствует в `policy_contents`, но все секции не прочитались (`sections == {}`,
    `errors` непусто) — та же «данных нет» ситуация, что и полное отсутствие политики в секции."""
    raw = build_export()
    raw["policy_contents"]["1"]["sections"] = {}
    raw["policy_contents"]["1"]["errors"] = ["KLPRSS_Basic: boom"]
    idx = _idx(raw)
    cfg = KscConfig()
    missing = check_policy_content_missing(idx, cfg)
    assert {x.target for x in missing} == {"KES workstations"}
    finding = next(x for x in missing if x.target == "KES workstations")
    assert finding.key_extra == "1" and finding.details["case"] == "empty" and finding.details["reason"] == "KLPRSS_Basic: boom"
    assert not [x for x in check_policy_no_locks(idx, cfg) if x.target == "KES workstations"]


def test_check_policy_content_missing_distinguishes_missing_from_empty_case() -> None:
    raw = build_export()
    raw["policy_contents"]["1"]["sections"] = {}
    raw["policy_contents"]["1"]["errors"] = []
    del raw["policy_contents"]["3"]
    missing = _run(check_policy_content_missing, raw)
    by_target = {x.target: x for x in missing}
    assert by_target["KES workstations"].details["case"] == "empty" and by_target["KES workstations"].details["reason"] == ""
    assert by_target["KES lab"].details["case"] == "missing"


def test_registry_has_three_policy_content_checks() -> None:
    for code, severity in (("POLICY_NO_LOCKS", "High"), ("POLICY_WEAK_LOCKS", "Medium"), ("POLICY_CONTENT_MISSING", "Info")):
        spec = CHECK_BY_CODE[code]
        assert spec.title and spec.description
        f = spec.func(_idx(), KscConfig(policy_lock_share=0.99))
        assert all(x.severity == severity for x in f) or not f


def test_flat_settings_descends_into_dict_values() -> None:
    """Значение-словарь контейнера раскрывается до листьев с полным путём и замком контейнера; списки и пустые словари —
    листья; `walk_settings` по-прежнему отдаёт контейнеры."""
    container = {"KLPRSS_Val": {"a": {"b": 1, "c": [{"x": 1}], "d": {}}, "e": "s"}, "KLPRSS_Mnd": True,
                 "KLPRSS_ValLck": True, "KLPRSS_ValLckPolicy": "root", "KLPRSS_ValLckGroup": "g"}
    sections = {"S": {"top": container, "plain": {"leaf": {"KLPRSS_Val": False, "KLPRSS_Mnd": False}}}, "W": container}
    assert [(s.section, s.path) for s in walk_settings(sections)] == [("S", "top"), ("S", "plain.leaf"), ("W", "")]
    flat = flat_settings(sections)
    assert [(s.section, s.path, s.value) for s in flat] == [
        ("S", "top.a.b", 1), ("S", "top.a.c", [{"x": 1}]), ("S", "top.a.d", {}), ("S", "top.e", "s"), ("S", "plain.leaf", False),
        ("W", "a.b", 1), ("W", "a.c", [{"x": 1}]), ("W", "a.d", {}), ("W", "e", "s"),
    ]
    top_b = flat[0]
    assert (top_b.locked, top_b.inherited_lock, top_b.lock_from) == (True, True, "root (g)")
    assert flat[4].locked is False

