"""Профиль инсталляции: решения человека о конкретной выгрузке."""
from pathlib import Path

from kbaudit.profile import (
    FieldRoles,
    Profile,
    TableRoles,
    detect_profile,
    load_profile,
    save_profile,
)


def test_missing_file_gives_empty_profile(tmp_path: Path) -> None:
    """Инструмент обязан работать без настройки: после ухода вендора
    настраивать его некому, а выгрузку разбирать надо."""
    profile = load_profile(tmp_path / "нет-такого.yaml")
    assert profile.name_scheme is None
    assert profile.tables.scoping == []
    assert profile.is_confirmed is False


def test_broken_file_does_not_crash(tmp_path: Path) -> None:
    path = tmp_path / "p.yaml"
    path.write_text("это не отображение, а строка", encoding="utf-8")
    assert load_profile(path).tables.watched == []


def test_round_trip_preserves_decisions(tmp_path: Path) -> None:
    original = Profile(
        tables=TableRoles(scoping=["Hosts"], watched=["Hosts", "Auth"]),
        builtin_accounts=["служебная запись"],
        field_roles=FieldRoles(environmental=["custom.host"]),
        confirmed_by="analyst",
    )
    path = tmp_path / "p.yaml"
    save_profile(original, path)
    restored = load_profile(path)

    assert restored.tables.scoping == ["Hosts"]
    assert restored.tables.watched == ["Hosts", "Auth"]
    assert restored.builtin_accounts == ["служебная запись"]
    assert restored.field_roles.environmental == ["custom.host"]
    assert restored.is_confirmed is True


def test_saved_profile_is_readable_by_a_human(tmp_path: Path) -> None:
    """Профиль правят руками, поэтому кириллица не должна экранироваться."""
    path = tmp_path / "p.yaml"
    save_profile(Profile(builtin_accounts=["система"]), path)
    assert "система" in path.read_text(encoding="utf-8")


def test_detect_fills_only_what_data_can_tell(tmp_path: Path) -> None:
    """Схема имён выводится из данных. Роли списков — нет: в теле правила
    чтение списка и ограничение им выглядят одинаково, и различить их
    может только человек."""
    names = [f"ACME_{c}_{i:03d}_Rule_Text" for c in ("AA", "BB") for i in range(6)]
    draft = detect_profile(names)

    assert draft.name_scheme is not None
    assert draft.name_scheme.group_count == 2
    assert draft.tables.scoping == []
    assert draft.tables.watched == []
    assert draft.is_confirmed is False


def test_detect_on_unstructured_names_yields_no_scheme() -> None:
    assert detect_profile(["alpha", "beta"]).name_scheme is None
