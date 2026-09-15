import json
import re
from collections.abc import Callable
from pathlib import Path

from typer.testing import CliRunner

from kbaudit.cli import app
from kbaudit.profile import Profile, TableRoles, save_profile

runner = CliRunner()

U1 = "000ffb49-bb9e-4ee4-9262-6754b7ee28d2"
CO = 'filter { msgid == "4688" and event_src.host == "host31.corp.internal" }'


def archive(synthetic_zip: Callable[..., Path]) -> Path:
    return synthetic_zip({
        "taxonomy.json": json.dumps({"msgid": {}, "event_src.host": {}}),
        f"correlation-rules/rules/correlation/{U1}/metainfo.yaml": "Origin: Local\n",
        f"correlation-rules/rules/correlation/{U1}/DEMO_HC_002_029_Impacket.co": CO,
    })


def test_stats_prints_counts(synthetic_zip: Callable[..., Path]) -> None:
    result = runner.invoke(app, ["stats", str(archive(synthetic_zip))])
    assert result.exit_code == 0
    assert "правил: 1" in result.stdout


def test_stats_json_is_machine_readable(synthetic_zip: Callable[..., Path]) -> None:
    result = runner.invoke(app, ["stats", str(archive(synthetic_zip)), "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["rule_count"] == 1


def test_findings_hides_values_unless_asked(synthetic_zip: Callable[..., Path]) -> None:
    result = runner.invoke(app, ["findings", str(archive(synthetic_zip))])
    assert result.exit_code == 0
    assert "host31.corp.internal" not in result.stdout, "значения по умолчанию скрыты"

    shown = runner.invoke(
        app, ["findings", str(archive(synthetic_zip)), "--show-values"]
    )
    assert "host31.corp.internal" in shown.stdout


def test_missing_file_exits_with_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["stats", str(tmp_path / "нет.zip")])
    assert result.exit_code != 0


def test_stats_distinguishes_missing_empty_and_populated_tables(
    synthetic_zip: Callable[..., Path],
) -> None:
    """Три состояния критичного списка обязаны читаться как три разные вещи:
    списка нет в выгрузке вовсе, список есть но пуст, список есть и наполнен.

    Какие списки критичны, задаёт профиль инсталляции: имён вендора
    в коде больше нет.
    """
    watched = Profile(
        tables=TableRoles(
            watched=["DEMO_User_Authentications", "DEMO_Critical_Hosts_by_Rule"]
        )
    )
    empty_archive = archive(synthetic_zip)
    profile_path = empty_archive.parent / "watched.yaml"
    save_profile(watched, profile_path)

    missing = runner.invoke(
        app, ["stats", str(empty_archive), "--profile", str(profile_path)]
    )
    assert "DEMO_User_Authentications: СПИСКА НЕТ В ВЫГРУЗКЕ" in missing.stdout
    assert "DEMO_Critical_Hosts_by_Rule: СПИСКА НЕТ В ВЫГРУЗКЕ" in missing.stdout

    mixed = synthetic_zip({
        "taxonomy.json": json.dumps({"msgid": {}, "event_src.host": {}}),
        f"correlation-rules/rules/correlation/{U1}/metainfo.yaml": "Origin: Local\n",
        f"correlation-rules/rules/correlation/{U1}/DEMO_HC_002_029_Impacket.co": CO,
        "correlation_defaults.json": json.dumps({
            "DEMO_User_Authentications": {"rows": []},
            "DEMO_Critical_Hosts_by_Rule": {"rows": [["srv99"]]},
        }),
    })
    result = runner.invoke(app, ["stats", str(mixed), "--profile", str(profile_path)])
    assert result.exit_code == 0
    assert "DEMO_User_Authentications: список есть, но ПУСТ" in result.stdout
    assert "DEMO_Critical_Hosts_by_Rule: 1 значений" in result.stdout

    # три состояния — это три разные строки, а не оттенки одной
    assert len({
        "СПИСКА НЕТ В ВЫГРУЗКЕ",
        "список есть, но ПУСТ",
        "1 значений",
    }) == 3


def test_divergence_command_hides_values(synthetic_zip: Callable[..., Path]) -> None:
    members = {
        "taxonomy.json": json.dumps({"src.host": {}}),
        f"correlation-rules/rules/correlation/{U1}/metainfo.yaml": "Origin: Local\n",
        f"correlation-rules/rules/correlation/{U1}/R.co": 'src.host == "srv01"',
        "correlation_defaults.json": json.dumps({"DEMO_Hosts": {"rows": [["srv01"]]}}),
    }
    path = synthetic_zip(members)
    result = runner.invoke(app, ["divergence", str(path)])
    assert result.exit_code == 0
    assert "DEMO_Hosts" in result.stdout
    assert "srv01" not in result.stdout


def test_stats_json_hides_divergence_values(synthetic_zip: Callable[..., Path]) -> None:
    """stats --json — машиночитаемая сводка, а не дамп инвентаря: значение
    расхождения не должно утекать вместе со счётчиками (ТЗ §9)."""
    members = {
        "taxonomy.json": json.dumps({"src.host": {}}),
        f"correlation-rules/rules/correlation/{U1}/metainfo.yaml": "Origin: Local\n",
        f"correlation-rules/rules/correlation/{U1}/R.co": 'src.host == "srv01"',
        "correlation_defaults.json": json.dumps({"DEMO_Hosts": {"rows": [["srv01"]]}}),
    }
    path = synthetic_zip(members)
    result = runner.invoke(app, ["stats", str(path), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["divergence_count"] == 1, "счётчик — часть сводки, остаётся"
    assert "divergences" not in payload, "сам список расхождений в сводке лишний"
    assert "srv01" not in result.stdout


def test_divergence_shows_field_and_distinguishes_same_looking_rows(
    synthetic_zip: Callable[..., Path],
) -> None:
    """Одно правило, одно поле, один список — но два разных хардкода. Без
    поля и различителя эти две находки в выводе неотличимы, хотя это не
    повтор одной строки, а два разных расхождения."""
    members = {
        "taxonomy.json": json.dumps({"src.host": {}}),
        f"correlation-rules/rules/correlation/{U1}/metainfo.yaml": "Origin: Local\n",
        f"correlation-rules/rules/correlation/{U1}/R.co": (
            'src.host == "srv01" or src.host == "srv02"'
        ),
        "correlation_defaults.json": json.dumps(
            {"DEMO_Hosts": {"rows": [["srv01"], ["srv02"]]}}
        ),
    }
    path = synthetic_zip(members)

    hidden = runner.invoke(app, ["divergence", str(path)])
    assert hidden.exit_code == 0
    rows = [line for line in hidden.stdout.splitlines() if line.startswith("DEMO_Hosts")]
    assert len(rows) == 2
    assert all("src.host" in row for row in rows), "поле находки должно быть в выводе"
    assert rows[0] != rows[1], "разные значения не должны давать одинаковую строку"
    assert "srv01" not in hidden.stdout
    assert "srv02" not in hidden.stdout

    shown = runner.invoke(app, ["divergence", str(path), "--show-values"])
    assert "srv01" in shown.stdout
    assert "srv02" in shown.stdout


def test_divergence_uses_opaque_sequential_numbers(
    synthetic_zip: Callable[..., Path],
) -> None:
    """Номер, а не хеш: одинаковые значения получают один и тот же номер,
    разные значения — разные номера, и по номеру значение не вычислить.
    Прежний sha256-отпечаток ловился словарной атакой на коротком словаре
    имён хостов без единой коллизии — проверено на реальной выгрузке."""
    u2 = "111ffb49-bb9e-4ee4-9262-6754b7ee28d2"
    members = {
        "taxonomy.json": json.dumps({"src.host": {}}),
        f"correlation-rules/rules/correlation/{U1}/metainfo.yaml": "Origin: Local\n",
        f"correlation-rules/rules/correlation/{U1}/R1.co": 'src.host == "srv01"',
        f"correlation-rules/rules/correlation/{u2}/metainfo.yaml": "Origin: Local\n",
        f"correlation-rules/rules/correlation/{u2}/R2.co": (
            'src.host == "srv01" or src.host == "srv02"'
        ),
        "correlation_defaults.json": json.dumps(
            {"DEMO_Hosts": {"rows": [["srv01"], ["srv02"]]}}
        ),
    }
    path = synthetic_zip(members)

    hidden = runner.invoke(app, ["divergence", str(path)])
    shown = runner.invoke(app, ["divergence", str(path), "--show-values"])
    assert hidden.exit_code == 0
    assert shown.exit_code == 0

    hidden_rows = [l for l in hidden.stdout.splitlines() if l.startswith("DEMO_Hosts")]
    shown_rows = [l for l in shown.stdout.splitlines() if l.startswith("DEMO_Hosts")]
    # два расхождения из-за srv01 (R1 и R2) плюс одно из-за srv02 (R2)
    assert len(hidden_rows) == len(shown_rows) == 3

    markers_of_value: dict[str, set[str]] = {"srv01": set(), "srv02": set()}
    for hidden_line, shown_line in zip(hidden_rows, shown_rows, strict=True):
        assert "srv01" not in hidden_line
        assert "srv02" not in hidden_line
        marker = re.search(r"<скрыто> #\d+", hidden_line)
        assert marker, "различитель обязан быть непрозрачным номером вида #N"
        value = "srv01" if "srv01" in shown_line else "srv02"
        markers_of_value[value].add(marker.group())

    assert len(markers_of_value["srv01"]) == 1, "одно и то же значение — один номер"
    assert len(markers_of_value["srv02"]) == 1, "одно и то же значение — один номер"
    assert markers_of_value["srv01"] != markers_of_value["srv02"], (
        "разные значения обязаны получать разные номера"
    )


def test_findings_uses_opaque_sequential_numbers(
    synthetic_zip: Callable[..., Path],
) -> None:
    """findings страдает той же неразличимостью строк, что divergence:
    несколько находок под общим плейсхолдером выглядят одинаково. Номер
    обязан быть тем же для одинакового значения и разным для разных, без
    вычислимой связи со значением."""
    body = 'src.ip == "10.0.0.1" and dst.ip == "10.0.0.1" and other.ip == "10.0.0.2"'
    members = {
        "taxonomy.json": json.dumps({"src.ip": {}, "dst.ip": {}, "other.ip": {}}),
        f"correlation-rules/rules/correlation/{U1}/metainfo.yaml": "Origin: Local\n",
        f"correlation-rules/rules/correlation/{U1}/R.co": body,
    }
    path = synthetic_zip(members)

    hidden = runner.invoke(app, ["findings", str(path)])
    shown = runner.invoke(app, ["findings", str(path), "--show-values"])
    assert hidden.exit_code == 0
    assert shown.exit_code == 0

    hidden_rows = [l for l in hidden.stdout.splitlines() if l.split()[:1] == ["2"]]
    shown_rows = [l for l in shown.stdout.splitlines() if l.split()[:1] == ["2"]]
    assert len(hidden_rows) == len(shown_rows) == 3

    markers_of_value: dict[str, set[str]] = {"10.0.0.1": set(), "10.0.0.2": set()}
    for hidden_line, shown_line in zip(hidden_rows, shown_rows, strict=True):
        assert "10.0.0.1" not in hidden_line
        assert "10.0.0.2" not in hidden_line
        marker = re.search(r"<скрыто> #\d+", hidden_line)
        assert marker, "различитель обязан быть непрозрачным номером вида #N"
        value = "10.0.0.1" if "10.0.0.1" in shown_line else "10.0.0.2"
        markers_of_value[value].add(marker.group())

    assert len(markers_of_value["10.0.0.1"]) == 1, "одно и то же значение — один номер"
    assert len(markers_of_value["10.0.0.2"]) == 1, "одно и то же значение — один номер"
    assert markers_of_value["10.0.0.1"] != markers_of_value["10.0.0.2"], (
        "разные значения обязаны получать разные номера"
    )


def test_divergence_marker_depends_on_order_not_on_value_content(
    synthetic_zip: Callable[..., Path],
) -> None:
    """Ловит контрпример, который формат `#\\d+` и корреляция «одно
    значение — один маркер» не ловят: `#{int(sha256(value).hexdigest(), 16)}`
    тоже уникален на значение, тоже стабилен для повторов значения — но
    вычисляется из содержимого, а значит восстановим словарной атакой в
    точности как прежний укороченный отпечаток.

    Проверка: два архива одинаковой структуры (два расхождения на одно
    правило), но с совершенно разными значениями. Порядковая нумерация
    зависит только от того, каким по счёту встретилось значение — поэтому
    обязана дать одну и ту же последовательность маркеров (#1, #2) в обоих
    архивах. Любая схема, вычисляющая маркер из содержимого значения, на
    разных значениях почти наверняка даст разные (и не похожие на #1/#2)
    маркеры — именно так контрпример себя выдаёт."""

    def build(value_a: str, value_b: str, name: str) -> Path:
        members = {
            "taxonomy.json": json.dumps({"src.host": {}}),
            f"correlation-rules/rules/correlation/{U1}/metainfo.yaml": "Origin: Local\n",
            f"correlation-rules/rules/correlation/{U1}/R.co": (
                f'src.host == "{value_a}" or src.host == "{value_b}"'
            ),
            "correlation_defaults.json": json.dumps(
                {"DEMO_Hosts": {"rows": [[value_a], [value_b]]}}
            ),
        }
        return synthetic_zip(members, name=name)

    path_a = build("srv01", "srv02", "a.zip")
    path_b = build("completely-unrelated-host-9000", "another-value-entirely-42", "b.zip")

    result_a = runner.invoke(app, ["divergence", str(path_a)])
    result_b = runner.invoke(app, ["divergence", str(path_b)])
    assert result_a.exit_code == 0
    assert result_b.exit_code == 0

    markers_a = re.findall(r"<скрыто> (#\d+)", result_a.stdout)
    markers_b = re.findall(r"<скрыто> (#\d+)", result_b.stdout)
    assert markers_a == markers_b == ["#1", "#2"], (
        "маркер обязан определяться порядком появления значения в выводе, "
        "а не содержимым самого значения: при одинаковой структуре архива "
        "и заведомо разных значениях последовательность номеров должна "
        f"совпадать буквально ({markers_a!r} vs {markers_b!r})"
    )


def test_findings_marker_depends_on_order_not_on_value_content(
    synthetic_zip: Callable[..., Path],
) -> None:
    """Тот же контрпример (маркер, вычисленный из значения, а не из
    порядка появления), но для команды findings — у неё отдельная
    нумерация, и её тоже нужно защитить от той же дыры."""

    def build(value_a: str, value_b: str, name: str) -> Path:
        body = f'src.ip == "{value_a}" and dst.ip == "{value_b}"'
        members = {
            "taxonomy.json": json.dumps({"src.ip": {}, "dst.ip": {}}),
            f"correlation-rules/rules/correlation/{U1}/metainfo.yaml": "Origin: Local\n",
            f"correlation-rules/rules/correlation/{U1}/R.co": body,
        }
        return synthetic_zip(members, name=name)

    path_a = build("10.0.0.1", "10.0.0.2", "a.zip")
    path_b = build("172.16.5.9", "203.0.113.77", "b.zip")

    result_a = runner.invoke(app, ["findings", str(path_a)])
    result_b = runner.invoke(app, ["findings", str(path_b)])
    assert result_a.exit_code == 0
    assert result_b.exit_code == 0

    markers_a = re.findall(r"<скрыто> (#\d+)", result_a.stdout)
    markers_b = re.findall(r"<скрыто> (#\d+)", result_b.stdout)
    assert markers_a == markers_b == ["#1", "#2"], (
        "маркер обязан определяться порядком появления значения в выводе, "
        "а не содержимым самого значения: при одинаковой структуре архива "
        "и заведомо разных значениях последовательность номеров должна "
        f"совпадать буквально ({markers_a!r} vs {markers_b!r})"
    )
