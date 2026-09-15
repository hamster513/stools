"""CLI: анализ выгрузки без базы, HTTP и сети."""
from __future__ import annotations

import json
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer

from kbaudit.parsers.snapshot import parse_archive
from kbaudit.profile import Profile, detect_profile, load_profile, save_profile
from kbaudit.report import AuditReport, build_report

#: Профиль инсталляции ищется рядом с выгрузкой под этим именем.
DEFAULT_PROFILE_NAME = "kbaudit.profile.yaml"

app = typer.Typer(help="KB Auditor — анализатор базы знаний MP SIEM", no_args_is_help=True)

#: Значения находок — это адреса, имена хостов и учётки. По умолчанию скрыты.
VALUE_PLACEHOLDER = "<скрыто>"


def _numbering() -> Callable[[str], str]:
    """Непрозрачный порядковый номер значения в пределах одного вывода команды.

    Одного плейсхолдера недостаточно: у одного правила несколько находок в
    одном и том же поле и списке отличаются только значением, а его прячут —
    без различителя такие строки выглядят как повтор одной и той же находки.

    Хеш здесь не годится: на коротком, предсказуемо устроенном словаре
    значений (имена хостов и учёток по фиксированным шаблонам, адреса в
    известных подсетях) отпечаток восстанавливается словарной атакой без
    коллизий — проверено на реальной выгрузке. Порядковый номер с значением
    не связан никаким вычислимым отношением: одинаковые значения получают
    один номер, разные — разные, но по номеру значение не восстановить.
    Нумерация не переживает вызов — счётчик заводится заново на каждый
    запуск команды.
    """
    numbers: dict[str, int] = {}

    def mark(value: str) -> str:
        number = numbers.setdefault(value, len(numbers) + 1)
        return f"{VALUE_PLACEHOLDER} #{number}"

    return mark


def _profile_path(archive: Path, explicit: Path | None) -> Path:
    return explicit if explicit else archive.parent / DEFAULT_PROFILE_NAME


def _load(path: Path, profile_path: Path | None = None) -> AuditReport:
    if not path.is_file():
        typer.secho(f"файл не найден: {path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    try:
        parsed = parse_archive(path)
    except zipfile.BadZipFile:
        typer.secho(f"это не zip-архив: {path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from None
    return build_report(parsed, load_profile(_profile_path(path, profile_path)))


@app.command()
def stats(
    archive: Path,
    as_json: Annotated[bool, typer.Option("--json", help="машиночитаемый вывод")] = False,
    profile: Annotated[
        Path | None, typer.Option(help="профиль инсталляции (по умолчанию рядом с архивом)")
    ] = None,
) -> None:
    """Сводка по выгрузке."""
    report = _load(archive, profile)
    if as_json:
        typer.echo(
            report.model_dump_json(
                exclude={"findings", "rules", "catalog", "divergences"}, indent=2
            )
        )
        return

    typer.echo(f"правил: {report.rule_count}")
    typer.echo(f"групп каталога: {report.group_count}")
    typer.echo(f"без распознанного кода: {report.rules_without_code}")
    typer.echo(f"неразобранных тел: {report.unsupported_count}")
    typer.echo(f"рёбер графа: {report.edge_count}")
    typer.echo(f"ограничены списками: {report.scoped_count}")
    typer.echo(f"клонов: {report.clone_count}")
    typer.echo(f"\nнаходок: {report.finding_count}")
    for kind, count in report.findings_by_kind.items():
        typer.echo(f"  класс {kind}: {count}")
    for polarity, count in report.findings_by_polarity.items():
        typer.echo(f"  {polarity}: {count}")

    scheme = report.name_scheme_coverage
    mark = "подтверждена" if report.profile_confirmed else "определена автоматически"
    typer.echo(f"\nсхема именования: {scheme or 'структуры в именах не найдено'} ({mark})")

    if report.table_status:
        typer.echo("\nсостояние критичных списков:")
        rows = report.table_status
    else:
        typer.echo(
            "\nсписки по риску (профиль не заполнен — критичные не отмечены):"
        )
        rows = [r for r in report.table_ranking if r.risk][:10] or report.table_ranking[:5]

    for status in rows:
        if not status.exists:
            state = "СПИСКА НЕТ В ВЫГРУЗКЕ"
        elif status.is_empty:
            state = "список есть, но ПУСТ"
        else:
            state = f"{status.value_count} значений"
        typer.echo(f"  {status.name}: {state}, зависит правил: {status.dependant_count}")


@app.command()
def findings(
    archive: Path,
    show_values: Annotated[
        bool, typer.Option("--show-values", help="показать значения находок")
    ] = False,
    kind: Annotated[int | None, typer.Option(help="фильтр по классу 1..5")] = None,
    limit: Annotated[int, typer.Option(help="сколько строк показать")] = 40,
) -> None:
    """Список находок. Значения скрыты, пока их явно не попросят."""
    report = _load(archive)
    rows = [f for f in report.findings if kind is None or f.kind == kind]
    mark = _numbering()
    for finding in rows[:limit]:
        value = finding.value if show_values else mark(finding.value)
        typer.echo(
            f"{finding.kind}  {finding.object_name}  {finding.field}  "
            f"{finding.polarity}  {'в списке' if finding.in_table else '—'}  {value}"
        )
    typer.echo(f"\nпоказано {min(len(rows), limit)} из {len(rows)}")


@app.command()
def divergence(
    archive: Path,
    show_values: Annotated[
        bool, typer.Option("--show-values", help="показать значения")
    ] = False,
    limit: Annotated[int, typer.Option(help="сколько строк показать")] = 30,
) -> None:
    """Расхождения правило ↔ табличный список: где два источника истины."""
    report = _load(archive)
    mark = _numbering()
    for row in report.divergences[:limit]:
        value = row.value if show_values else mark(row.value)
        typer.echo(
            f"{row.table_name}  {row.field}  {value}  зашито в {row.hardcoded_in}  "
            f"затронет правил: {row.blast_radius}"
        )
    typer.echo(f"\nвсего расхождений: {report.divergence_count}")


@app.command()
def verify(
    archive: Path,
    expected: Annotated[Path, typer.Option(help="JSON с эталонными числами")],
) -> None:
    """Сверка с эталонными числами. Расхождение — ненулевой код возврата."""
    report = _load(archive)
    reference = json.loads(expected.read_text(encoding="utf-8"))
    actual = report.model_dump(mode="json")

    mismatches = {
        key: (value, actual.get(key))
        for key, value in reference.items()
        if actual.get(key) != value
    }
    for key, (want, got) in mismatches.items():
        typer.secho(f"{key}: ожидалось {want}, получено {got}", fg=typer.colors.RED)
    if mismatches:
        raise typer.Exit(code=1)
    typer.secho(f"совпало проверок: {len(reference)}", fg=typer.colors.GREEN)


@app.command()
def profile(
    archive: Path,
    write: Annotated[
        bool, typer.Option("--write", help="записать черновик профиля рядом с архивом")
    ] = False,
    out: Annotated[Path | None, typer.Option(help="куда записать профиль")] = None,
) -> None:
    """Определить схему именования и предложить профиль инсталляции.

    Инструмент выводит из данных то, что может: как устроены имена правил
    и какие списки рискованны. Чего вывести нельзя — какие списки сужают
    область действия правила, — остаётся человеку: в теле правила чтение
    списка и ограничение списком выглядят одинаково.
    """
    if not archive.is_file():
        typer.secho(f"файл не найден: {archive}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    try:
        parsed = parse_archive(archive)
    except zipfile.BadZipFile:
        typer.secho(f"это не zip-архив: {archive}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from None

    draft: Profile = detect_profile([r.name for r in parsed.rules])
    scheme = draft.name_scheme
    if scheme is None:
        typer.echo("структуры в именах правил не найдено: каждое правило — своя группа")
    else:
        typer.echo(
            f"схема имён: разделитель {scheme.separator!r}, "
            f"покрытие {scheme.coverage}/{scheme.total}, групп {scheme.group_count}"
        )
        for stat in scheme.stats:
            role = stat.role or "свободный текст"
            typer.echo(
                f"  позиция {stat.position}: {role}, "
                f"различных {stat.distinct}, примеры {', '.join(stat.examples[:3])}"
            )

    report = build_report(parsed, draft)
    risky = [t for t in report.table_ranking if t.risk][:10]
    if risky:
        typer.echo("\nсписки, от которых зависят детекты (проверьте и отметьте):")
        for table in risky:
            state = "отсутствует" if not table.exists else "пуст"
            typer.echo(
                f"  {table.name}: {state}, зависит правил: {table.dependant_count}"
            )

    if write or out:
        target = out or archive.parent / DEFAULT_PROFILE_NAME
        save_profile(draft, target)
        typer.echo(f"\nчерновик записан: {target}")
        typer.echo("отметьте в нём ограничивающие списки и подтвердите схему")
