"""CLI администрирования: создание первого пользователя, перешифрование секретов,
снятие блокировки входа.

Пароль запрашивается интерактивно (`getpass`), а не аргументом командной
строки — аргумент попадает в историю оболочки и в вывод `ps`.
"""
from __future__ import annotations

import getpass
import json
from typing import Annotated

import typer
from sqlalchemy.orm import Session

from api.crypto import reseal
from api.db.base import get_sessionmaker
from api.db.models import AccessGroup, AccessMembership, AccessRole, AppSetting, AppUser
from api.platform.services.access import (
    BUILTIN_GROUPS,
    access_for_groups,
    active_platform_admins,
    allows,
    ensure_builtin,
)
from api.security import hash_password
from api.settings import get_settings

#: Группа по умолчанию: первому пользователю — полные права, чтобы было кому управлять.
FIRST_USER_GROUP = "Администраторы"
NEXT_USER_GROUP = "Аналитики"

app = typer.Typer(help="Администрирование STools API", no_args_is_help=True)


@app.callback()
def _callback() -> None:
    """Пустой callback нужен, чтобы Typer не «схлопнул» единственную команду
    в саму программу — иначе `python -m api.cli create-user login` перестал
    бы работать, как только команда осталась одна."""


@app.command("create-user")
def create_user(
    login: str,
    group: Annotated[list[str] | None, typer.Option("--group", help="имя локальной группы; можно повторять")] = None,
) -> None:
    """Создать пользователя. Пароль спрашивается дважды, в открытый вид
    нигде не попадает — ни в аргументы, ни в лог. Группа по умолчанию:
    «Администраторы» для первого пользователя, «Аналитики» для остальных.

    Это и выход, когда система осталась без администратора: удалённая
    встроенная группа заводится заново со своей встроенной ролью, а
    учётка без `platform = admin` в системе без администратора не
    создаётся — иначе выход молча не сработал бы."""
    session = get_sessionmaker()()
    try:
        #: CLI работает без старта API, где встроенные роли и группы заводятся.
        ensure_builtin(session)
        names = group or [FIRST_USER_GROUP if session.query(AppUser).count() == 0 else NEXT_USER_GROUP]
        _restore_builtin_groups(session, names)
        found = {
            g.name: g
            for g in session.query(AccessGroup).filter(AccessGroup.name.in_(names), AccessGroup.source == "local")
        }
        for name in names:
            if name not in found:
                typer.secho(f"неизвестная локальная группа: {name}", fg=typer.colors.RED, err=True)
                raise typer.Exit(code=1)
        if active_platform_admins(session) == 0 and not allows(
            access_for_groups(session, (g.id for g in found.values())), "platform", "admin",
        ):
            given = ", ".join(f"«{n}» (роль «{found[n].role.name}»)" for n in dict.fromkeys(names))
            typer.secho(
                f"в системе нет активного администратора платформы, а группы {given} не дают "
                "platform = admin — учётка не создана; укажите группу с ролью «Администратор»",
                fg=typer.colors.RED, err=True,
            )
            raise typer.Exit(code=1)
        password = getpass.getpass("пароль: ")
        confirm = getpass.getpass("повторите пароль: ")
        if password != confirm:
            typer.secho("пароли не совпадают", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        if not password:
            typer.secho("пустой пароль недопустим", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        if session.query(AppUser).filter_by(login=login).one_or_none() is not None:
            typer.secho(f"пользователь уже существует: {login}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        user = AppUser(login=login, password_hash=hash_password(password))
        session.add(user)
        session.flush()
        session.add_all(AccessMembership(user_id=user.id, group_id=found[n].id) for n in dict.fromkeys(names))
        session.commit()
        typer.secho(f"пользователь создан: {login} ({', '.join(dict.fromkeys(names))})", fg=typer.colors.GREEN)
    finally:
        session.close()


def _restore_builtin_groups(session: Session, names: list[str]) -> None:
    """Встроенная группа, которой нет, заводится заново со своей встроенной ролью.

    API встроенные группы не возвращает (владелец мог их удалить), но запрос
    группы по имени в CLI — явное действие оператора на сервере. Без коммита:
    группа сохраняется вместе с учёткой."""
    for name in dict.fromkeys(names):
        if name not in BUILTIN_GROUPS or session.query(AccessGroup).filter_by(name=name).count():
            continue
        role = session.query(AccessRole).filter_by(name=BUILTIN_GROUPS[name], builtin=True).one_or_none()
        if role is not None:
            session.add(AccessGroup(name=name, source="local", role_id=role.id))
    session.flush()


@app.command("reseal-secrets")
def reseal_secrets() -> None:
    """Зашифровать секреты, сохранённые открытым текстом до обновления:
    пароли подключений AD и KSC, API-токены MaxPatrol VM и базы знаний SIEM,
    секрет клиента OIDC. Уже зашифрованные не
    трогаются; значения не печатаются."""
    from api.modules.ad.models import AdConnection
    from api.modules.ksc.models import KscConnection

    if not get_settings().session_secret:
        typer.secho("STOOLS_SESSION_SECRET не задан — шифровать нечем", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    counts = {"ad": 0, "ksc": 0, "vm": 0, "siem_mp": 0, "oidc": 0}
    session = get_sessionmaker()()
    try:
        conns: list[tuple[str, AdConnection | KscConnection]] = [
            *(("ad", c) for c in session.query(AdConnection)),
            *(("ksc", c) for c in session.query(KscConnection)),
        ]
        for kind, conn in conns:
            sealed = reseal(conn.password)
            if sealed != conn.password:
                conn.password = sealed
                counts[kind] += 1
        #: Ключ настройки в app_setting, раздел JSON с секретами (None — корень), поля.
        for kind, section, fields in (
            ("vm", "connection", ("api_token",)),
            ("siem_mp", None, ("api_token",)),
            ("oidc", None, ("client_secret",)),
        ):
            row = session.get(AppSetting, kind)
            if row is None or not row.value_json:
                continue
            value = json.loads(row.value_json)
            holder = (value.get(section) or {}) if section else value
            before = counts[kind]
            for field in fields:
                sealed = reseal(holder.get(field) or "")
                if sealed != (holder.get(field) or ""):
                    holder[field] = sealed
                    counts[kind] += 1
            if counts[kind] != before:
                row.value_json = json.dumps(value, ensure_ascii=False)
        session.commit()
    finally:
        session.close()
    typer.echo(", ".join(f"{kind}: {n}" for kind, n in counts.items()))


@app.command("unlock-login")
def unlock_login(
    login: str | None = typer.Argument(None, help="логин, для которого снять блокировку"),
    ip: str | None = typer.Option(None, "--ip", help="адрес клиента, для которого снять блокировку"),
) -> None:
    """Снять блокировку входа: удалить из журнала неудачные входы за окно
    троттлинга (15 минут) для логина и/или адреса. Старые записи журнала и
    записи других логинов и адресов не трогаются."""
    from sqlalchemy import CursorResult, delete, or_

    from api.db.models import AuditEvent
    from api.routers.auth import counted_failures

    if not login and not ip:
        typer.secho("укажите логин или --ip", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    targets = [*([AuditEvent.login == login] if login else []), *([AuditEvent.ip == ip] if ip else [])]
    session = get_sessionmaker()()
    try:
        result = session.execute(delete(AuditEvent).where(*counted_failures(), or_(*targets)))
        session.commit()
    finally:
        session.close()
    deleted = result.rowcount if isinstance(result, CursorResult) else 0
    typer.echo(f"удалено неудачных входов: {deleted}")


@app.command("import-trivy-db")
def import_trivy_db() -> None:
    """Установить ZIP базы Trivy из стандартного ввода для автономной проверки SBOM."""
    import sys
    import tempfile
    import zipfile
    from pathlib import Path

    from api.limits import VM_UPLOAD
    from api.modules.vm.services.trivy_update import install

    data_dir = get_settings().data_dir
    data_dir.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.NamedTemporaryFile(dir=data_dir, suffix=".zip") as upload:
            while chunk := sys.stdin.buffer.read(1024**2):
                if upload.tell() + len(chunk) > VM_UPLOAD:
                    raise ValueError("ZIP базы Trivy превышает 500 МиБ")
                upload.write(chunk)
            upload.flush()
            result = install(Path(upload.name), data_dir)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    status = "уже используется" if result["duplicate"] else "установлена"
    typer.echo(f"База Trivy от {result['db_updated_at']} {status}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
