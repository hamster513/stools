"""CLI администрирования: создание первого пользователя, перешифрование секретов,
снятие блокировки входа.

Пароль запрашивается интерактивно (`getpass`), а не аргументом командной
строки — аргумент попадает в историю оболочки и в вывод `ps`.
"""
from __future__ import annotations

import getpass
import json

import typer

from api.crypto import reseal
from api.db.base import get_sessionmaker
from api.db.models import ROLE_ADMIN, ROLE_ANALYST, ROLES, AppSetting, AppUser
from api.security import hash_password
from api.settings import get_settings

app = typer.Typer(help="Администрирование STools API", no_args_is_help=True)


@app.callback()
def _callback() -> None:
    """Пустой callback нужен, чтобы Typer не «схлопнул» единственную команду
    в саму программу — иначе `python -m api.cli create-user login` перестал
    бы работать, как только команда осталась одна."""


@app.command("create-user")
def create_user(
    login: str,
    role: str | None = typer.Option(None, "--role", help="admin | analyst | auditor"),
) -> None:
    """Создать пользователя. Пароль спрашивается дважды, в открытый вид
    нигде не попадает — ни в аргументы, ни в лог. Роль по умолчанию:
    admin для первого пользователя, analyst для остальных."""
    if role is not None and role not in ROLES:
        typer.secho(f"неизвестная роль: {role}; допустимы {', '.join(ROLES)}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    password = getpass.getpass("пароль: ")
    confirm = getpass.getpass("повторите пароль: ")
    if password != confirm:
        typer.secho("пароли не совпадают", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    if not password:
        typer.secho("пустой пароль недопустим", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    session = get_sessionmaker()()
    try:
        if session.query(AppUser).filter_by(login=login).one_or_none() is not None:
            typer.secho(f"пользователь уже существует: {login}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        if role is None:
            role = ROLE_ADMIN if session.query(AppUser).count() == 0 else ROLE_ANALYST
        user = AppUser(login=login, password_hash=hash_password(password), role=role)
        session.add(user)
        session.commit()
        typer.secho(f"пользователь создан: {login} ({role})", fg=typer.colors.GREEN)
    finally:
        session.close()


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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
