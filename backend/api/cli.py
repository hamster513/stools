"""CLI администрирования: создание первого пользователя.

Пароль запрашивается интерактивно (`getpass`), а не аргументом командной
строки — аргумент попадает в историю оболочки и в вывод `ps`.
"""
from __future__ import annotations

import getpass

import typer

from api.db.base import get_sessionmaker
from api.db.models import ROLE_ADMIN, ROLE_ANALYST, ROLES, AppUser
from api.security import hash_password

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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
