"""Миграция A ролей и групп: настоящий прогон alembic на отдельной базе —
upgrade, сверка перенесённого из app_user.role и OIDC group_roles, downgrade."""
from __future__ import annotations

import json
import uuid
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.engine import make_url

from tests.conftest import BACKEND_DIR

BEFORE = "8aacd2621120"

GROUP_ROLES = [
    {"group": "fam-admins", "role": "admin"},
    {"group": "Аналитики", "role": "analyst"},
    {"group": "fam-dup", "role": "auditor"},
    {"group": "fam-dup", "role": "analyst"},
]


@pytest.fixture
def scratch(postgres_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Engine, Config]]:
    """Пустая база рядом с тестовой; alembic смотрит в неё через STOOLS_DATABASE_URL."""
    name = f"stools_mig_{uuid.uuid4().hex[:8]}"
    admin = create_engine(postgres_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    url = make_url(postgres_url).set(database=name).render_as_string(hide_password=False)
    monkeypatch.setenv("STOOLS_DATABASE_URL", url)
    engine = create_engine(url)
    try:
        yield engine, Config(str(BACKEND_DIR / "alembic.ini"))
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _rows(engine: Engine, sql: str) -> list[tuple[object, ...]]:
    with engine.connect() as conn:
        return [tuple(r) for r in conn.execute(text(sql)).all()]


def test_roles_groups_and_membership_move_and_come_back(scratch: tuple[Engine, Config]) -> None:
    engine, cfg = scratch
    command.upgrade(cfg, BEFORE)
    with engine.begin() as conn:
        for login, role in (("adm", "admin"), ("ana", "analyst"), ("aud", "auditor")):
            conn.execute(text(
                "INSERT INTO app_user (login, role, is_active, auth_source, created_at) "
                "VALUES (:l, :r, true, 'local', now())"
            ), {"l": login, "r": role})
        conn.execute(text("INSERT INTO app_setting (key, value_json, updated_at) VALUES ('oidc', :v, now())"), {
            "v": json.dumps({"enabled": True, "client_id": "c", "group_roles": GROUP_ROLES}, ensure_ascii=False),
        })

    command.upgrade(cfg, "head")
    assert {"access_role", "access_role_level", "access_group", "access_membership"} <= set(inspect(engine).get_table_names())

    assert _rows(engine, "SELECT name, builtin FROM access_role ORDER BY name") == [
        ("Администратор", True), ("Аналитик", True), ("Аудитор", True),
    ]
    assert _rows(engine, "SELECT count(*) FROM access_role_level") == [(24,)]
    assert _rows(engine, (
        "SELECT r.name, l.area, l.level FROM access_role_level l JOIN access_role r ON r.id = l.role_id "
        "WHERE l.area IN ('platform', 'toolbox') ORDER BY r.name, l.area"
    )) == [
        ("Администратор", "platform", "admin"), ("Администратор", "toolbox", "admin"),
        ("Аналитик", "platform", "deny"), ("Аналитик", "toolbox", "write"),
        ("Аудитор", "platform", "deny"), ("Аудитор", "toolbox", "read"),
    ]
    assert _rows(engine, (
        "SELECT g.name, g.source, g.external_name, r.name FROM access_group g "
        "JOIN access_role r ON r.id = g.role_id ORDER BY g.id"
    )) == [
        ("Администраторы", "local", None, "Администратор"),
        ("Аналитики", "local", None, "Аналитик"),
        ("Аудиторы", "local", None, "Аудитор"),
        ("fam-admins", "oidc", "fam-admins", "Администратор"),
        ("Аналитики (OIDC)", "oidc", "Аналитики", "Аналитик"),
        ("fam-dup", "oidc", "fam-dup", "Аналитик"),  # дубль пары: берётся широчайшая роль
    ]
    assert _rows(engine, (
        "SELECT u.login, g.name FROM access_membership m JOIN app_user u ON u.id = m.user_id "
        "JOIN access_group g ON g.id = m.group_id ORDER BY u.login"
    )) == [("adm", "Администраторы"), ("ana", "Аналитики"), ("aud", "Аудиторы")]
    settings = json.loads(str(_rows(engine, "SELECT value_json FROM app_setting WHERE key = 'oidc'")[0][0]))
    assert "group_roles" not in settings and settings["client_id"] == "c"
    # Миграция A колонку app_user.role не трогает.
    assert {c["name"] for c in inspect(engine).get_columns("app_user")} >= {"role"}

    # Откат считает старую роль по максимуму из групп; у пользователя без групп роль не меняется.
    with engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO app_user (login, role, is_active, auth_source, created_at) "
            "VALUES ('alone', 'admin', true, 'local', now())"
        ))
        conn.execute(text(
            "INSERT INTO access_membership (user_id, group_id) "
            "SELECT u.id, g.id FROM app_user u, access_group g WHERE u.login = 'aud' AND g.name = 'fam-admins'"
        ))
        conn.execute(text("UPDATE app_user SET role = 'auditor'"))

    command.downgrade(cfg, BEFORE)
    assert not {"access_role", "access_group", "access_membership"} & set(inspect(engine).get_table_names())
    assert _rows(engine, "SELECT login, role FROM app_user ORDER BY login") == [
        ("adm", "admin"), ("alone", "auditor"), ("ana", "analyst"), ("aud", "admin"),
    ]
    restored = json.loads(str(_rows(engine, "SELECT value_json FROM app_setting WHERE key = 'oidc'")[0][0]))
    assert sorted((p["group"], p["role"]) for p in restored["group_roles"]) == [
        ("fam-admins", "admin"), ("fam-dup", "analyst"), ("Аналитики", "analyst"),
    ]
