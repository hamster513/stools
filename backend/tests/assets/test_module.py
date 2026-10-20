"""Каркас модуля: роутер подключён, задачи читаются любой ролью."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.db.models import Base
from api.modules.assets.models import (
    Asset,
    AssetUser,
    AssetUserGroup,
    AssetUserHost,
    AssetUserObservation,
    AssetZone,
)


def test_jobs_list_is_empty_for_auditor(client_as: Callable[[str], TestClient]) -> None:
    response = client_as("auditor").get("/api/assets/jobs")
    assert response.status_code == 200, response.text
    assert response.json() == []


def test_jobs_require_session(client: TestClient) -> None:
    assert client.get("/api/assets/jobs").status_code == 401


def test_zone_reference_is_a_table(db_session: Session) -> None:
    """Справочник зон — таблица миграции; предустановленные строки очищает TRUNCATE
    между тестами, поэтому здесь проверяется только, что запись в неё работает."""
    db_session.add(AssetZone(name="Lab", title="Стенд", description=""))
    db_session.commit()
    assert db_session.get(AssetZone, "Lab") is not None


def test_user_tables_match_models(db_session: Session) -> None:
    """Таблицы пользователей из миграции совпадают с моделями."""
    ctx = MigrationContext.configure(db_session.connection(), opts={"compare_type": True, "compare_server_default": False})
    assert [d for d in compare_metadata(ctx, Base.metadata) if "asset_user" in repr(d)] == []


def test_user_cascades(db_session: Session) -> None:
    """Удаление хоста уносит только ссылки на него; удаление пользователя — всё его."""
    now = dt.datetime(2026, 10, 20, tzinfo=dt.UTC)
    host = Asset(name="WS01")
    user = AssetUser(sid="S-1-5-21-1111111111-2222222222-3333333333-1001", name_key="corp.local\\user01", sam="user01")
    db_session.add_all([host, user])
    db_session.flush()
    db_session.add_all([
        AssetUserObservation(user_id=user.id, source="ad", source_key=user.sid, seen_at=now),
        AssetUserHost(user_id=user.id, asset_id=host.id, source="ksc", kind="session", active=True, seen_at=now),
        AssetUserGroup(user_id=user.id, group_sid="S-1-5-21-1111111111-2222222222-3333333333-513",
                       group_name="CORP\\Domain Users", direct=True, source="ad"),
    ])
    db_session.commit()

    def count(model: type) -> int:
        return db_session.scalar(select(func.count()).select_from(model)) or 0

    db_session.delete(host)
    db_session.commit()
    assert (count(AssetUser), count(AssetUserHost), count(AssetUserObservation), count(AssetUserGroup)) == (1, 0, 1, 1)
    db_session.delete(user)
    db_session.commit()
    assert (count(AssetUserObservation), count(AssetUserGroup)) == (0, 0)


def test_one_live_user_per_sid(db_session: Session) -> None:
    """Пустой SID и слитая строка не мешают; второй живой пользователь с тем же SID — ошибка."""
    sid = "S-1-5-21-1111111111-2222222222-3333333333-1001"
    first = AssetUser(sid=sid, name_key="corp.local\\user01")
    db_session.add_all([first, AssetUser(sid="", name_key="local:1\\admin"), AssetUser(sid="", name_key="local:2\\admin")])
    db_session.flush()
    db_session.add(AssetUser(sid=sid, name_key="corp.local\\user01", merged_into=first.id))
    db_session.commit()
    db_session.add(AssetUser(sid=sid, name_key="corp.local\\user01"))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()
