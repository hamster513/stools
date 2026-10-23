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
    AssetGroup,
    AssetGroupMember,
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


def test_group_tables_match_models(db_session: Session) -> None:
    """Таблицы групп из миграции совпадают с моделями."""
    ctx = MigrationContext.configure(db_session.connection(), opts={"compare_type": True, "compare_server_default": False})
    assert [d for d in compare_metadata(ctx, Base.metadata) if "asset_group" in repr(d)] == []


def test_group_member_indexes(db_session: Session) -> None:
    """Ссылки `SET NULL` (пользователь, актив) — с индексами; отдельного по `group_id` нет: его ведёт уникальный."""
    from sqlalchemy import inspect

    insp = inspect(db_session.connection())
    indexes = {ix["name"]: ix["column_names"] for ix in insp.get_indexes("asset_group_member")}
    assert indexes.pop("uq_asset_group_member")[0] == "group_id"
    assert indexes == {
        "ix_asset_group_member_member_group_id": ["member_group_id"],
        "ix_asset_group_member_user_id": ["user_id"],
        "ix_asset_group_member_asset_id": ["asset_id"],
    }
    columns = {c["name"]: c for c in insp.get_columns("asset_group")}
    assert columns["group_key"]["type"].length == 800 and columns["os_family"]["type"].length == 8
    assert columns["members_direct"]["nullable"] is False


def test_list_and_delete_indexes(db_session: Session) -> None:
    """Страница групп — индекс по `lower(name)`; удаление пользователя — индекс самоссылки `merged_into`."""
    from sqlalchemy import text

    defs = dict(db_session.execute(text(
        "SELECT indexname, indexdef FROM pg_indexes WHERE indexname IN ('ix_asset_group_name_lower', 'ix_asset_user_merged_into')"
    )).tuples().all())
    assert "lower((name)::text)" in defs["ix_asset_group_name_lower"]
    assert defs["ix_asset_user_merged_into"].endswith("(merged_into)")


def test_group_cascades(db_session: Session) -> None:
    """Удаление хоста уносит его локальные группы с составом; удаление участника лишь рвёт ссылку."""
    host, member_host = Asset(name="WS01"), Asset(name="SRV01")
    user = AssetUser(sid="S-1-5-21-1111111111-2222222222-3333333333-1001", name_key="corp.local\\user01")
    db_session.add_all([host, member_host, user])
    db_session.flush()
    domain = AssetGroup(group_key="d:corp.local:n:helpdesk", name="helpdesk", domain="corp.local", sources=["ad"])
    local = AssetGroup(group_key=f"l:{host.id}:S-1-5-32-544", sid="S-1-5-32-544", name="administrators",
                       local=True, host_asset_id=host.id, sources=["vm"])
    db_session.add_all([domain, local])
    db_session.flush()
    db_session.add_all([
        AssetGroupMember(group_id=domain.id, member_kind="user", user_id=user.id, member_name="user01", source="ad"),
        AssetGroupMember(group_id=domain.id, member_kind="computer", asset_id=member_host.id,
                         member_name="srv01$", source="ad"),
        AssetGroupMember(group_id=local.id, member_kind="group", member_group_id=domain.id,
                         member_name="helpdesk", source="vm"),
    ])
    db_session.commit()

    def links() -> list[tuple[int | None, int | None, int | None]]:
        rows = db_session.scalars(select(AssetGroupMember).order_by(AssetGroupMember.id)).all()
        return [(m.user_id, m.asset_id, m.member_group_id) for m in rows]

    db_session.delete(user)
    db_session.delete(member_host)
    db_session.commit()
    db_session.expire_all()
    assert links() == [(None, None, None), (None, None, None), (None, None, domain.id)]
    db_session.delete(host)
    db_session.commit()
    db_session.expire_all()
    assert db_session.scalars(select(AssetGroup.name)).all() == ["helpdesk"]
    assert links() == [(None, None, None), (None, None, None)]
    db_session.delete(domain)
    db_session.commit()
    assert db_session.scalar(select(func.count()).select_from(AssetGroupMember)) == 0


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
