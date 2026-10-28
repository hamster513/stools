"""Пользователи платформы.

Права пользователя — это его группы (api.platform.services.access). Защита от
выстрела в ногу: нельзя заблокировать или удалить себя, а блокировка, удаление и
смена групп не оставляют систему без администратора и не снимают права с самого
себя (`guard_last_admin`).
"""
from __future__ import annotations

import datetime as dt

from fastapi import HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from api.db.models import AppUser, SessionRow
from api.platform.services.access import (
    Access,
    GroupRef,
    access_for,
    groups_of,
    guard_last_admin,
    set_user_groups,
)
from api.security import hash_password

MIN_PASSWORD = 8


class UserView(BaseModel):
    id: int
    login: str
    display_name: str | None = None
    #: Группы пользователя (локальные и из OIDC) и итоговые права по ним.
    groups: list[GroupRef]
    access: Access
    is_active: bool
    last_login_at: dt.datetime | None = None
    created_at: dt.datetime
    auth_source: str


class UserCreate(BaseModel):
    login: str = Field(min_length=1, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)
    #: Только локальные группы: членство в группах из OIDC выдаёт вход.
    group_ids: list[int] = []
    password: str = Field(min_length=MIN_PASSWORD)


class UserPatch(BaseModel):
    display_name: str | None = Field(default=None, max_length=255)
    #: None — группы не трогать; список заменяет локальное членство целиком.
    group_ids: list[int] | None = None
    is_active: bool | None = None


class PasswordSet(BaseModel):
    password: str = Field(min_length=MIN_PASSWORD)


def view(db: Session, user: AppUser) -> UserView:
    return UserView(
        id=user.id, login=user.login, display_name=user.display_name,
        groups=[GroupRef(id=g.id, name=g.name, source=g.source) for g in groups_of(db, user.id)],
        access=access_for(db, user.id), is_active=user.is_active, last_login_at=user.last_login_at,
        created_at=user.created_at, auth_source=user.auth_source,
    )


def list_users(db: Session) -> list[UserView]:
    return [view(db, u) for u in db.scalars(select(AppUser).order_by(AppUser.login))]


def create_user(db: Session, actor: AppUser, payload: UserCreate) -> UserView:
    if db.scalar(select(AppUser).where(AppUser.login == payload.login)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="пользователь с таким логином уже есть")
    user = AppUser(login=payload.login, display_name=payload.display_name, password_hash=hash_password(payload.password))
    db.add(user)
    try:
        db.flush()
        if payload.group_ids:
            set_user_groups(db, actor, user.id, payload.group_ids)
        else:
            db.commit()
    except HTTPException:
        #: Неудачные группы не оставляют учётку без прав; откат сбрасывает и актора,
        #: которого журнал действий читает уже после закрытия сессии.
        db.rollback()
        db.get(AppUser, actor.id)
        raise
    db.refresh(user)
    return view(db, user)


def _get(db: Session, user_id: int) -> AppUser:
    user = db.get(AppUser, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="пользователь не найден")
    return user


def drop_sessions(db: Session, user_id: int) -> None:
    db.execute(delete(SessionRow).where(SessionRow.user_id == user_id))


def patch_user(db: Session, actor: AppUser, user_id: int, payload: UserPatch) -> UserView:
    user = _get(db, user_id)
    if user.id == actor.id and payload.is_active is False:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="нельзя заблокировать себя")

    def apply() -> None:
        if payload.display_name is not None:
            user.display_name = payload.display_name
        if payload.is_active is not None:
            user.is_active = payload.is_active
            if not payload.is_active:
                drop_sessions(db, user.id)

    if payload.is_active is False:
        guard_last_admin(db, actor.id, after=apply)
    else:
        apply()
    if payload.group_ids is not None:
        #: Фиксирует и правки выше: не прошла проверка групп — откат всего.
        try:
            set_user_groups(db, actor, user.id, payload.group_ids)
        except HTTPException:
            db.rollback()
            db.get(AppUser, actor.id)
            raise
    else:
        db.commit()
    db.refresh(user)
    return view(db, user)


def delete_user(db: Session, actor: AppUser, user_id: int) -> None:
    user = _get(db, user_id)
    if user.id == actor.id:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="нельзя удалить себя")

    def apply() -> None:
        drop_sessions(db, user.id)
        db.delete(user)

    guard_last_admin(db, actor.id, after=apply)
    db.commit()


def set_password(db: Session, user_id: int, password: str) -> None:
    user = _get(db, user_id)
    if user.auth_source == "oidc":
        raise HTTPException(status.HTTP_409_CONFLICT, detail="пароль задаётся в провайдере входа")
    user.password_hash = hash_password(password)
    drop_sessions(db, user.id)
    db.commit()
