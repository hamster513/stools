"""Engine и фабрика сессий SQLAlchemy.

Синхронный движок: фоновая обработка задания и так идёт в потоке
(`BackgroundTasks`), а не в asyncio-задаче, поэтому асинхронная сессия
не даёт выгоды и только усложняет вызовы ядра `kbaudit`, которое само
синхронное.
"""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from api.settings import Settings, get_settings


class Base:
    """Общий declarative base — определён в models.py, импортируется оттуда."""


def make_engine(settings: Settings | None = None) -> Engine:
    settings = settings or get_settings()
    connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
    return create_engine(settings.database_url, connect_args=connect_args, future=True)


_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = make_engine()
    return _engine


def get_sessionmaker() -> sessionmaker[Session]:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)
    return _SessionLocal


def get_db() -> Iterator[Session]:
    """Зависимость FastAPI: сессия на запрос."""
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()
