"""Latest complete Docker inventory from MaxPatrol VM, separate from Harbor digests."""
from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base


class VmDockerImage(Base):
    __tablename__ = "vm_docker_image"

    id: Mapped[int] = mapped_column(primary_key=True)
    image_key: Mapped[str] = mapped_column(String(64), unique=True)
    image_id: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    tags: Mapped[list[str]] = mapped_column(JSON)
    platform: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), index=True)
    host_count: Mapped[int] = mapped_column(Integer)
    container_count: Mapped[int] = mapped_column(Integer)
    details: Mapped[dict[str, Any]] = mapped_column(JSON)
    search_text: Mapped[str] = mapped_column(Text)
    collected_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))


class VmDockerSnapshot(Base):
    __tablename__ = "vm_docker_snapshot"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_address: Mapped[str] = mapped_column(Text, default="")
    attempted_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    collected_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")
