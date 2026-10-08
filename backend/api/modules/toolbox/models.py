"""Таблицы ToolBox (спека §2–3): задания очистки, их находки, таблица соответствий, настройки.

Таблица соответствий одна на установку и живёт дольше заданий: по ней старые файлы переводятся
обратно, поэтому вместе с настройками (ключ HMAC) она обязана попадать в резервную копию.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base, _utcnow
from api.jobs import JobColumns

JSONType = JSON().with_variant(JSONB(), "postgresql")


class ToolboxJob(JobColumns, Base):
    """Одно задание проходит scan, затем apply той же строкой: находки и файлы привязаны к нему."""

    __tablename__ = "toolbox_job"

    input_name: Mapped[str] = mapped_column(String(255), default="")
    input_size: Mapped[int] = mapped_column(BigInteger, default=0)
    #: file | text
    input_kind: Mapped[str] = mapped_column(String(8), default="file")
    files_deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    result_name: Mapped[str] = mapped_column(String(255), default="")
    #: {"files": N, "skipped": N, "findings": {kind: n}, "replaced": {kind: n}}
    stats: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    users_from_ad: Mapped[bool] = mapped_column(Boolean, default=False)


class ToolboxAlias(Base):
    __tablename__ = "toolbox_alias"
    __table_args__ = (
        UniqueConstraint("kind", "real_key", name="uq_toolbox_alias_real"),
        UniqueConstraint("kind", "alias", name="uq_toolbox_alias_alias"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))
    #: Нормализованное значение (types.value_key): одно значение в разных написаниях — одна строка.
    real_key: Mapped[str] = mapped_column(String(512))
    #: Как встретилось впервые — в это написание переводит обратный перевод.
    real: Mapped[str] = mapped_column(String(512))
    alias: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    created_by: Mapped[str] = mapped_column(String(255), default="")
    first_job_id: Mapped[int | None] = mapped_column(ForeignKey("toolbox_job.id", ondelete="SET NULL"), nullable=True)


class ToolboxFinding(Base):
    __tablename__ = "toolbox_finding"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("toolbox_job.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(Text)
    value_key: Mapped[str] = mapped_column(Text)
    alias: Mapped[str] = mapped_column(Text)
    alias_id: Mapped[int | None] = mapped_column(ForeignKey("toolbox_alias.id", ondelete="SET NULL"), nullable=True)
    count: Mapped[int] = mapped_column(Integer, default=0)
    contexts: Mapped[list[str]] = mapped_column(JSONType, default=list)
    first_file: Mapped[str] = mapped_column(String(512), default="")
    checked: Mapped[bool] = mapped_column(Boolean, default=True)
    #: Найдено авто-поиском, а не по словарю.
    auto: Mapped[bool] = mapped_column(Boolean, default=False)


# Значение — Text, а уникальность по md5: секрет (JWT, значение под ключом-паролем) бывает длиннее и 512
# символов, и предела строки индекса Postgres.
Index(
    "uq_toolbox_finding_value", ToolboxFinding.job_id, ToolboxFinding.kind, func.md5(ToolboxFinding.value_key),
    unique=True,
)


class ToolboxSettings(Base):
    """Одна строка (id=1). Ключ HMAC наружу не отдаётся никогда: по нему считаются псевдонимы адресов."""

    __tablename__ = "toolbox_settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[bytes] = mapped_column(LargeBinary(32))
    #: [{"word": …, "alias": …}] — alias "" назначит word-NNNN
    words: Mapped[list[dict[str, str]]] = mapped_column(JSONType, default=list)
    #: [{"cidr": …, "to": …}] — сети одной длины
    subnets: Mapped[list[dict[str, str]]] = mapped_column(JSONType, default=list)
    retention_days: Mapped[int] = mapped_column(Integer, default=7)
