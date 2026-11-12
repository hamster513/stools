"""Последние авторизации из SIEM и отдельная очередь импорта."""
import datetime as dt

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base
from api.jobs import JobColumns


class SiemLogonJob(JobColumns, Base):
    __tablename__ = 'siem_logon_job'


class SiemLogon(Base):
    __tablename__ = 'siem_logon'

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(64), unique=True)
    scope: Mapped[str] = mapped_column(String(64), index=True)
    table_name: Mapped[str] = mapped_column(String(255))
    user: Mapped[str] = mapped_column(String(255))
    domain: Mapped[str] = mapped_column(String(255))
    src_host: Mapped[str] = mapped_column(String(255))
    src_ip: Mapped[str] = mapped_column(String(64))
    dst_host: Mapped[str] = mapped_column(String(255))
    dst_ip: Mapped[str] = mapped_column(String(64))
    last_login: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey('asset_user.id', ondelete='SET NULL'), index=True)
    src_asset_id: Mapped[int | None] = mapped_column(ForeignKey('asset.id', ondelete='SET NULL'), index=True)
    dst_asset_id: Mapped[int | None] = mapped_column(ForeignKey('asset.id', ondelete='SET NULL'), index=True)
