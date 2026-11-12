import datetime as dt

from sqlalchemy import DateTime, Integer
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base


class StorageSample(Base):
    __tablename__ = 'platform_storage_sample'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    measured_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    data: Mapped[dict] = mapped_column(JSONB)
