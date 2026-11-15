"""Provenance for additive diagnostic imports into normal module stores."""
import datetime as dt

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base, _utcnow


class DiagnosticImport(Base):
    __tablename__ = "platform_diagnostic_import"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    records_json: Mapped[str] = mapped_column(Text, default="{}")
