"""Complete local GitHub Advisory Database, including advisories without a CVE."""
from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base


class VmRefGhsa(Base):
    __tablename__ = "vm_ref_ghsa"

    ghsa_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_version: Mapped[str] = mapped_column(String(16), default="")
    cvss_vector: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="unknown")
    published: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    modified: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    withdrawn: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False)
    references: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    cwes: Mapped[list[str]] = mapped_column(JSONB, default=list)


class VmRefGhsaAlias(Base):
    __tablename__ = "vm_ref_ghsa_alias"

    ghsa_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("vm_ref_ghsa.ghsa_id", ondelete="CASCADE"), primary_key=True,
    )
    alias: Mapped[str] = mapped_column(String(128), primary_key=True, index=True)


class VmRefGhsaPackage(Base):
    __tablename__ = "vm_ref_ghsa_package"

    ghsa_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("vm_ref_ghsa.ghsa_id", ondelete="CASCADE"), primary_key=True,
    )
    position: Mapped[int] = mapped_column(Integer, primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(Text)
    purl: Mapped[str | None] = mapped_column(Text, nullable=True)
    ranges: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    versions: Mapped[list[str]] = mapped_column(JSONB, default=list)
    fixed_versions: Mapped[list[str]] = mapped_column(JSONB, default=list)
