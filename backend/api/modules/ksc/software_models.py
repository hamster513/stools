"""Installed software as observed by KSC, scoped to immutable snapshots."""
from __future__ import annotations

import datetime as dt

from sqlalchemy import Date, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base


class KscSoftwareInventory(Base):
    __tablename__ = "ksc_software_inventory"
    __table_args__ = (UniqueConstraint("snapshot_id", "host_id", name="uq_ksc_inventory_host"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("ksc_snapshot.id", ondelete="CASCADE"), index=True)
    host_id: Mapped[str] = mapped_column(String(64))
    host_name: Mapped[str] = mapped_column(String(255))
    os: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20))
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class KscSoftware(Base):
    __tablename__ = "ksc_software"
    __table_args__ = (Index("ix_ksc_software_product", "vendor_key", "product_key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    inventory_id: Mapped[int] = mapped_column(ForeignKey("ksc_software_inventory.id", ondelete="CASCADE"), index=True)
    product_id: Mapped[str] = mapped_column(Text, default="")
    name: Mapped[str] = mapped_column(Text)
    version: Mapped[str] = mapped_column(Text, default="")
    publisher: Mapped[str] = mapped_column(Text, default="")
    vendor_key: Mapped[str] = mapped_column(Text, default="")
    product_key: Mapped[str] = mapped_column(Text, default="")
    installed_on: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    install_dir: Mapped[str] = mapped_column(Text, default="")
    raw_json: Mapped[str] = mapped_column(Text)
    assessment: Mapped[str] = mapped_column(String(20), default="pending")
