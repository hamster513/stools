"""NVD candidate index and evidence from KSC inventory; scanner records stay separate."""
from __future__ import annotations

import datetime as dt

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base, _utcnow


class VmNvdProduct(Base):
    __tablename__ = "vm_nvd_product"
    __table_args__ = (Index("ix_vm_nvd_product_identity", "vendor", "product"),)
    cve_id: Mapped[str] = mapped_column(ForeignKey("vm_ref_nvd.cve_id", ondelete="CASCADE"), primary_key=True)
    vendor: Mapped[str] = mapped_column(Text, primary_key=True)
    product: Mapped[str] = mapped_column(Text, primary_key=True)


class VmKscCve(Base):
    __tablename__ = "vm_ksc_cve"
    __table_args__ = (UniqueConstraint("software_id", "cve_id", name="uq_vm_ksc_software_cve"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    software_id: Mapped[int] = mapped_column(ForeignKey("ksc_software.id", ondelete="CASCADE"), index=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("vm_ref_nvd.cve_id", ondelete="CASCADE"), index=True)
    state: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(Text)
    evidence_json: Mapped[str] = mapped_column(Text)
    checked_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
