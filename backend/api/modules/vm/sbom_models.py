"""Package observations in MaxPatrol and the independent Trivy result for a canonical asset."""

import datetime as dt

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base


class VmHostCoverage(Base):
    """Hosts explicitly present in the CVE export. Inventory alone cannot establish a clean result."""

    __tablename__ = "vm_host_cve_coverage"
    source_key: Mapped[str] = mapped_column(String(512), primary_key=True)
    observed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))


class VmPackageFeed(Base):
    __tablename__ = "vm_package_feed"
    kind: Mapped[str] = mapped_column(String(16), primary_key=True)
    checked_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    collected_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)


class VmPackageHost(Base):
    __tablename__ = "vm_package_host"
    kind: Mapped[str] = mapped_column(String(16), primary_key=True)
    source_key: Mapped[str] = mapped_column(String(512), primary_key=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    ip: Mapped[str] = mapped_column(String(64))
    os_name: Mapped[str] = mapped_column(Text)
    packages: Mapped[list[dict]] = mapped_column(JSONB)
    changed_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))


class HostSbomScan(Base):
    __tablename__ = "vm_host_sbom_scan"
    __table_args__ = (Index("ix_vm_host_sbom_queue", "status", "requested_at"),)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("asset.id", ondelete="CASCADE"), primary_key=True
    )
    target: Mapped[str] = mapped_column(String(32))
    prepared_target: Mapped[str | None] = mapped_column(String(32))
    components: Mapped[int | None] = mapped_column(Integer)
    sources: Mapped[dict | None] = mapped_column(JSONB)
    requested_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20))
    force: Mapped[bool] = mapped_column(Boolean, default=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    claim: Mapped[str | None] = mapped_column(String(32))
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    scan_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    digest: Mapped[str | None] = mapped_column(String(64))
    db_version: Mapped[str | None] = mapped_column(Text)
    scanner_version: Mapped[str | None] = mapped_column(Text)
    checked: Mapped[int | None] = mapped_column(Integer)
    scanned_components: Mapped[int | None] = mapped_column(Integer)
    findings: Mapped[list[dict] | None] = mapped_column(JSONB)
    vendor_summary: Mapped[dict | None] = mapped_column(JSONB)
    error: Mapped[str | None] = mapped_column(Text)


class VmSbomConfirmedCve(Base):
    __tablename__ = "vm_sbom_confirmed_cve"

    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id", ondelete="CASCADE"), primary_key=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey("vm_cve.cve_id"), primary_key=True, index=True)
    risk_raw: Mapped[float] = mapped_column(Float, default=0.0)
    risk: Mapped[int] = mapped_column(Integer, default=0)
