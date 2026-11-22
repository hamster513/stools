"""Read-only host risk, including current independent vendor-confirmed SBOM evidence."""

from sqlalchemy import (
    Boolean,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    column,
    literal_column,
    select,
    table,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from api.modules.assets.models import AssetObservation
from api.modules.vm.models import VmCve, VmHost


class _RiskView(DeclarativeBase):
    """These views are installed by Alembic, outside the writable model metadata."""


class RiskHost(_RiskView):
    __tablename__ = "vm_risk_host"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String)
    ip: Mapped[str] = mapped_column(String)
    os_name: Mapped[str] = mapped_column(String)
    groups: Mapped[str] = mapped_column(Text)
    criticality: Mapped[str] = mapped_column(String)
    zone: Mapped[str] = mapped_column(String)
    state_hostname: Mapped[str] = mapped_column(String)
    internet: Mapped[bool] = mapped_column(Boolean)


class RiskHostCve(_RiskView):
    __tablename__ = "vm_risk_host_cve"

    host_id: Mapped[int] = mapped_column(ForeignKey(RiskHost.id), primary_key=True)
    cve_id: Mapped[str] = mapped_column(ForeignKey(VmCve.cve_id), primary_key=True)
    risk_raw: Mapped[float] = mapped_column(Float)
    risk: Mapped[int] = mapped_column(Integer)
    sbom_asset_id: Mapped[int | None] = mapped_column(Integer)


sbom_risk_hosts = table("vm_sbom_risk_host", column("asset_id", Integer), column("id", Integer),
                        column("criticality", String), column("zone", String))


def asset_risk_host_ids(asset_ids):
    """Both confirmed SBOM and live MaxPatrol inventory identify an asset's risk hosts."""
    raw = select(VmHost.id).join(AssetObservation,
        VmHost.hostname + literal_column("'|'") + VmHost.ip == AssetObservation.source_key).where(
            AssetObservation.source == "vm", AssetObservation.gone_at.is_(None), AssetObservation.asset_id.in_(asset_ids))
    return raw.union(select(sbom_risk_hosts.c.id).where(sbom_risk_hosts.c.asset_id.in_(asset_ids)))
