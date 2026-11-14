"""Installed software from KSC in the canonical asset card."""
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.assets.models import Asset, AssetObservation
from api.modules.assets.services import software_catalog
from api.modules.ksc.models import KscSnapshot
from api.modules.ksc.services.host_scope import find_host
from api.modules.ksc.services.host_software import host_software
from api.modules.vm.services.software import latest_snapshot_ids
from api.modules.vm.services.software_views import asset_software

router = APIRouter()


@router.get("/assets/{asset_id}/software")
def get_software(asset_id: int, q: str = Query("", max_length=200), limit: int = Query(100, ge=1, le=200),
                 offset: int = Query(0, ge=0), db: Session = Depends(get_db),
                 _user: AppUser = Depends(get_current_user)) -> dict:
    if db.get(Asset, asset_id) is None:
        raise HTTPException(404, "Актив не найден")
    return asset_software(db, asset_id, q, limit, offset)


@router.get("/assets/{asset_id}/software/assessment")
def get_assessment(
    asset_id: int, server_id: int = Query(ge=1), host_id: str = Query(min_length=1, max_length=64),
    q: str = Query("", max_length=255),
    coverage: Literal["checked", "unrecognized", "missing_version", "pending", "uncertain"] | None = None,
    state: Literal["affected", "unknown"] | None = None,
    limit: int = Query(50, ge=1, le=100), software_offset: int = Query(0, ge=0), vuln_offset: int = Query(0, ge=0),
    db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user),
) -> dict:
    source = db.scalar(select(AssetObservation.id).join(Asset, Asset.id == AssetObservation.asset_id).where(
        Asset.id == asset_id, Asset.merged_into.is_(None), AssetObservation.source == "ksc",
        AssetObservation.source_key == f"{server_id}:{host_id}", AssetObservation.gone_at.is_(None)).limit(1))
    if source is None:
        raise HTTPException(404, "Источник ПО этого хоста не найден")
    snap = db.scalar(select(KscSnapshot).where(KscSnapshot.server_id == server_id, KscSnapshot.id.in_(latest_snapshot_ids())))
    if snap is None:
        raise HTTPException(404, "Снимок KSC не найден")
    find_host(db, snap.id, host_id)
    return host_software(db, snap, host_id, q=q, coverage=coverage, state=state,
                         limit=limit, software_offset=software_offset, vuln_offset=vuln_offset)


@router.get("/software/products")
def get_products(q: str = Query("", max_length=255), limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0),
                 db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict:
    return software_catalog.products(db, q, limit, offset)


@router.get("/software/versions")
def get_versions(vendor_key: str = Query("", max_length=512), product_key: str = Query(min_length=1, max_length=512),
                 limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0),
                 db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict:
    return software_catalog.versions(db, vendor_key, product_key, limit, offset)


@router.get("/software/hosts")
def get_hosts(vendor_key: str = Query("", max_length=512), product_key: str = Query(min_length=1, max_length=512),
              version: str | None = Query(None, max_length=512), limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0),
              db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict:
    return software_catalog.hosts(db, vendor_key, product_key, version, limit, offset)
