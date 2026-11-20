"""Download the host inventory and inspect independently produced vulnerability results."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.modules.assets.models import Asset
from api.modules.vm.core.host_sbom import bom_bytes
from api.modules.vm.sbom_models import HostSbomScan
from api.modules.vm.services.host_sbom import inventory, refresh_queue
from api.modules.vm.services.host_sbom_view import comparison, component_nvd
from api.platform.services.access import allows
from api.rbac import current_access
from api.settings import Settings, get_settings

router = APIRouter()


def host(asset_id: int, db: Session = Depends(get_db)) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None or asset.merged_into is not None:
        raise HTTPException(404, "Актив не найден или объединён с другим хостом")
    return asset


def vm_reader(access: dict = Depends(current_access)) -> None:
    if not allows(access, "vm", "read"):
        raise HTTPException(403, "Для сравнения находок нужен доступ на чтение VM")


@router.get("/assets/{asset_id}/sbom", response_class=Response)
def download(asset: Asset = Depends(host), db: Session = Depends(get_db),
             settings: Settings = Depends(get_settings)) -> Response:
    document, _ = inventory(db, asset, settings.data_dir)
    return Response(
        bom_bytes(document),
        media_type="application/vnd.cyclonedx+json",
        headers={
            "Content-Disposition": f'attachment; filename="host-{asset.id}.cdx.json"',
            "Cache-Control": "private, no-store",
        },
    )


@router.get("/assets/{asset_id}/sbom/components")
def components(
    asset: Asset = Depends(host),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    q: str = Query("", max_length=255),
    limit: int = Query(10, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict:
    document, _ = inventory(db, asset, settings.data_dir)
    rows = document["components"]
    term = q.strip().casefold()
    matches = [
        c for c in rows if not term or term in c["name"].casefold() or term in c.get("version", "").casefold()
    ]
    return {
        "total": len(matches),
        "identified": sum(bool(c.get("purl")) for c in rows),
        "nvd_identified": sum(bool(c.get("cpe")) for c in rows),
        "items": [
            {"ref": c["bom-ref"], "name": c["name"], "version": c.get("version"),
             "purl": c.get("purl"), "cpe": c.get("cpe"), "publisher": c.get("publisher"),
             "winget_id": next((p["value"] for p in c["properties"] if p["name"] == "stools:winget-id"), None),
             "sources": [p["value"] for p in c["properties"] if p["name"] == "stools:source"]}
            for c in matches[offset:offset + limit]
        ],
    }


@router.get("/assets/{asset_id}/sbom/components/{ref}/nvd", dependencies=[Depends(vm_reader)])
def software_findings(
    ref: str, asset: Asset = Depends(host), settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db), limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0),
) -> dict:
    document, _ = inventory(db, asset, settings.data_dir)
    result = component_nvd(db, document, ref, limit, offset)
    if result is None:
        raise HTTPException(404, "Компонент отсутствует в текущем SBOM хоста")
    return result


@router.get("/assets/{asset_id}/sbom/comparison", dependencies=[Depends(vm_reader)])
def findings(
    asset: Asset = Depends(host),
    group: Literal["all", "both", "trivy_only", "vm_only", "packages", "unlinked"] = "all",
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> dict:
    return comparison(db, asset, settings.data_dir, group, limit, offset)


@router.post("/assets/{asset_id}/sbom/scan", status_code=202, dependencies=[Depends(vm_reader)])
def scan(
    asset: Asset = Depends(host),
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
) -> dict:
    refresh_queue(db, settings.data_dir, asset.id, force=True)
    return {"asset_id": asset.id, "status": db.get(HostSbomScan, asset.id).status}
