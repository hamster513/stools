"""Container inventory shared by the VM and Assets image catalogues."""
from typing import Any

from fastapi import Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.modules.vm.services.host_containers import by_host
from api.platform.services.access import Access, allows
from api.rbac import current_access


def list_host_containers(
    asset_id: int | None = Query(default=None, ge=1), q: str = Query(default="", max_length=200),
    running_only: bool = False, unmatched_only: bool = False,
    limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db), access: Access = Depends(current_access),
) -> dict[str, Any]:
    with_assets = allows(access, "assets", "read")
    if asset_id is not None and not with_assets:
        raise HTTPException(403, "Для отбора по активу нужен доступ на чтение к Активам")
    result = by_host(db, asset_id=asset_id, q=q, running_only=running_only, unmatched_only=unmatched_only,
                     limit=limit, offset=offset, with_assets=with_assets)
    if asset_id is not None and result["asset"] is None:
        raise HTTPException(404, "Актив не найден")
    return result
