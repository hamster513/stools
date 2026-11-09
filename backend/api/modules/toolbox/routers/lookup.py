"""Read-only local lookup. POST keeps internal identifiers out of URL/access logs."""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.modules.toolbox.services.lookup import lookup
from api.modules.toolbox.services.lookup_types import LookupRequest, LookupResult, parse_query
from api.platform.services.access import Access
from api.rbac import current_access

router = APIRouter()


@router.post("/lookup", response_model=LookupResult)
def search(
    payload: LookupRequest,
    request: Request,
    db: Session = Depends(get_db),
    access: Access = Depends(current_access),
) -> LookupResult:
    request.state.audit_summary = "TBX: локальный поиск по источникам"
    try:
        query, kind = parse_query(payload.query, payload.kind)
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    return lookup(db, query, kind, access)
