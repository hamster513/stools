"""Versioned STools boundary for the independently deployed IRP."""
from __future__ import annotations

from collections.abc import Callable, Coroutine
from secrets import compare_digest
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.routing import APIRoute
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.models import AccessGroup, AccessMembership, AccessRoleLevel, AppUser
from api.deps import get_current_user, get_db
from api.platform.services.access import access_for, allows
from api.routers.irp_enrichment import EnrichmentRequest, EnrichmentResult, enrich
from api.settings import Settings, get_settings

router = APIRouter(prefix="/api/integrations/irp/v1", tags=["IRP integration"])
VERSION = "1.0"
NO_STORE = {"Cache-Control": "no-store"}
BEARER = HTTPBearer(auto_error=False)


def _session_user(
    request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
) -> AppUser:
    try:
        return get_current_user(request, db, settings)
    except HTTPException as exc:
        exc.headers = {**(exc.headers or {}), **NO_STORE}
        raise


def _service_scopes(
    credentials: HTTPAuthorizationCredentials | None,
    settings: Settings,
) -> frozenset[str]:
    if credentials is None:
        raise HTTPException(401, "service bearer required", headers={"WWW-Authenticate": "Bearer"})
    token = settings.irp_service_token.get_secret_value()
    if not token:
        raise HTTPException(503, "service authentication not configured")
    if not compare_digest(credentials.credentials.encode(), token.encode()):
        raise HTTPException(401, "invalid service bearer", headers={"WWW-Authenticate": "Bearer"})
    return frozenset(scope.strip() for scope in settings.irp_enrichment_scopes.split(",") if scope.strip())


@router.get("/session")
def session(
    response: Response, user: AppUser = Depends(_session_user), db: Session = Depends(get_db),
) -> dict[str, object]:
    response.headers.update(NO_STORE)
    return {
        "contract_version": VERSION,
        "user": {"id": str(user.id), "login": user.login, "display_name": user.display_name,
                 "theme": "light" if user.theme == "light" else "dark"},
        "access": {"irp": access_for(db, user.id)["irp"]},
    }


@router.get("/users")
def users(
    response: Response,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
    user: AppUser = Depends(_session_user),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    if not allows(access_for(db, user.id), "irp", "write"):
        raise HTTPException(403, "IRP write access required", headers=NO_STORE)
    response.headers.update(NO_STORE)
    assignable = (
        select(AccessMembership.user_id)
        .join(AccessGroup, AccessGroup.id == AccessMembership.group_id)
        .join(AccessRoleLevel, AccessRoleLevel.role_id == AccessGroup.role_id)
        .where(AccessMembership.user_id == AppUser.id, AccessRoleLevel.area == "irp",
               AccessRoleLevel.level.in_(("write", "admin")))
        .exists()
    )
    rows = db.execute(
        select(AppUser.id, AppUser.login, AppUser.display_name)
        .where(AppUser.is_active.is_(True), assignable)
        .order_by(AppUser.login).limit(limit + 1)
    ).all()
    return {
        "contract_version": VERSION,
        "items": [{"id": str(row.id), "login": row.login, "display_name": row.display_name} for row in rows[:limit]],
        "truncated": len(rows) > limit,
    }


class EnrichmentResponse(BaseModel):
    contract_version: str = VERSION
    results: list[EnrichmentResult]


class _EnrichmentRoute(APIRoute):
    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handle = super().get_route_handler()

        async def authenticate(request: Request) -> Response:
            # FastAPI's handler decodes JSON before it resolves route dependencies.
            request.state.irp_enrichment_scopes = _service_scopes(await BEARER(request), get_settings())
            return await handle(request)

        return authenticate


service_router = APIRouter(route_class=_EnrichmentRoute)


# Advertise bearer auth in OpenAPI alongside the typed request body.
@service_router.post("/enrichment", dependencies=[Depends(BEARER)])
def enrichment(
    request: Request,
    payload: EnrichmentRequest,
    db: Session = Depends(get_db),
) -> EnrichmentResponse:
    scopes: frozenset[str] = request.state.irp_enrichment_scopes
    return EnrichmentResponse(results=enrich(db, payload, scopes))


router.include_router(service_router)
