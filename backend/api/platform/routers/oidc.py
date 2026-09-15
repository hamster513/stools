"""Ручки настроек OIDC: /api/settings/oidc.

Читает и пишет только администратор — по префиксу пути (api/rbac.py),
как и остальные настройки платформы.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.oidc import login as oidc_login
from api.oidc.provider import ProviderError, fetch_discovery, fetch_jwks
from api.oidc.settings import OidcSettingsIn, load_oidc, public_view, require_secure_url, save_oidc

router = APIRouter(prefix="/oidc", tags=["settings"])


@router.get("")
def get_oidc(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> dict[str, object]:
    return public_view(load_oidc(db))


@router.put("", status_code=status.HTTP_204_NO_CONTENT)
def put_oidc(payload: OidcSettingsIn, db: Session = Depends(get_db), user: AppUser = Depends(get_current_user)) -> None:
    save_oidc(db, payload, user.login)


class OidcTestRequest(BaseModel):
    issuer_url: str

    @field_validator("issuer_url")
    @classmethod
    def _secure(cls, value: str) -> str:
        return require_secure_url(value)


@router.post("/test")
def test_oidc(payload: OidcTestRequest, _user: AppUser = Depends(get_current_user)) -> dict[str, Any]:
    """Скачать discovery и JWKS: секрет для этого не нужен."""
    try:
        disco = fetch_discovery(payload.issuer_url.strip(), oidc_login.http_factory)
        keys = fetch_jwks(disco.jwks_uri, oidc_login.http_factory, force=True)
    except ProviderError as exc:
        return {"ok": False, "issuer": None, "endpoints": None, "keys": 0, "error": str(exc)}
    return {
        "ok": True, "issuer": disco.issuer, "keys": len(keys), "error": None,
        "endpoints": {
            "authorization": disco.authorization_endpoint,
            "token": disco.token_endpoint,
            "jwks": disco.jwks_uri,
            "userinfo": disco.userinfo_endpoint,
        },
    }
