"""Сервер KSC: 2FA, администраторы, сертификаты, иерархия, точки распространения."""
from __future__ import annotations

import datetime as dt
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.ksc.core.certs import parse_cert
from api.modules.ksc.core.checks import CHECK_BY_CODE
from api.modules.ksc.core.checks.server import is_admin_role, role_account
from api.modules.ksc.core.config import KscConfig
from api.modules.ksc.core.export import ExportIndex, _dt, _int, _str, load_export_path, unwrap
from api.modules.ksc.models import KscFinding, KscSnapshot
from api.modules.ksc.services.settings import load_config
from api.modules.ksc.services.snapshots import snapshot_path
from api.settings import Settings, get_settings

router = APIRouter(tags=["ksc"])

#: Находки уровня сервера (не привязаны к хосту) — см. core/checks/server.py.
SERVER_CHECKS = {"KSC_2FA_OFF", "KSC_INTERNAL_ADMIN", "KSC_ADMINS", "SERVER_CERT", "SECONDARY_SERVER_STALE"}


class AdminView(BaseModel):
    account: str
    internal: bool
    role: str
    group: str


class CertView(BaseModel):
    function: str
    subject: str
    not_after: dt.datetime
    days_left: int


class SecondaryServerView(BaseModel):
    name: str
    address: str
    version: str
    last_connected: dt.datetime | None
    status: int


class UpdateAgentView(BaseModel):
    host: str
    group: str


class ServerFindingView(BaseModel):
    key: str
    check: str
    check_title: str
    severity: str
    target: str


class ServerResponse(BaseModel):
    two_factor_required_for_all: bool | None
    admins: list[AdminView]
    certs: list[CertView]
    secondary_servers: list[SecondaryServerView]
    update_agents: list[UpdateAgentView]
    warnings: list[str]
    findings: list[ServerFindingView]


def _admins(idx: ExportIndex, cfg: KscConfig) -> list[AdminView]:
    out = []
    for r in idx.export.role_assignments:
        role, role_display = _str(r.get("wstrRoleName")), _str(r.get("wstrRoleDisplayName"))
        if not is_admin_role(role, role_display, cfg.admin_role_patterns):
            continue
        out.append(AdminView(
            # То же значение, что в `target` находок о ролях, — иначе находки не пристанут к строке.
            account=role_account(r),
            internal=_int(r.get("nInternalUserId")) > 0,
            role=role_display or role,
            group=_str(r.get("wstrGroupName")),
        ))
    return out


def _certs(idx: ExportIndex) -> list[CertView]:
    out = []
    for fn, entry in idx.export.server_certs.items():
        if not isinstance(entry, dict):
            continue
        info = parse_cert(entry.get("CPublic"))
        if info is None:
            continue
        out.append(CertView(function=fn, subject=info.subject, not_after=info.not_after, days_left=(info.not_after - idx.now).days))
    return out


def _secondary_servers(idx: ExportIndex) -> list[SecondaryServerView]:
    out = []
    for s in idx.export.secondary_servers:
        out.append(SecondaryServerView(
            name=_str(s.get("KLSRVH_SRV_DN")) or _str(s.get("KLSRVH_SRV_ADDR")),
            address=_str(s.get("KLSRVH_SRV_ADDR")),
            version=_str(s.get("KLSRVH_SRV_VERSION")),
            last_connected=_dt(s.get("KLSRVH_SRV_LAST_CONNECTED")),
            status=_int(s.get("KLSRVH_SRV_STATUS")),
        ))
    return out


def _update_agents(idx: ExportIndex) -> list[UpdateAgentView]:
    return [
        UpdateAgentView(
            host=_str(a.get("KLUAGNT_HOST_DN")) or _str(a.get("KLUAGNT_HOST_NAME")),
            group=idx.group_path(_int(a.get("KLUAGNT_GROUP_ID"))),
        )
        for a in idx.export.update_agents
    ]


@router.get("/snapshots/{snapshot_id}/server", response_model=ServerResponse)
def get_server(
    snapshot_id: int,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _user: AppUser = Depends(get_current_user),
) -> ServerResponse:
    snap = db.get(KscSnapshot, snapshot_id)
    if snap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="снапшот не найден")
    path = snapshot_path(settings.data_dir, snap.id)
    if not path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="файл выгрузки не найден")
    idx = ExportIndex(load_export_path(path))
    cfg = load_config(db)
    rows = db.execute(select(KscFinding).where(KscFinding.snapshot_id == snapshot_id, KscFinding.check.in_(SERVER_CHECKS))).scalars()
    findings = [
        ServerFindingView(
            key=f.key, check=f.check,
            check_title=CHECK_BY_CODE[f.check].title if f.check in CHECK_BY_CODE else f.check,
            severity=f.severity, target=f.target,
        )
        for f in rows
    ]
    two_fa: Any = unwrap(idx.export.security.get("two_factor_required_for_all"))
    return ServerResponse(
        two_factor_required_for_all=two_fa if isinstance(two_fa, bool) else None,
        admins=_admins(idx, cfg),
        certs=_certs(idx),
        secondary_servers=_secondary_servers(idx),
        update_agents=_update_agents(idx),
        warnings=list(idx.export.server.warnings),
        findings=findings,
    )
