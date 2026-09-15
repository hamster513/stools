"""Настройки модуля VM: подключение, веса формулы, порог."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db.base import get_db
from api.db.models import AppUser
from api.deps import get_current_user
from api.modules.vm.core.mpvm import MpVmClient, MpVmError, make_client
from api.modules.vm.core.weights import DEFAULT_THRESHOLD, Weights
from api.modules.vm.services.settings import (
    DEFAULT_ATTACK_MIN_RISK,
    VmSettings,
    VmSettingsIn,
    load_settings,
    save_settings,
)

router = APIRouter(prefix="/settings", tags=["vm"])


class SettingsView(BaseModel):
    connection: dict[str, Any]
    weights: Weights
    threshold: int
    attack_min_risk: int
    defaults: dict[str, Any]


def _view(s: VmSettings) -> SettingsView:
    conn = s.connection.model_dump(exclude={"password", "client_secret"})
    conn["password_set"] = bool(s.connection.password)
    conn["client_secret_set"] = bool(s.connection.client_secret)
    conn["configured"] = s.connection.configured
    return SettingsView(
        connection=conn,
        weights=s.weights,
        threshold=s.threshold,
        attack_min_risk=s.attack_min_risk,
        # Умолчания отдаются рядом, чтобы «сбросить» на экране не требовало
        # ещё одной ручки и не расходилось с бэкендом.
        defaults={"weights": Weights().model_dump(), "threshold": DEFAULT_THRESHOLD, "attack_min_risk": DEFAULT_ATTACK_MIN_RISK},
    )


@router.get("", response_model=SettingsView)
def get_settings_(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> SettingsView:
    return _view(load_settings(db))


@router.put("", response_model=SettingsView)
def put_settings(
    payload: VmSettingsIn,
    db: Session = Depends(get_db),
    user: AppUser = Depends(get_current_user),
) -> SettingsView:
    return _view(save_settings(db, payload, user.login))


class TestVmResponse(BaseModel):
    ok: bool
    message: str


@router.post("/test-vm", response_model=TestVmResponse)
def test_vm(db: Session = Depends(get_db), _user: AppUser = Depends(get_current_user)) -> TestVmResponse:
    """Проверка сохранённого подключения: токен и PDQL с limit(1).

    Проверяется то, что сохранено, а не то, что в форме: пароль и секрет
    форма не показывает и не присылает, проверять их «из поля» нечем.
    """
    conn = load_settings(db).connection
    if not conn.configured:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="подключение не настроено: нужны хост, логин и пароль")
    try:
        with make_client(conn, timeout=30.0) as http:
            head = MpVmClient(conn, http).probe()
    except MpVmError as exc:
        return TestVmResponse(ok=False, message=str(exc))
    return TestVmResponse(ok=True, message=f"MaxPatrol VM отвечает, экспорт начинается с: {head[:60]}")
